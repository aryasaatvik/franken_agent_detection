//! `OpenCode` connector for JSON file-based and `SQLite` storage.
//!
//! **v1.2+ (SQLite):** Data is stored in `~/.local/share/opencode/opencode.db`
//! with tables: session, message, part. The `message.data` and `part.data` columns
//! contain JSON blobs.
//!
//! **Pre-v1.2 (JSON):** Data at `~/.local/share/opencode/storage/` using files:
//!   - session/{projectID}/{sessionID}.json  - Session metadata
//!   - message/{sessionID}/{messageID}.json  - Message metadata
//!   - part/{messageID}/{partID}.json        - Actual message content

#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::manual_string_new,
    clippy::map_unwrap_or,
    clippy::missing_const_for_fn,
    clippy::must_use_candidate,
    clippy::nonminimal_bool,
    clippy::option_if_let_else,
    clippy::single_option_map,
    clippy::too_many_lines,
    clippy::uninlined_format_args,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal
)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rusqlite::types::Value as SqliteValue;
use rusqlite::{Connection, OpenFlags, Row};
use serde::Deserialize;
use walkdir::WalkDir;

use super::scan::{DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use super::utils::{dedupe_path_key, env_path_nonempty};
use super::{Connector, file_modified_since, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation, NormalizedMessage};

pub struct OpenCodeConnector;

impl Default for OpenCodeConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenCodeConnector {
    pub fn new() -> Self {
        Self
    }

    /// Get the OpenCode storage directory.
    /// OpenCode stores sessions in ~/.local/share/opencode/storage/
    fn storage_root() -> Option<PathBuf> {
        // Check for env override first (useful for testing)
        if let Some(p) = env_path_nonempty("OPENCODE_STORAGE_ROOT") {
            if p.is_dir() {
                return Some(p);
            }
        }

        // Primary location: XDG data directory (Linux/macOS)
        if let Some(data) = dirs::data_local_dir() {
            let storage_dir = data.join("opencode/storage");
            if storage_dir.is_dir() {
                return Some(storage_dir);
            }
        }

        // XDG config path — on macOS dirs::data_local_dir() returns
        // ~/Library/Application Support which misses XDG-style installs
        // that place data under ~/.config/opencode/ (#146).
        if let Some(config) = dirs::config_dir() {
            let storage_dir = config.join("opencode/storage");
            if storage_dir.is_dir() {
                return Some(storage_dir);
            }
        }

        // Fallback: ~/.local/share/opencode/storage
        if let Some(home) = dirs::home_dir() {
            let storage_dir = home.join(".local/share/opencode/storage");
            if storage_dir.is_dir() {
                return Some(storage_dir);
            }
            // Also check ~/.config/opencode/storage for XDG-style installs
            let xdg_storage = home.join(".config/opencode/storage");
            if xdg_storage.is_dir() {
                return Some(xdg_storage);
            }
        }

        None
    }

    /// All known locations where OpenCode may store its SQLite database,
    /// in priority order. Exposed so that scan paths can fall back through
    /// them even when the caller provided an explicit (non-matching)
    /// `data_dir`.
    fn sqlite_db_candidates() -> Vec<PathBuf> {
        Self::sqlite_db_candidates_from(
            env_path_nonempty("OPENCODE_SQLITE_DB"),
            dirs::home_dir().as_deref(),
            dirs::data_local_dir().as_deref(),
            dirs::config_dir().as_deref(),
        )
    }

    /// Pure, env-free variant of [`Self::sqlite_db_candidates`] for tests.
    /// Every environment-dependent input is passed in explicitly so the
    /// resulting list is fully deterministic.
    fn sqlite_db_candidates_from(
        explicit_override: Option<PathBuf>,
        home: Option<&Path>,
        xdg_data: Option<&Path>,
        xdg_config: Option<&Path>,
    ) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();

        // 1. Explicit override for tests / custom installs.
        if let Some(path) = explicit_override {
            out.push(path);
        }

        // 2. XDG data dir via $HOME. OpenCode uses this on every platform,
        //    including macOS. This MUST be tried before
        //    dirs::data_local_dir() because on macOS the latter resolves
        //    to ~/Library/Application Support which OpenCode does not use.
        if let Some(home) = home {
            out.push(home.join(".local/share/opencode/opencode.db"));
            out.push(home.join(".config/opencode/opencode.db"));
        }

        // 3. Platform-native data/config dirs (for users who have moved
        //    OpenCode into non-XDG locations).
        if let Some(data) = xdg_data {
            out.push(data.join("opencode/opencode.db"));
        }
        if let Some(config) = xdg_config {
            out.push(config.join("opencode/opencode.db"));
        }

        // Deduplicate preserving order — multiple dirs helpers may resolve
        // to the same path on a given platform (e.g. macOS config_dir ==
        // data_local_dir).
        let mut seen = HashSet::new();
        out.retain(|p| seen.insert(p.clone()));
        out
    }

    fn is_local_share_root(path: &Path) -> bool {
        path.file_name().is_some_and(|name| name == "share")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|name| name == ".local"))
    }

    fn is_appdata_roaming(path: &Path) -> bool {
        path.file_name().is_some_and(|name| name == "Roaming")
            && path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|name| name == "AppData"))
    }

    fn append_explicit_db_candidates(out: &mut Vec<PathBuf>, base: &Path) {
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_config = file_name.is_some_and(|n| n == ".config");
        let is_local = file_name.is_some_and(|n| n == ".local");
        let is_share = Self::is_local_share_root(base);
        let is_app_support = file_name.is_some_and(|n| n == "Application Support");
        let is_roaming = Self::is_appdata_roaming(base);
        let is_opencode = file_name.is_some_and(|n| n == "opencode");

        if base.extension().is_some_and(|ext| ext == "db") {
            out.push(base.to_path_buf());
        } else {
            out.push(base.join("opencode.db"));
        }

        if is_opencode {
            out.push(base.join("opencode.db"));
        }

        // Treat base as an XDG-style root for opencode data.
        out.push(base.join("opencode/opencode.db"));

        if is_local {
            out.push(base.join("share/opencode/opencode.db"));
        }

        if !(is_config || is_local || is_share || is_app_support || is_roaming || is_opencode) {
            out.push(base.join(".local/share/opencode/opencode.db"));
            out.push(base.join(".config/opencode/opencode.db"));
            out.push(base.join("Library/Application Support/opencode/opencode.db"));
            out.push(base.join("AppData/Roaming/opencode/opencode.db"));
        }
    }

    fn append_explicit_storage_candidates(out: &mut Vec<PathBuf>, base: &Path) {
        let file_name = base.file_name().and_then(|n| n.to_str());
        let is_config = file_name.is_some_and(|n| n == ".config");
        let is_local = file_name.is_some_and(|n| n == ".local");
        let is_share = Self::is_local_share_root(base);
        let is_app_support = file_name.is_some_and(|n| n == "Application Support");
        let is_roaming = Self::is_appdata_roaming(base);
        let is_opencode = file_name.is_some_and(|n| n == "opencode");

        out.push(base.join("opencode/storage"));

        if is_opencode {
            out.push(base.join("storage"));
        }

        if is_local {
            out.push(base.join("share/opencode/storage"));
        }

        if !(is_config || is_local || is_share || is_app_support || is_roaming || is_opencode) {
            out.push(base.join(".local/share/opencode/storage"));
            out.push(base.join(".config/opencode/storage"));
            out.push(base.join("Library/Application Support/opencode/storage"));
            out.push(base.join("AppData/Roaming/opencode/storage"));
        }
    }

    fn sqlite_source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut db_candidates: Vec<ScanRoot> = Vec::new();
        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            db_candidates.push(ScanRoot::local(ctx.data_dir.clone()));
        } else if !ctx.data_dir.as_os_str().is_empty() {
            db_candidates.push(ScanRoot::local(ctx.data_dir.join("opencode.db")));
        }

        if !ctx.use_default_detection() {
            for scan_root in &ctx.scan_roots {
                let mut candidates = Vec::new();
                Self::append_explicit_db_candidates(&mut candidates, &scan_root.path);
                db_candidates.extend(candidates.into_iter().map(|path| scan_root.with_path(path)));
            }
        }

        db_candidates.extend(
            Self::sqlite_db_candidates()
                .into_iter()
                .map(ScanRoot::local),
        );

        let mut seen = HashSet::new();
        db_candidates.retain(|root| seen.insert(root.path.clone()));
        db_candidates
    }

    fn storage_source_roots(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut storage_roots: Vec<ScanRoot> = Vec::new();
        if ctx.use_default_detection() {
            if ctx.data_dir.exists() && looks_like_opencode_storage(&ctx.data_dir) {
                storage_roots.push(ScanRoot::local(ctx.data_dir.clone()));
            } else if let Some(root) = Self::storage_root() {
                storage_roots.push(ScanRoot::local(root));
            }
        } else {
            if ctx.data_dir.exists() && looks_like_opencode_storage(&ctx.data_dir) {
                storage_roots.push(ScanRoot::local(ctx.data_dir.clone()));
            }
            for scan_root in &ctx.scan_roots {
                let mut candidates = vec![scan_root.path.clone()];
                Self::append_explicit_storage_candidates(&mut candidates, &scan_root.path);
                for candidate in candidates {
                    if candidate.exists() && looks_like_opencode_storage(&candidate) {
                        storage_roots.push(scan_root.with_path(candidate));
                    }
                }
            }
        }

        storage_roots.sort_by(|a, b| a.path.cmp(&b.path));
        storage_roots.dedup_by(|a, b| a.path == b.path);
        storage_roots
    }

    fn discover_sources(ctx: &ScanContext) -> Vec<DiscoveredSourceFile> {
        let mut out = Vec::new();
        Self::discover_sqlite_sources(ctx, &mut out);
        // `opencode.db` is authoritative once it exists: opencode's v1.2
        // migration imports the pre-v1.2 file storage
        // (`storage/{session,message,part}`) into the database and then leaves
        // those files untouched. When the DB is present the legacy tree is
        // fully redundant — and on a migrated install it is hundreds of
        // thousands of tiny per-part files. Enumerating them here makes the
        // indexer capture each one into the raw mirror before the scan even
        // starts, which stalls ingestion. Only fall back to discovering legacy
        // sources on pre-v1.2 installs that never migrated (no DB present).
        let has_sqlite_db = out
            .iter()
            .any(|source| source.role == DiscoveredSourceRole::SqliteDatabase);
        if !has_sqlite_db {
            Self::discover_legacy_storage_sources(ctx, &mut out);
        }
        out
    }

    fn discover_sqlite_sources(ctx: &ScanContext, out: &mut Vec<DiscoveredSourceFile>) {
        let mut seen = HashSet::new();

        for root in Self::sqlite_source_roots(ctx) {
            if !root.path.is_file() {
                continue;
            }
            let canonical = std::fs::canonicalize(&root.path).unwrap_or_else(|_| root.path.clone());
            if !seen.insert(canonical) {
                continue;
            }
            out.push(
                DiscoveredSourceFile::new(
                    "opencode",
                    &root,
                    root.path.clone(),
                    DiscoveredSourceRole::SqliteDatabase,
                    true,
                )
                .with_fs_metadata(),
            );
        }
    }

    fn discover_legacy_storage_sources(ctx: &ScanContext, out: &mut Vec<DiscoveredSourceFile>) {
        let mut seen_session_files = HashSet::new();
        for root in Self::storage_source_roots(ctx) {
            let session_dir = root.path.join("session");
            let message_dir = root.path.join("message");
            let part_dir = root.path.join("part");
            if !session_dir.exists() {
                continue;
            }

            let session_files: Vec<PathBuf> = WalkDir::new(&session_dir)
                .into_iter()
                .flatten()
                .filter(|entry| entry.file_type().is_file())
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .map(|entry| entry.path().to_path_buf())
                .collect();

            for session_file in session_files {
                if !seen_session_files.insert(dedupe_path_key(&session_file)) {
                    continue;
                }
                if !session_has_updates(&session_file, &message_dir, &part_dir, ctx.since_ts) {
                    continue;
                }
                out.push(
                    DiscoveredSourceFile::new(
                        "opencode",
                        &root,
                        session_file.clone(),
                        DiscoveredSourceRole::PrimarySessionLog,
                        true,
                    )
                    .with_fs_metadata(),
                );

                Self::discover_legacy_session_sidecars(
                    &root,
                    &session_file,
                    &message_dir,
                    &part_dir,
                    out,
                );
            }
        }
    }

    fn discover_legacy_session_sidecars(
        root: &ScanRoot,
        session_file: &Path,
        message_dir: &Path,
        part_dir: &Path,
        out: &mut Vec<DiscoveredSourceFile>,
    ) {
        let Some(session_id) = session_file.file_stem().and_then(|name| name.to_str()) else {
            return;
        };
        let session_msg_dir = message_dir.join(session_id);
        if !session_msg_dir.exists() {
            return;
        }

        for entry in WalkDir::new(&session_msg_dir).into_iter().flatten() {
            if !entry.file_type().is_file()
                || !entry.path().extension().is_some_and(|ext| ext == "json")
            {
                continue;
            }

            let message_file = entry.path().to_path_buf();
            out.push(
                DiscoveredSourceFile::new(
                    "opencode",
                    root,
                    message_file.clone(),
                    DiscoveredSourceRole::MetadataSidecar,
                    true,
                )
                .with_fs_metadata(),
            );
            Self::discover_legacy_message_parts(root, &message_file, part_dir, out);
        }
    }

    fn discover_legacy_message_parts(
        root: &ScanRoot,
        message_file: &Path,
        part_dir: &Path,
        out: &mut Vec<DiscoveredSourceFile>,
    ) {
        let Some(message_id) = message_file.file_stem().and_then(|name| name.to_str()) else {
            return;
        };
        let message_part_dir = part_dir.join(message_id);
        for part_entry in WalkDir::new(&message_part_dir).into_iter().flatten() {
            if !part_entry.file_type().is_file()
                || part_entry
                    .path()
                    .extension()
                    .is_none_or(|ext| ext != "json")
            {
                continue;
            }
            out.push(
                DiscoveredSourceFile::new(
                    "opencode",
                    root,
                    part_entry.path().to_path_buf(),
                    DiscoveredSourceRole::MetadataSidecar,
                    true,
                )
                .with_fs_metadata(),
            );
        }
    }

    /// Extract sessions from OpenCode's SQLite database (v1.2+).
    ///
    /// Schema: session(id, title, directory, project_id, time_created, time_updated),
    ///         message(id, session_id, data JSON), part(id, message_id, session_id, data JSON)
    /// Collect every conversation from an OpenCode SQLite DB into a Vec.
    ///
    /// Thin collector over the streaming core, retained for tests that assert on
    /// the full result set. Production paths (`scan` / `scan_with_callback`) drive
    /// `stream_from_sqlite` directly so peak memory tracks a single session rather
    /// than the whole corpus.
    #[cfg(test)]
    fn extract_from_sqlite(
        db_path: &Path,
        since_ts: Option<i64>,
    ) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        let mut seen_ids = HashSet::new();
        Self::stream_from_sqlite(db_path, since_ts, &mut seen_ids, &mut |conv| {
            convs.push(conv);
            Ok(())
        })?;
        Ok(convs)
    }

    /// Stream conversations from an OpenCode SQLite DB one session at a time.
    ///
    /// The `part` table on a real OpenCode DB is routinely multiple GB (tool
    /// outputs, inlined base64 files). The previous implementation loaded the
    /// entire `part` and `message` tables into memory before assembling anything,
    /// so peak heap scaled with the whole corpus and OOM'd large DBs. Here we read
    /// only the small `session` table up front, then load each session's messages
    /// and parts scoped by `session_id` — both columns are indexed
    /// (`part_session_idx`, `message_session_time_created_id_idx`) — emit the
    /// conversation, and let it drop. Peak memory tracks the single largest
    /// session, not the database.
    fn stream_from_sqlite(
        db_path: &Path,
        since_ts: Option<i64>,
        seen_ids: &mut HashSet<String>,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("failed to open OpenCode db: {}", db_path.display()))?;

        conn.busy_timeout(std::time::Duration::from_secs(5))
            .with_context(|| "failed to set busy_timeout")?;

        // Read timestamps as raw SQLite values — Drizzle ORM may store them as ISO
        // text (YYYY-MM-DD HH:MM:SS) or epoch integers; we normalize in Rust rather
        // than using strftime() which breaks on integer columns.
        let sessions: Vec<SqliteSession> = {
            let mut stmt = conn
                .prepare(
                    "SELECT id, title, directory, project_id, time_created, time_updated FROM session",
                )
                .with_context(|| "failed to prepare OpenCode sessions query")?;
            stmt.query_map([], |row| {
                Ok(SqliteSession {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    directory: row.get(2)?,
                    project_id: row.get(3)?,
                    time_created_raw: optional_sqlite_value(row, 4),
                    time_updated_raw: optional_sqlite_value(row, 5),
                })
            })
            .with_context(|| "failed to query OpenCode sessions")?
            .collect::<rusqlite::Result<Vec<_>>>()
            .with_context(|| "failed to read OpenCode session rows")?
        };

        warn_on_opencode_schema_drift(&conn, db_path);

        // Per-session statements, prepared once and reused. Both are scoped by
        // session_id (indexed by message_session_time_created_id_idx and
        // part_session_idx), so each fetches only one session's rows.
        let mut msg_stmt = conn
            .prepare(
                "SELECT id, data, time_created FROM message
                 WHERE session_id = ?1
                 ORDER BY time_created ASC, id ASC",
            )
            .with_context(|| "failed to prepare OpenCode messages query")?;
        // No ORDER BY: load_session_parts groups parts by message_id and
        // sort_parts_for_message re-sorts each message's parts, so a SQL sort here
        // would only build a per-session temp b-tree that is immediately discarded.
        let mut part_stmt = conn
            .prepare("SELECT message_id, data FROM part WHERE session_id = ?1")
            .with_context(|| "failed to prepare OpenCode parts query")?;

        for session in sessions {
            let session_created_ms = session
                .time_created_raw
                .as_ref()
                .and_then(normalize_sqlite_ts_value);
            let session_updated_ms = session
                .time_updated_raw
                .as_ref()
                .and_then(normalize_sqlite_ts_value);

            // Incremental fast-path: skip loading a session's messages/parts when
            // its own update timestamp predates since_ts. Gate on session_updated_ms
            // specifically (not created) — the post-load filter sets
            // ended_at = session_updated_ms.or(msg_ended_at)..., so skipping only on
            // session_updated_ms keeps this a strict subset of what the post-load
            // filter rejects: we never drop a session it would have kept (e.g. one
            // with no time_updated but newer messages).
            if let Some(since) = since_ts
                && let Some(updated) = session_updated_ms
                && updated < since
            {
                continue;
            }

            // First occurrence of a session id wins (dedupes within and across DBs,
            // and against the legacy JSON path that shares this set). Claimed only
            // after the since fast-path, so a since-skipped session does not block
            // the JSON fallback — matching the pre-rewrite dedup semantics.
            if !seen_ids.insert(session.id.clone()) {
                continue;
            }

            let parts_by_message = Self::load_session_parts(&mut part_stmt, &session.id)?;
            let messages =
                Self::load_session_messages(&mut msg_stmt, &session.id, parts_by_message)?;
            if messages.is_empty() {
                continue;
            }

            let msg_started_at = messages.iter().filter_map(|m| m.created_at).min();
            let msg_ended_at = messages.iter().filter_map(|m| m.created_at).max();

            let started_at = session_created_ms.or(msg_started_at);
            let ended_at = session_updated_ms.or(msg_ended_at).or(started_at);

            // Final since_ts filter, for sessions whose only timestamp came from
            // their messages (no usable session timestamp for the fast-path above).
            if let Some(since) = since_ts {
                let latest = ended_at.or(started_at).unwrap_or(0);
                if latest < since {
                    continue;
                }
            }

            let workspace = session.directory.map(PathBuf::from);
            let title = session.title.or_else(|| {
                messages
                    .first()
                    .and_then(|m| m.content.lines().next())
                    .map(|s| s.chars().take(100).collect())
            });

            on_conversation(NormalizedConversation {
                agent_slug: "opencode".into(),
                external_id: Some(session.id.clone()),
                title,
                workspace,
                source_path: db_path.join(urlencoding::encode(&session.id).as_ref()),
                started_at,
                ended_at,
                metadata: serde_json::json!({
                    "session_id": session.id,
                    "project_id": session.project_id,
                    "source": "sqlite",
                }),
                messages,
                ..Default::default()
            })?;
        }

        Ok(())
    }

    /// Load one session's messages (scoped by `session_id`), draining its parts
    /// from `parts_by_message` and assembling per-message content.
    fn load_session_messages(
        stmt: &mut rusqlite::Statement<'_>,
        session_id: &str,
        mut parts_by_message: HashMap<String, Vec<PartInfo>>,
    ) -> Result<Vec<NormalizedMessage>> {
        let mut pending: Vec<PendingSqliteMessage> = Vec::new();
        let mut rows = stmt
            .query([session_id])
            .with_context(|| "failed to query OpenCode messages")?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let data_json: String = row.get(1)?;
            let time_created_raw = optional_sqlite_value(row, 2);

            let msg_data: SqliteMessageData = match serde_json::from_str(&data_json) {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!("opencode sqlite: failed to parse message data for {id}: {e}");
                    continue;
                }
            };

            let parts = parts_by_message.remove(&id).unwrap_or_default();
            let content_text = if parts.is_empty() {
                String::new()
            } else {
                assemble_content_from_parts(&parts)
            };
            if content_text.trim().is_empty() {
                continue;
            }

            let role = msg_data.role.unwrap_or_else(|| "assistant".to_string());
            let col_ts = time_created_raw
                .as_ref()
                .and_then(normalize_sqlite_ts_value);
            let created_at =
                normalize_opencode_timestamp(msg_data.time.as_ref().and_then(|t| t.created))
                    .or(col_ts);
            let author = if role == "assistant" {
                msg_data.model_id.clone()
            } else {
                Some("user".to_string())
            };

            pending.push(PendingSqliteMessage {
                created_at,
                message_id: id.clone(),
                message: NormalizedMessage {
                    idx: 0,
                    role,
                    author,
                    created_at,
                    content: content_text,
                    extra: serde_json::json!({
                        "message_id": id,
                        "session_id": session_id,
                    }),
                    invocations: Vec::new(),
                    snippets: Vec::new(),
                    ..Default::default()
                },
            });
        }

        pending.sort_by(|a, b| {
            let a_ts = a.created_at.unwrap_or(i64::MAX);
            let b_ts = b.created_at.unwrap_or(i64::MAX);
            a_ts.cmp(&b_ts)
                .then_with(|| a.message_id.cmp(&b.message_id))
        });
        let mut messages: Vec<NormalizedMessage> =
            pending.into_iter().map(|pending| pending.message).collect();
        crate::types::reindex_messages(&mut messages);
        Ok(messages)
    }

    /// Load one session's parts (scoped by `session_id`), grouped by message id.
    /// Each row's raw `data` string is transient — `SqlitePartData` ignores the
    /// `file` part's base64 `url`, so inlined images are not retained in memory.
    fn load_session_parts(
        stmt: &mut rusqlite::Statement<'_>,
        session_id: &str,
    ) -> Result<HashMap<String, Vec<PartInfo>>> {
        let mut parts_by_message: HashMap<String, Vec<PartInfo>> = HashMap::new();
        let mut rows = stmt
            .query([session_id])
            .with_context(|| "failed to query OpenCode parts")?;
        while let Some(row) = rows.next()? {
            let message_id: String = row.get(0)?;
            let data: String = row.get(1)?;
            match serde_json::from_str::<SqlitePartData>(&data) {
                Ok(part_data) => {
                    parts_by_message
                        .entry(message_id)
                        .or_default()
                        .push(PartInfo {
                            id: part_data.id,
                            index: part_data.index,
                            message_id: None,
                            part_type: part_data.part_type,
                            text: part_data.text,
                            state: part_data.state,
                        });
                }
                Err(e) => {
                    tracing::debug!("opencode sqlite: failed to parse part data: {e}");
                }
            }
        }

        for parts in parts_by_message.values_mut() {
            sort_parts_for_message(parts);
        }

        Ok(parts_by_message)
    }
}

struct PendingSqliteMessage {
    created_at: Option<i64>,
    message_id: String,
    message: NormalizedMessage,
}

/// Session row from SQLite.
/// Timestamps are read as raw SQLite values because Drizzle ORM
/// may store them as TEXT (ISO 8601) or INTEGER (epoch seconds/ms).
struct SqliteSession {
    id: String,
    title: Option<String>,
    directory: Option<String>,
    project_id: Option<String>,
    time_created_raw: Option<SqliteValue>,
    time_updated_raw: Option<SqliteValue>,
}

/// Deserialized message.data JSON from SQLite.
#[derive(Debug, Deserialize)]
struct SqliteMessageData {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    time: Option<MessageTime>,
    #[serde(rename = "modelID", default)]
    model_id: Option<String>,
}

/// Deserialized part.data JSON from SQLite.
#[derive(Debug, Deserialize)]
struct SqlitePartData {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, alias = "order", alias = "sequence")]
    index: Option<i64>,
    #[serde(rename = "type", default)]
    part_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    state: Option<ToolState>,
}

// ============================================================================
// JSON Structures for OpenCode Storage (pre-v1.2 flat files)
// ============================================================================

/// Session info from session/{projectID}/{sessionID}.json
#[derive(Debug, Deserialize)]
struct SessionInfo {
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    #[serde(rename = "projectID", default)]
    project_id: Option<String>,
    #[serde(default)]
    time: Option<SessionTime>,
}

#[derive(Debug, Deserialize)]
struct SessionTime {
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    updated: Option<i64>,
}

/// Message info from message/{sessionID}/{messageID}.json
#[derive(Debug, Deserialize)]
struct MessageInfo {
    id: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    time: Option<MessageTime>,
    #[serde(rename = "modelID", default)]
    model_id: Option<String>,
    #[serde(rename = "sessionID", default)]
    session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MessageTime {
    #[serde(default)]
    created: Option<i64>,
    #[serde(default)]
    #[allow(dead_code)]
    completed: Option<i64>,
}

/// Part info from part/{messageID}/{partID}.json
#[derive(Debug, Clone, Deserialize)]
struct PartInfo {
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
    #[serde(default, alias = "order", alias = "sequence")]
    index: Option<i64>,
    #[serde(rename = "messageID", default)]
    #[allow(dead_code)]
    message_id: Option<String>,
    #[serde(rename = "type", default)]
    part_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
    // Tool state for tool parts
    #[serde(default)]
    state: Option<ToolState>,
}

#[derive(Debug, Clone, Deserialize)]
struct ToolState {
    #[serde(default)]
    output: Option<String>,
}

impl Connector for OpenCodeConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("opencode").unwrap_or_else(DetectionResult::not_found)
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut convs = Vec::new();
        self.scan_with_callback(ctx, &mut |conv| {
            convs.push(conv);
            Ok(())
        })?;
        Ok(convs)
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        on_conversation: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        // Shared across the SQLite stream and the legacy JSON fallback so a
        // session present in both sources is emitted only once (first wins).
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut scanned_dbs: HashSet<PathBuf> = HashSet::new();

        // --- Phase 1: Try SQLite database(s) (v1.2+) ---
        // Collect candidate database paths in priority order:
        //   1. If ctx.data_dir looks like a path to `opencode.db` itself
        //      (has a `.db` extension), use it as-is.
        //   2. Otherwise, if ctx.data_dir is non-empty, treat it as a
        //      directory and check for `<data_dir>/opencode.db`.
        //   3. Always add the built-in default search list. This ensures
        //      we find the canonical XDG location even when explicit scan
        //      roots or a stale detection path were passed in (see issue #174).
        //
        // Non-existence of any candidate is filtered at iteration time
        // (`if !db.exists() { continue; }` below), so we do not gate the
        // `extension == "db"` branch on `.exists()` — otherwise a
        // user-supplied .db path that doesn't exist yet would silently
        // fall through to the "join opencode.db" branch and produce a
        // nonsense `/path/to/file.db/opencode.db` candidate.
        let mut db_candidates: Vec<PathBuf> = Vec::new();
        if ctx.data_dir.extension().is_some_and(|ext| ext == "db") {
            db_candidates.push(ctx.data_dir.clone());
        } else if !ctx.data_dir.as_os_str().is_empty() {
            db_candidates.push(ctx.data_dir.join("opencode.db"));
        }

        if !ctx.use_default_detection() {
            for scan_root in &ctx.scan_roots {
                Self::append_explicit_db_candidates(&mut db_candidates, &scan_root.path);
            }
        }

        db_candidates.extend(Self::sqlite_db_candidates());

        // Deduplicate while preserving priority order.
        {
            let mut seen = HashSet::new();
            db_candidates.retain(|p| seen.insert(p.clone()));
        }

        for db in db_candidates {
            if !db.is_file() {
                continue;
            }
            // Canonicalize if possible so two routes to the same file are
            // still deduplicated (e.g. via symlink or `./`-prefixed path).
            let canonical = std::fs::canonicalize(&db).unwrap_or_else(|_| db.clone());
            if !scanned_dbs.insert(canonical) {
                continue;
            }
            // Stream this DB's sessions straight to the callback. A broken DB
            // (open/prepare/query failure) is logged and skipped — not fatal,
            // matching the prior per-candidate handling. But a callback error
            // (the orchestrator failing to ingest a conversation) must PROPAGATE,
            // not be swallowed by that DB-error skip — capture it separately so we
            // can return it instead of reporting a false success. seen_ids is
            // updated as sessions are emitted.
            let mut callback_error: Option<anyhow::Error> = None;
            let stream_result =
                Self::stream_from_sqlite(&db, ctx.since_ts, &mut seen_ids, &mut |conv| {
                    on_conversation(conv).map_err(|err| {
                        callback_error = Some(err);
                        anyhow::anyhow!("opencode: conversation callback failed")
                    })
                });
            if let Some(err) = callback_error {
                return Err(err);
            }
            if let Err(e) = stream_result {
                tracing::debug!("opencode sqlite: failed to read {}: {e}", db.display());
            }
        }

        // --- Phase 2: Fall back to JSON file storage (pre-v1.2) ---
        //
        // The SQLite database is authoritative once it has yielded any session:
        // opencode's v1.2 migration imports the legacy file storage into the DB
        // and stops writing the files, so a populated DB already contains every
        // legacy session (the dedup set would drop them all anyway). Skipping
        // the fallback avoids re-walking and re-parsing the migrated tree, which
        // on a real install is 100k+ message + part files. Only pre-v1.2
        // installs that never migrated (no DB, so `seen_ids` is empty) still
        // need the file scan.
        if !seen_ids.is_empty() {
            return Ok(());
        }

        let mut storage_roots: Vec<PathBuf> = Vec::new();
        if ctx.use_default_detection() {
            if ctx.data_dir.exists() && looks_like_opencode_storage(&ctx.data_dir) {
                storage_roots.push(ctx.data_dir.clone());
            } else if let Some(root) = Self::storage_root() {
                storage_roots.push(root);
            }
        } else {
            if ctx.data_dir.exists() && looks_like_opencode_storage(&ctx.data_dir) {
                storage_roots.push(ctx.data_dir.clone());
            }
            for scan_root in &ctx.scan_roots {
                let mut candidates = vec![scan_root.path.clone()];
                Self::append_explicit_storage_candidates(&mut candidates, &scan_root.path);
                for candidate in candidates {
                    if candidate.exists() && looks_like_opencode_storage(&candidate) {
                        storage_roots.push(candidate);
                    }
                }
            }
        }

        if storage_roots.is_empty() {
            return Ok(());
        }

        storage_roots.sort();
        storage_roots.dedup();

        let mut seen_session_files: HashSet<PathBuf> = HashSet::new();

        for storage_root in storage_roots {
            let session_dir = storage_root.join("session");
            let message_dir = storage_root.join("message");
            let part_dir = storage_root.join("part");

            if !session_dir.exists() {
                continue;
            }

            // Collect all session files
            let session_files: Vec<PathBuf> = WalkDir::new(&session_dir)
                .into_iter()
                .flatten()
                .filter(|e| e.file_type().is_file())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "json")
                        .unwrap_or(false)
                })
                .map(|e| e.path().to_path_buf())
                .collect();

            for session_file in session_files {
                if !seen_session_files.insert(dedupe_path_key(&session_file)) {
                    continue;
                }
                if !session_has_updates(&session_file, &message_dir, &part_dir, ctx.since_ts) {
                    continue;
                }

                // Parse session
                let session = match parse_session_file(&session_file) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(
                            "opencode: failed to parse session {}: {e}",
                            session_file.display()
                        );
                        continue;
                    }
                };

                // Deduplicate by session ID
                if !seen_ids.insert(session.id.clone()) {
                    continue;
                }

                // Load messages for this session
                let session_msg_dir = message_dir.join(&session.id);
                let messages = if session_msg_dir.exists() {
                    load_messages(&session_msg_dir, &part_dir)?
                } else {
                    Vec::new()
                };

                if messages.is_empty() {
                    continue;
                }

                // Build normalized conversation
                let msg_started_at = messages.iter().filter_map(|m| m.created_at).min();
                let msg_ended_at = messages.iter().filter_map(|m| m.created_at).max();

                let started_at = session
                    .time
                    .as_ref()
                    .and_then(|t| normalize_opencode_timestamp(t.created))
                    .or(msg_started_at);
                let ended_at = session
                    .time
                    .as_ref()
                    .and_then(|t| normalize_opencode_timestamp(t.updated))
                    .or(msg_ended_at)
                    .or(started_at);

                let workspace = session.directory.map(PathBuf::from);
                let title = session.title.or_else(|| {
                    messages
                        .first()
                        .and_then(|m| m.content.lines().next())
                        .map(|s| s.chars().take(100).collect())
                });

                on_conversation(NormalizedConversation {
                    agent_slug: "opencode".into(),
                    external_id: Some(session.id.clone()),
                    title,
                    workspace,
                    source_path: session_file.clone(),
                    started_at,
                    ended_at,
                    metadata: serde_json::json!({
                        "session_id": session.id,
                        "project_id": session.project_id,
                    }),
                    messages,
                    ..Default::default()
                })?;
            }
        }

        Ok(())
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        Ok(Self::discover_sources(ctx))
    }
}

/// Check if a directory looks like OpenCode storage
fn looks_like_opencode_storage(path: &std::path::Path) -> bool {
    // Check for characteristic subdirectories.
    // We require 'session' and 'message' to be present to confirm this is an OpenCode storage root.
    // relying on the path name containing "opencode" is too loose and causes shadowing
    // if the CASS data directory has "opencode" in its name.
    path.join("session").exists() && path.join("message").exists()
}

/// The closed set of tables the schema-drift guard probes. Keeping it an enum
/// means the count query below is built from a compile-time string literal — the
/// table name is never interpolated from a caller-supplied string.
#[derive(Clone, Copy)]
enum OpenCodeRowCount {
    Message,
    SessionMessage,
}

/// Count rows in one of the known OpenCode tables, returning `None` when the
/// table does not exist (the query errors, which `.ok()` maps to `None`).
fn count_known_table_rows(conn: &Connection, table: OpenCodeRowCount) -> Option<i64> {
    let count_sql = match table {
        OpenCodeRowCount::Message => "SELECT count(*) FROM message",
        OpenCodeRowCount::SessionMessage => "SELECT count(*) FROM session_message",
    };
    conn.query_row(count_sql, [], |r| r.get(0)).ok()
}

/// Warn loudly when the `message`/`part` tables this connector reads are empty
/// but the newer `session_message` table is populated — i.e. OpenCode migrated
/// to a schema this connector does not yet read. Without this, the scan would
/// silently return zero conversations and look like a successful no-op.
fn warn_on_opencode_schema_drift(conn: &Connection, db_path: &Path) {
    if count_known_table_rows(conn, OpenCodeRowCount::Message).unwrap_or(0) != 0 {
        return;
    }
    if let Some(session_message_rows) =
        count_known_table_rows(conn, OpenCodeRowCount::SessionMessage)
        && session_message_rows > 0
    {
        tracing::warn!(
            db = %db_path.display(),
            session_message_rows,
            "opencode: `message` table is empty but `session_message` has rows; OpenCode \
             may have migrated to a schema this connector does not read — indexing 0 \
             OpenCode conversations from this database"
        );
    }
}

fn normalize_opencode_timestamp(ts: Option<i64>) -> Option<i64> {
    ts.map(|raw| {
        // OpenCode appears to store epoch timestamps in milliseconds (see fixtures),
        // but some sources may emit epoch seconds. We treat "plausible epoch seconds"
        // as seconds and otherwise assume milliseconds (including small synthetic test values).
        if (1_000_000_000..10_000_000_000).contains(&raw) {
            raw.saturating_mul(1000)
        } else {
            raw
        }
    })
}

fn optional_sqlite_value(row: &Row, index: usize) -> Option<SqliteValue> {
    match row.get::<_, SqliteValue>(index) {
        Ok(SqliteValue::Null) | Err(_) => None,
        Ok(value) => Some(value),
    }
}

/// Normalize a raw SQLite value to epoch milliseconds.
///
/// Drizzle ORM can store timestamps as:
///  - TEXT: ISO 8601 strings like `"2024-01-15 14:30:00"` or `"2024-01-15T14:30:00"`
///  - INTEGER: epoch seconds (e.g. `1700000000`) or epoch milliseconds (e.g. `1700000000000`)
///
/// Returns `None` for NULL or unparseable values.
fn normalize_sqlite_ts_value(val: &SqliteValue) -> Option<i64> {
    match val {
        SqliteValue::Integer(i) => normalize_opencode_timestamp(Some(*i)),
        SqliteValue::Real(f) => normalize_opencode_timestamp(Some(*f as i64)),
        SqliteValue::Text(s) => {
            // Try common SQLite/Drizzle datetime formats (space separator)
            if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
                Some(dt.and_utc().timestamp_millis())
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
            {
                Some(dt.and_utc().timestamp_millis())
            // ISO 8601 with T separator
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
                Some(dt.and_utc().timestamp_millis())
            } else if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
            {
                Some(dt.and_utc().timestamp_millis())
            // RFC 3339 with timezone (e.g. "2024-01-15T14:30:00Z")
            } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                Some(dt.timestamp_millis())
            } else {
                // Last resort: try parsing as integer string
                s.trim()
                    .parse::<i64>()
                    .ok()
                    .and_then(|i| normalize_opencode_timestamp(Some(i)))
            }
        }
        SqliteValue::Null | SqliteValue::Blob(_) => None,
    }
}

fn session_has_updates(
    session_file: &Path,
    message_root: &Path,
    part_root: &Path,
    since_ts: Option<i64>,
) -> bool {
    if since_ts.is_none() {
        return true;
    }

    if file_modified_since(session_file, since_ts) {
        return true;
    }

    let session_id = session_file
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_string);
    let Some(session_id) = session_id else {
        return true;
    };

    let session_msg_dir = message_root.join(&session_id);
    if !session_msg_dir.exists() {
        return false;
    }

    let mut message_ids = Vec::new();
    if let Ok(entries) = fs::read_dir(&session_msg_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if path.extension().map(|ext| ext == "json").unwrap_or(false) {
                if file_modified_since(&path, since_ts) {
                    return true;
                }
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    message_ids.push(stem.to_string());
                }
            }
        }
    }

    for message_id in message_ids {
        let part_dir = part_root.join(&message_id);
        if !part_dir.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&part_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if file_modified_since(&path, since_ts) {
                    return true;
                }
            }
        }
    }

    false
}

/// Parse a session JSON file
fn parse_session_file(path: &Path) -> Result<SessionInfo> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read session file {}", path.display()))?;
    let session: SessionInfo = serde_json::from_str(&content)
        .with_context(|| format!("parse session JSON {}", path.display()))?;
    Ok(session)
}

/// Load all messages for a session
fn load_messages(session_msg_dir: &Path, part_dir: &Path) -> Result<Vec<NormalizedMessage>> {
    let mut pending: Vec<(Option<i64>, String, NormalizedMessage)> = Vec::new();

    // Find all message files for this session
    let msg_files: Vec<PathBuf> = WalkDir::new(session_msg_dir)
        .max_depth(1)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    for msg_file in msg_files {
        let content = match fs::read_to_string(&msg_file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let msg_info: MessageInfo = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Load parts for this specific message
        let mut parts = Vec::new();
        let msg_part_dir = part_dir.join(&msg_info.id);

        if msg_part_dir.exists() {
            for entry in WalkDir::new(&msg_part_dir)
                .max_depth(1)
                .into_iter()
                .flatten()
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false)
                    && let Ok(content) = fs::read_to_string(path)
                    && let Ok(part) = serde_json::from_str::<PartInfo>(&content)
                {
                    parts.push(part);
                }
            }
        }
        sort_parts_for_message(&mut parts);

        // Assemble message content from parts
        let content_text = assemble_content_from_parts(&parts);
        if content_text.trim().is_empty() {
            continue;
        }

        // Determine role
        let role = msg_info
            .role
            .clone()
            .unwrap_or_else(|| "assistant".to_string());

        // Determine timestamp
        let created_at =
            normalize_opencode_timestamp(msg_info.time.as_ref().and_then(|t| t.created));

        // Author from model_id for assistant messages
        let author = if role == "assistant" {
            msg_info.model_id.clone()
        } else {
            Some("user".to_string())
        };

        let message_id = msg_info.id.clone();
        pending.push((
            created_at,
            message_id.clone(),
            NormalizedMessage {
                idx: 0, // Will be assigned later
                role,
                author,
                created_at,
                content: content_text,
                extra: serde_json::json!({
                    "message_id": message_id,
                    "session_id": msg_info.session_id,
                }),
                invocations: Vec::new(),
                snippets: Vec::new(),
                ..Default::default()
            },
        ));
    }

    // Sort by timestamp, then by message id to ensure deterministic ordering.
    pending.sort_by(|a, b| {
        let a_ts = a.0.unwrap_or(i64::MAX);
        let b_ts = b.0.unwrap_or(i64::MAX);
        a_ts.cmp(&b_ts).then_with(|| a.1.cmp(&b.1))
    });
    let mut messages: Vec<NormalizedMessage> = pending.into_iter().map(|(_, _, msg)| msg).collect();
    crate::types::reindex_messages(&mut messages);

    Ok(messages)
}

fn sort_parts_for_message(parts: &mut [PartInfo]) {
    parts.sort_by(|a, b| {
        let a_idx = a.index.unwrap_or(i64::MAX);
        let b_idx = b.index.unwrap_or(i64::MAX);
        a_idx
            .cmp(&b_idx)
            .then_with(|| {
                a.id.as_deref()
                    .unwrap_or("")
                    .cmp(b.id.as_deref().unwrap_or(""))
            })
            .then_with(|| {
                a.part_type
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.part_type.as_deref().unwrap_or(""))
            })
            .then_with(|| {
                a.text
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.text.as_deref().unwrap_or(""))
            })
    });
}

/// Cap on a single part's contributed text. OpenCode tool outputs can reach
/// multiple MB (whole-file dumps, command spew); the head carries the search
/// signal, so we keep the head and mark the truncated tail.
const MAX_PART_CONTENT_BYTES: usize = 256 * 1024;
/// Cap on a single message's total assembled content. A pathological session can
/// hold a 100+ MB message; bound it so neither the heap nor the lexical indexer
/// chokes on one document.
const MAX_MESSAGE_CONTENT_BYTES: usize = 1024 * 1024;

/// Truncate `s` to at most `max_bytes`, snapping down to a UTF-8 char boundary.
/// Returns the (possibly shortened) slice and whether truncation occurred.
fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> (&str, bool) {
    if s.len() <= max_bytes {
        return (s, false);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], true)
}

/// Cap a single part's body, appending a byte-count marker when truncated.
fn cap_part_body(body: &str) -> String {
    let (head, truncated) = truncate_on_char_boundary(body, MAX_PART_CONTENT_BYTES);
    if truncated {
        format!("{head}\n[… truncated {} bytes]", body.len() - head.len())
    } else {
        head.to_string()
    }
}

/// Assemble message content from parts.
///
/// Each part's body is capped at `MAX_PART_CONTENT_BYTES`. The assembled message
/// is bounded by `MAX_MESSAGE_CONTENT_BYTES` as a SOFT cap: the check fires before
/// appending each piece, so the piece that crosses the threshold is still added —
/// the true upper bound is `MAX_MESSAGE_CONTENT_BYTES + MAX_PART_CONTENT_BYTES`
/// (~1.25 MiB) plus the truncation marker. That keeps one giant tool output (or a
/// session with thousands of large parts) from ballooning a single message's
/// content. Output is byte-identical to the uncapped path for content under the caps.
fn assemble_content_from_parts(parts: &[PartInfo]) -> String {
    let mut content_pieces: Vec<String> = Vec::new();
    let mut total_bytes = 0usize;

    for part in parts {
        let piece = match part.part_type.as_deref() {
            Some("text") => part
                .text
                .as_deref()
                .filter(|t| !t.trim().is_empty())
                .map(cap_part_body),
            Some("tool") => part
                .state
                .as_ref()
                .and_then(|s| s.output.as_deref())
                .filter(|o| !o.trim().is_empty())
                .map(|o| format!("[Tool Output]\n{}", cap_part_body(o))),
            Some("reasoning") => part
                .text
                .as_deref()
                .filter(|t| !t.trim().is_empty())
                .map(|t| format!("[Reasoning]\n{}", cap_part_body(t))),
            Some("patch") => part
                .text
                .as_deref()
                .filter(|t| !t.trim().is_empty())
                .map(|t| format!("[Patch]\n{}", cap_part_body(t))),
            // Ignore step-start, step-finish, and other control parts.
            _ => None,
        };
        // Only real (non-empty) pieces count toward the cap and trigger the
        // truncation marker — control/empty parts after the cap is crossed must
        // not produce a spurious marker for content that was never dropped.
        let Some(piece) = piece else { continue };
        if total_bytes >= MAX_MESSAGE_CONTENT_BYTES {
            content_pieces.push("[… message content truncated]".to_string());
            break;
        }
        total_bytes += piece.len() + 2; // + "\n\n" separator
        content_pieces.push(piece);
    }

    content_pieces.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use serde_json::json;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn open_test_connection(path: &Path) -> Connection {
        Connection::open(path).unwrap()
    }

    // =====================================================
    // Constructor Tests
    // =====================================================

    #[test]
    fn new_creates_connector() {
        let connector = OpenCodeConnector::new();
        let _ = connector;
    }

    #[test]
    fn default_creates_connector() {
        let connector = OpenCodeConnector;
        let _ = connector;
    }

    // =====================================================
    // looks_like_opencode_storage() Tests
    // =====================================================

    #[test]
    fn looks_like_opencode_storage_requires_subdirs() {
        let dir = TempDir::new().unwrap();
        let opencode_path = dir.path().join("opencode").join("test");
        fs::create_dir_all(&opencode_path).unwrap();

        // Name alone should NOT be enough (prevents shadowing)
        assert!(!looks_like_opencode_storage(&opencode_path));

        // Adding subdirs makes it valid
        fs::create_dir_all(opencode_path.join("session")).unwrap();
        fs::create_dir_all(opencode_path.join("message")).unwrap();
        assert!(looks_like_opencode_storage(&opencode_path));
    }

    #[test]
    fn looks_like_opencode_storage_with_session_dir() {
        let dir = TempDir::new().unwrap();
        // Requires both session AND message subdirs
        fs::create_dir_all(dir.path().join("session")).unwrap();
        assert!(!looks_like_opencode_storage(dir.path()));
        fs::create_dir_all(dir.path().join("message")).unwrap();
        assert!(looks_like_opencode_storage(dir.path()));
    }

    #[test]
    fn looks_like_opencode_storage_with_message_dir() {
        let dir = TempDir::new().unwrap();
        // Requires both session AND message subdirs
        fs::create_dir_all(dir.path().join("message")).unwrap();
        assert!(!looks_like_opencode_storage(dir.path()));
        fs::create_dir_all(dir.path().join("session")).unwrap();
        assert!(looks_like_opencode_storage(dir.path()));
    }

    #[test]
    fn looks_like_opencode_storage_with_part_dir() {
        let dir = TempDir::new().unwrap();
        // part alone is not enough; need session + message
        fs::create_dir_all(dir.path().join("part")).unwrap();
        assert!(!looks_like_opencode_storage(dir.path()));
        fs::create_dir_all(dir.path().join("session")).unwrap();
        fs::create_dir_all(dir.path().join("message")).unwrap();
        assert!(looks_like_opencode_storage(dir.path()));
    }

    #[test]
    fn looks_like_opencode_storage_returns_false_for_random_dir() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("random")).unwrap();
        assert!(!looks_like_opencode_storage(dir.path()));
    }

    // =====================================================
    // session_has_updates() Tests
    // =====================================================

    #[test]
    fn session_has_updates_detects_message_file_change() {
        let dir = TempDir::new().unwrap();
        let storage = dir.path();
        let session_dir = storage.join("session/proj");
        let message_dir = storage.join("message/session-1");
        let part_dir = storage.join("part");
        fs::create_dir_all(&session_dir).unwrap();
        fs::create_dir_all(&message_dir).unwrap();
        fs::create_dir_all(&part_dir).unwrap();

        let session_file = session_dir.join("session-1.json");
        fs::write(&session_file, r#"{"id":"session-1"}"#).unwrap();

        let message_file = message_dir.join("msg-1.json");
        fs::write(&message_file, r#"{"id":"msg-1","role":"user"}"#).unwrap();

        let since_ts = file_mtime_ms(&message_file);

        let updated_message_file = message_dir.join("msg-2.json");
        fs::write(&updated_message_file, r#"{"id":"msg-2","role":"user"}"#).unwrap();

        assert!(session_has_updates(
            &session_file,
            &storage.join("message"),
            &storage.join("part"),
            Some(since_ts)
        ));
    }

    #[test]
    fn session_has_updates_detects_part_file_change() {
        let dir = TempDir::new().unwrap();
        let storage = dir.path();
        let session_dir = storage.join("session/proj");
        let message_dir = storage.join("message/session-1");
        let part_dir = storage.join("part");
        fs::create_dir_all(&session_dir).unwrap();
        fs::create_dir_all(&message_dir).unwrap();
        fs::create_dir_all(&part_dir).unwrap();

        let session_file = session_dir.join("session-1.json");
        fs::write(&session_file, r#"{"id":"session-1"}"#).unwrap();

        let message_file = message_dir.join("msg-1.json");
        fs::write(&message_file, r#"{"id":"msg-1","role":"assistant"}"#).unwrap();

        let since_ts = file_mtime_ms(&message_file);

        let part_dir_for_message = part_dir.join("msg-1");
        fs::create_dir_all(&part_dir_for_message).unwrap();
        fs::write(part_dir_for_message.join("part-1.json"), r#"{"text":"hi"}"#).unwrap();

        assert!(session_has_updates(
            &session_file,
            &storage.join("message"),
            &storage.join("part"),
            Some(since_ts)
        ));
    }

    fn file_mtime_ms(path: &Path) -> i64 {
        std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }

    // =====================================================
    // assemble_content_from_parts() Tests
    // =====================================================

    #[test]
    fn assemble_content_from_text_parts() {
        let parts = vec![
            PartInfo {
                id: Some("p1".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("Hello, world!".into()),
                state: None,
            },
            PartInfo {
                id: Some("p2".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("Second part".into()),
                state: None,
            },
        ];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("Hello, world!"));
        assert!(content.contains("Second part"));
    }

    #[test]
    fn assemble_content_from_tool_parts() {
        let parts = vec![PartInfo {
            id: Some("p1".into()),
            index: None,
            message_id: Some("m1".into()),
            part_type: Some("tool".into()),
            text: None,
            state: Some(ToolState {
                output: Some("Tool executed successfully".into()),
            }),
        }];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("[Tool Output]"));
        assert!(content.contains("Tool executed successfully"));
    }

    #[test]
    fn assemble_content_from_reasoning_parts() {
        let parts = vec![PartInfo {
            id: Some("p1".into()),
            index: None,
            message_id: Some("m1".into()),
            part_type: Some("reasoning".into()),
            text: Some("Let me think about this...".into()),
            state: None,
        }];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("[Reasoning]"));
        assert!(content.contains("Let me think about this..."));
    }

    #[test]
    fn assemble_content_from_patch_parts() {
        let parts = vec![PartInfo {
            id: Some("p1".into()),
            index: None,
            message_id: Some("m1".into()),
            part_type: Some("patch".into()),
            text: Some("@@ -1,3 +1,4 @@".into()),
            state: None,
        }];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("[Patch]"));
        assert!(content.contains("@@ -1,3 +1,4 @@"));
    }

    #[test]
    fn assemble_content_skips_empty_text() {
        let parts = vec![
            PartInfo {
                id: Some("p1".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("".into()),
                state: None,
            },
            PartInfo {
                id: Some("p2".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("   ".into()),
                state: None,
            },
            PartInfo {
                id: Some("p3".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("Actual content".into()),
                state: None,
            },
        ];
        let content = assemble_content_from_parts(&parts);
        assert_eq!(content, "Actual content");
    }

    #[test]
    fn assemble_content_skips_unknown_part_types() {
        let parts = vec![
            PartInfo {
                id: Some("p1".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("step-start".into()),
                text: Some("Starting...".into()),
                state: None,
            },
            PartInfo {
                id: Some("p2".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("step-finish".into()),
                text: Some("Done".into()),
                state: None,
            },
        ];
        let content = assemble_content_from_parts(&parts);
        assert!(content.is_empty());
    }

    #[test]
    fn assemble_content_mixed_parts() {
        let parts = vec![
            PartInfo {
                id: Some("p1".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("Here's my analysis:".into()),
                state: None,
            },
            PartInfo {
                id: Some("p2".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("reasoning".into()),
                text: Some("Thinking...".into()),
                state: None,
            },
            PartInfo {
                id: Some("p3".into()),
                index: None,
                message_id: Some("m1".into()),
                part_type: Some("tool".into()),
                text: None,
                state: Some(ToolState {
                    output: Some("Result: 42".into()),
                }),
            },
        ];
        let content = assemble_content_from_parts(&parts);
        assert!(content.contains("Here's my analysis:"));
        assert!(content.contains("[Reasoning]"));
        assert!(content.contains("[Tool Output]"));
    }

    #[test]
    fn sort_parts_for_message_orders_by_index_then_id() {
        let mut parts = vec![
            PartInfo {
                id: Some("b".into()),
                index: Some(2),
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("second".into()),
                state: None,
            },
            PartInfo {
                id: Some("a".into()),
                index: Some(1),
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some("first".into()),
                state: None,
            },
        ];

        sort_parts_for_message(&mut parts);
        assert_eq!(parts[0].text.as_deref(), Some("first"));
        assert_eq!(parts[1].text.as_deref(), Some("second"));
    }

    // =====================================================
    // Helper: Create OpenCode storage structure
    // =====================================================

    fn create_opencode_storage(dir: &TempDir) -> PathBuf {
        let storage = dir.path().join("opencode").join("storage");
        fs::create_dir_all(storage.join("session")).unwrap();
        fs::create_dir_all(storage.join("message")).unwrap();
        fs::create_dir_all(storage.join("part")).unwrap();
        storage
    }

    fn write_session(storage: &Path, project_id: &str, session: &serde_json::Value) {
        let session_id = session["id"].as_str().unwrap();
        let session_dir = storage.join("session").join(project_id);
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(
            session_dir.join(format!("{session_id}.json")),
            session.to_string(),
        )
        .unwrap();
    }

    fn write_message(storage: &Path, session_id: &str, message: &serde_json::Value) {
        let message_id = message["id"].as_str().unwrap();
        let message_dir = storage.join("message").join(session_id);
        fs::create_dir_all(&message_dir).unwrap();
        fs::write(
            message_dir.join(format!("{message_id}.json")),
            message.to_string(),
        )
        .unwrap();
    }

    fn write_part(storage: &Path, message_id: &str, part: &serde_json::Value) {
        let part_id = part["id"].as_str().unwrap();
        let part_dir = storage.join("part").join(message_id);
        fs::create_dir_all(&part_dir).unwrap();
        fs::write(part_dir.join(format!("{part_id}.json")), part.to_string()).unwrap();
    }

    // =====================================================
    // scan() Tests
    // =====================================================

    #[test]
    fn scan_parses_simple_conversation() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Create session
        let session = json!({
            "id": "sess-001",
            "title": "Test Session",
            "directory": "/home/user/project",
            "projectID": "proj-001",
            "time": {
                "created": 1733000000,
                "updated": 1733000100
            }
        });
        write_session(&storage, "proj-001", &session);

        // Create message
        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-001",
            "time": {
                "created": 1733000000,
                "completed": 1733000001
            }
        });
        write_message(&storage, "sess-001", &message);

        // Create part
        let part = json!({
            "id": "part-001",
            "messageID": "msg-001",
            "type": "text",
            "text": "Hello, OpenCode!"
        });
        write_part(&storage, "msg-001", &part);

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].title, Some("Test Session".to_string()));
        assert_eq!(
            convs[0].workspace,
            Some(PathBuf::from("/home/user/project"))
        );
        assert_eq!(convs[0].messages.len(), 1);
        assert_eq!(convs[0].messages[0].role, "user");
        assert!(convs[0].messages[0].content.contains("Hello, OpenCode!"));
        crate::connectors::assert_discovery_covers_scan_sources(&connector, &ctx);
    }

    #[test]
    fn scan_with_opencode_root_scan_root() {
        use crate::connectors::scan::ScanRoot;

        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-001",
            "title": "Explicit Root",
            "directory": "/home/user/project",
            "projectID": "proj-001",
            "time": {
                "created": 1733000000,
                "updated": 1733000100
            }
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-001",
            "time": {
                "created": 1733000000,
                "completed": 1733000001
            }
        });
        write_message(&storage, "sess-001", &message);

        let part = json!({
            "id": "part-001",
            "messageID": "msg-001",
            "type": "text",
            "text": "Hello explicit root!"
        });
        write_part(&storage, "msg-001", &part);

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::with_roots(
            PathBuf::new(),
            vec![ScanRoot::local(dir.path().join("opencode"))],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-001"));
    }

    #[test]
    fn scan_parses_multiple_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-002",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        // User message
        let user_msg = json!({
            "id": "msg-u1",
            "role": "user",
            "sessionID": "sess-002",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-002", &user_msg);
        write_part(
            &storage,
            "msg-u1",
            &json!({
                "id": "p1",
                "messageID": "msg-u1",
                "type": "text",
                "text": "What is 2+2?"
            }),
        );

        // Assistant message
        let assistant_msg = json!({
            "id": "msg-a1",
            "role": "assistant",
            "sessionID": "sess-002",
            "modelID": "gpt-4",
            "time": {"created": 1733000001}
        });
        write_message(&storage, "sess-002", &assistant_msg);
        write_part(
            &storage,
            "msg-a1",
            &json!({
                "id": "p2",
                "messageID": "msg-a1",
                "type": "text",
                "text": "2 + 2 = 4"
            }),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].messages[1].author, Some("gpt-4".to_string()));
    }

    #[test]
    fn scan_handles_empty_storage() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_sessions_without_messages() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-empty",
            "title": "Empty Session",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);
        // Don't create any messages

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_extracts_title_from_first_message_if_no_session_title() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-no-title",
            "projectID": "proj-001"
            // No title field
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-no-title",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-no-title", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({
                "id": "p1",
                "messageID": "msg-001",
                "type": "text",
                "text": "This is the first line\nSecond line\nThird line"
            }),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].title, Some("This is the first line".to_string()));
    }

    #[test]
    fn scan_sets_agent_slug_to_opencode() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-slug",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-slug",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-slug", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({"id": "p1", "messageID": "msg-001", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].agent_slug, "opencode");
    }

    #[test]
    fn scan_sets_metadata_with_session_and_project_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-meta",
            "projectID": "proj-meta-001"
        });
        write_session(&storage, "proj-meta-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-meta",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-meta", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({"id": "p1", "messageID": "msg-001", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].metadata["session_id"], "sess-meta");
        assert_eq!(convs[0].metadata["project_id"], "proj-meta-001");
    }

    #[test]
    fn scan_sorts_messages_by_timestamp() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-sort",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        // Create messages out of order
        let msg_later = json!({
            "id": "msg-later",
            "role": "assistant",
            "sessionID": "sess-sort",
            "time": {"created": 1733000100}
        });
        let msg_earlier = json!({
            "id": "msg-earlier",
            "role": "user",
            "sessionID": "sess-sort",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-sort", &msg_later);
        write_message(&storage, "sess-sort", &msg_earlier);

        write_part(
            &storage,
            "msg-later",
            &json!({"id": "p1", "messageID": "msg-later", "type": "text", "text": "Later"}),
        );
        write_part(
            &storage,
            "msg-earlier",
            &json!({"id": "p2", "messageID": "msg-earlier", "type": "text", "text": "Earlier"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages.len(), 2);
        // Earlier message should be first due to sorting
        assert!(convs[0].messages[0].content.contains("Earlier"));
        assert!(convs[0].messages[1].content.contains("Later"));
    }

    #[test]
    fn scan_assigns_sequential_indices() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-idx",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        for i in 0..3 {
            let msg = json!({
                "id": format!("msg-{i}"),
                "role": "user",
                "sessionID": "sess-idx",
                "time": {"created": 1733000000 + i}
            });
            write_message(&storage, "sess-idx", &msg);
            write_part(
                &storage,
                &format!("msg-{i}"),
                &json!({
                    "id": format!("p{i}"),
                    "messageID": format!("msg-{i}"),
                    "type": "text",
                    "text": format!("Message {i}")
                }),
            );
        }

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].messages[0].idx, 0);
        assert_eq!(convs[0].messages[1].idx, 1);
        assert_eq!(convs[0].messages[2].idx, 2);
    }

    #[test]
    fn scan_handles_messages_without_parts() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-no-parts",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-no-parts",
            "role": "user",
            "sessionID": "sess-no-parts",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-no-parts", &message);
        // Don't create any parts

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Session should be skipped because message has no content
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_deduplicates_sessions_by_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Create same session in two project directories
        let session = json!({
            "id": "sess-dupe",
            "title": "Duplicate Session",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);
        write_session(&storage, "proj-002", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "sess-dupe",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-dupe", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({"id": "p1", "messageID": "msg-001", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should only have one conversation (deduplicated)
        assert_eq!(convs.len(), 1);
    }

    #[test]
    fn scan_uses_default_role_when_missing() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-no-role",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        // Message without role field
        let message = json!({
            "id": "msg-no-role",
            "sessionID": "sess-no-role",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-no-role", &message);
        write_part(
            &storage,
            "msg-no-role",
            &json!({"id": "p1", "messageID": "msg-no-role", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Default role should be "assistant"
        assert_eq!(convs[0].messages[0].role, "assistant");
    }

    #[test]
    fn scan_handles_multiple_parts_per_message() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-multi-part",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-multi",
            "role": "assistant",
            "sessionID": "sess-multi-part",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-multi-part", &message);

        // Multiple parts for one message
        write_part(
            &storage,
            "msg-multi",
            &json!({"id": "p1", "messageID": "msg-multi", "type": "text", "text": "First part"}),
        );
        write_part(
            &storage,
            "msg-multi",
            &json!({"id": "p2", "messageID": "msg-multi", "type": "reasoning", "text": "Reasoning part"}),
        );
        write_part(
            &storage,
            "msg-multi",
            &json!({"id": "p3", "messageID": "msg-multi", "type": "text", "text": "Third part"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        let content = &convs[0].messages[0].content;
        assert!(content.contains("First part"));
        assert!(content.contains("[Reasoning]"));
        assert!(content.contains("Third part"));
    }

    #[test]
    fn scan_extracts_timestamps() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-ts",
            "projectID": "proj-001",
            "time": {
                "created": 1733000000,
                "updated": 1733000200
            }
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-ts",
            "role": "user",
            "sessionID": "sess-ts",
            "time": {"created": 1733000050}
        });
        write_message(&storage, "sess-ts", &message);
        write_part(
            &storage,
            "msg-ts",
            &json!({"id": "p1", "messageID": "msg-ts", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs[0].started_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_200_000));
        assert_eq!(convs[0].messages[0].created_at, Some(1_733_000_050_000));
    }

    #[test]
    fn scan_uses_external_id_from_session_id() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "unique-session-id-123",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-001",
            "role": "user",
            "sessionID": "unique-session-id-123",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "unique-session-id-123", &message);
        write_part(
            &storage,
            "msg-001",
            &json!({"id": "p1", "messageID": "msg-001", "type": "text", "text": "Test"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(
            convs[0].external_id,
            Some("unique-session-id-123".to_string())
        );
    }

    #[test]
    fn scan_skips_invalid_session_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Create invalid session file
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("invalid.json"), "not valid json").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn scan_skips_invalid_message_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({
            "id": "sess-invalid-msg",
            "projectID": "proj-001"
        });
        write_session(&storage, "proj-001", &session);

        // Create invalid message file
        let msg_dir = storage.join("message").join("sess-invalid-msg");
        fs::create_dir_all(&msg_dir).unwrap();
        fs::write(msg_dir.join("bad.json"), "not valid json").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        // Should skip the session because no valid messages
        assert_eq!(convs.len(), 0);
    }

    // =====================================================
    // parse_session_file() Tests
    // =====================================================

    #[test]
    fn parse_session_file_parses_complete_session() {
        let dir = TempDir::new().unwrap();
        let session = json!({
            "id": "sess-parse",
            "title": "Parse Test",
            "directory": "/test/dir",
            "projectID": "proj-parse",
            "time": {
                "created": 1733000000,
                "updated": 1733000100
            }
        });
        let path = dir.path().join("session.json");
        fs::write(&path, session.to_string()).unwrap();

        let result = parse_session_file(&path).unwrap();
        assert_eq!(result.id, "sess-parse");
        assert_eq!(result.title, Some("Parse Test".to_string()));
        assert_eq!(result.directory, Some("/test/dir".to_string()));
        assert_eq!(result.project_id, Some("proj-parse".to_string()));
        assert!(result.time.is_some());
    }

    #[test]
    fn parse_session_file_handles_minimal_session() {
        let dir = TempDir::new().unwrap();
        let session = json!({"id": "minimal"});
        let path = dir.path().join("minimal.json");
        fs::write(&path, session.to_string()).unwrap();

        let result = parse_session_file(&path).unwrap();
        assert_eq!(result.id, "minimal");
        assert!(result.title.is_none());
        assert!(result.directory.is_none());
    }

    // =========================================================================
    // Edge case tests — malformed input robustness (br-2w98)
    // =========================================================================

    #[test]
    fn edge_empty_session_file_returns_no_conversations() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("sess-empty.json"), "").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_whitespace_only_session_file_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(session_dir.join("sess-ws.json"), "   \n\t  ").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_truncated_session_json_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        fs::write(
            session_dir.join("sess-trunc.json"),
            r#"{"id": "sess-trunc", "title": "Trun"#,
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_invalid_utf8_session_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(
            session_dir.join("sess-bad-utf8.json"),
            b"\xff\xfe{\"id\":\"bad\"}",
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_bom_marker_at_session_file_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();

        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(br#"{"id":"sess-bom","projectID":"proj-001"}"#);
        std::fs::write(session_dir.join("sess-bom.json"), &data).unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        // BOM may cause parse failure; connector should skip gracefully
        let convs = connector.scan(&ctx).unwrap();
        assert!(convs.len() <= 1);
    }

    #[test]
    fn edge_json_type_mismatch_in_session_file() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);
        let session_dir = storage.join("session").join("proj-001");
        fs::create_dir_all(&session_dir).unwrap();
        // id should be a string, give it a number
        fs::write(session_dir.join("sess-bad.json"), r#"{"id": 12345}"#).unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Should skip since id is not a string (serde will fail)
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_deeply_nested_part_json() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-deep", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-deep",
            "role": "user",
            "sessionID": "sess-deep",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-deep", &message);

        // Create a part with deeply nested extra data
        let mut nested = String::from(
            r#"{"id":"p-deep","messageID":"msg-deep","type":"text","text":"deep test","extra":"#,
        );
        for _ in 0..200 {
            nested.push_str(r#"{"a":"#);
        }
        nested.push_str(r#""leaf""#);
        for _ in 0..200 {
            nested.push('}');
        }
        nested.push('}');
        let part_dir = storage.join("part").join("msg-deep");
        fs::create_dir_all(&part_dir).unwrap();
        fs::write(part_dir.join("p-deep.json"), &nested).unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        // Should not stack overflow
        let result = connector.scan(&ctx);
        assert!(result.is_ok());
    }

    #[test]
    fn edge_large_part_text_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-large", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-large",
            "role": "user",
            "sessionID": "sess-large",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-large", &message);

        let large_text = "x".repeat(1_000_000);
        write_part(
            &storage,
            "msg-large",
            &json!({"id": "p-large", "messageID": "msg-large", "type": "text", "text": large_text}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        // A 1 MB part is now capped at MAX_PART_CONTENT_BYTES with a truncation
        // marker rather than retained verbatim — this bounds message content from
        // monster tool outputs / inlined files. The head is preserved for search.
        let content = &convs[0].messages[0].content;
        assert!(
            content.len() < 1_000_000,
            "oversized part must be capped, got {} bytes",
            content.len()
        );
        assert!(
            content.contains("[… truncated"),
            "capped part must carry the truncation marker"
        );
        assert!(
            content.contains(&"x".repeat(1000)),
            "head must be preserved"
        );
    }

    #[test]
    fn edge_null_bytes_in_part_content() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-null", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-null",
            "role": "user",
            "sessionID": "sess-null",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-null", &message);

        write_part(
            &storage,
            "msg-null",
            &json!({"id": "p-null", "messageID": "msg-null", "type": "text", "text": "hello\u{0000}world"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("hello"));
    }

    #[test]
    fn edge_whitespace_only_part_text_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-ws-part", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-ws",
            "role": "assistant",
            "sessionID": "sess-ws-part",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-ws-part", &message);

        // Part with only whitespace text
        write_part(
            &storage,
            "msg-ws",
            &json!({"id": "p-ws", "messageID": "msg-ws", "type": "text", "text": "   \n\t  "}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Message with only whitespace content should be skipped
        assert_eq!(convs.len(), 0);
    }

    // ---- OpenCode-specific edge cases ----

    #[test]
    fn edge_corrupted_message_file_skipped() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-corrupt", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        // Write a valid message and a corrupted one
        let valid_msg = json!({
            "id": "msg-valid",
            "role": "user",
            "sessionID": "sess-corrupt",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-corrupt", &valid_msg);
        write_part(
            &storage,
            "msg-valid",
            &json!({"id": "p1", "messageID": "msg-valid", "type": "text", "text": "Valid message"}),
        );

        // Corrupted message file
        let msg_dir = storage.join("message").join("sess-corrupt");
        fs::write(msg_dir.join("msg-corrupt.json"), "{{{{not json").unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Valid message should still be parsed; corrupted one skipped
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].messages.len(), 1);
        assert!(convs[0].messages[0].content.contains("Valid message"));
    }

    #[test]
    fn edge_missing_part_directory_handled() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-nopart", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-nopartdir",
            "role": "user",
            "sessionID": "sess-nopart",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-nopart", &message);
        // Don't create part directory at all (not even the part/msg-nopartdir/ dir)

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Message without parts should be skipped (empty content)
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_part_with_no_type_field_ignored() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-notype", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-notype",
            "role": "assistant",
            "sessionID": "sess-notype",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-notype", &message);

        // Part without "type" field (falls through to _ => {} in match)
        write_part(
            &storage,
            "msg-notype",
            &json!({"id": "p-notype", "messageID": "msg-notype", "text": "No type field"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        // Part without type is ignored, message has no content, so session skipped
        assert_eq!(convs.len(), 0);
    }

    #[test]
    fn edge_part_ordering_preserves_index_order() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        let session = json!({"id": "sess-order", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-order",
            "role": "assistant",
            "sessionID": "sess-order",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-order", &message);

        // Parts with explicit indices out of order
        write_part(
            &storage,
            "msg-order",
            &json!({"id": "p-c", "messageID": "msg-order", "type": "text", "text": "Third", "index": 3}),
        );
        write_part(
            &storage,
            "msg-order",
            &json!({"id": "p-a", "messageID": "msg-order", "type": "text", "text": "First", "index": 1}),
        );
        write_part(
            &storage,
            "msg-order",
            &json!({"id": "p-b", "messageID": "msg-order", "type": "text", "text": "Second", "index": 2}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        let content = &convs[0].messages[0].content;
        // Verify order: First before Second before Third
        let first_pos = content.find("First").unwrap();
        let second_pos = content.find("Second").unwrap();
        let third_pos = content.find("Third").unwrap();
        assert!(first_pos < second_pos);
        assert!(second_pos < third_pos);
    }

    #[test]
    fn edge_session_ended_at_uses_latest_available_message_timestamp() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Session with no explicit time metadata
        let session = json!({"id": "sess-mixed-ts", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        // Message with timestamp
        let timed_message = json!({
            "id": "msg-timed",
            "role": "user",
            "sessionID": "sess-mixed-ts",
            "time": {"created": 1733000000}
        });
        write_message(&storage, "sess-mixed-ts", &timed_message);
        write_part(
            &storage,
            "msg-timed",
            &json!({"id": "p-timed", "messageID": "msg-timed", "type": "text", "text": "Timestamped"}),
        );

        // Later message without timestamp (sorts after timestamped messages)
        let untimed_message = json!({
            "id": "msg-untimed",
            "role": "assistant",
            "sessionID": "sess-mixed-ts"
        });
        write_message(&storage, "sess-mixed-ts", &untimed_message);
        write_part(
            &storage,
            "msg-untimed",
            &json!({"id": "p-untimed", "messageID": "msg-untimed", "type": "text", "text": "No timestamp"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].started_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_000_000));
        assert_eq!(convs[0].messages.len(), 2);
    }

    #[test]
    fn edge_session_ended_at_falls_back_to_started_at_when_updated_missing() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Session has created time but no updated time
        let session = json!({
            "id": "sess-created-only",
            "projectID": "proj-001",
            "time": {"created": 1733000500}
        });
        write_session(&storage, "proj-001", &session);

        // Message has no timestamp
        let message = json!({
            "id": "msg-no-time",
            "role": "user",
            "sessionID": "sess-created-only"
        });
        write_message(&storage, "sess-created-only", &message);
        write_part(
            &storage,
            "msg-no-time",
            &json!({"id": "p-no-time", "messageID": "msg-no-time", "type": "text", "text": "Only session created time"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();

        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].started_at, Some(1_733_000_500_000));
        assert_eq!(convs[0].ended_at, Some(1_733_000_500_000));
    }

    #[test]
    fn edge_session_without_time_field() {
        let dir = TempDir::new().unwrap();
        let storage = create_opencode_storage(&dir);

        // Session with no time field at all
        let session = json!({"id": "sess-notime", "projectID": "proj-001"});
        write_session(&storage, "proj-001", &session);

        let message = json!({
            "id": "msg-notime",
            "role": "user",
            "sessionID": "sess-notime"
            // No time field
        });
        write_message(&storage, "sess-notime", &message);
        write_part(
            &storage,
            "msg-notime",
            &json!({"id": "p1", "messageID": "msg-notime", "type": "text", "text": "No timestamps"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(storage.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        // Timestamps should be None
        assert!(convs[0].started_at.is_none());
        assert!(convs[0].ended_at.is_none());
    }

    // =====================================================
    // SQLite Extraction Tests (v1.2+)
    // =====================================================

    /// Create a test SQLite database with the OpenCode v1.2+ schema.
    fn create_test_sqlite_db(dir: &Path) -> PathBuf {
        let db_path = dir.join("opencode.db");
        let conn = open_test_connection(&db_path);

        conn.execute_batch(
            "CREATE TABLE session (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                title TEXT,
                directory TEXT,
                time_created TEXT DEFAULT CURRENT_TIMESTAMP,
                time_updated TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL,
                time_created TEXT DEFAULT CURRENT_TIMESTAMP,
                time_updated TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL,
                time_created TEXT DEFAULT CURRENT_TIMESTAMP,
                time_updated TEXT DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .unwrap();

        db_path
    }

    #[test]
    fn sqlite_extract_simple_session() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        conn.execute(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params!["sess-1", "proj-1", "Test Session", "/home/user/project"],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-1",
                "sess-1",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-1",
                "msg-1",
                "sess-1",
                r#"{"type":"text","text":"Hello world"}"#,
            ],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-2",
                "sess-1",
                r#"{"role":"assistant","time":{"created":1700000001000},"modelID":"claude-3"}"#,
            ],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-2",
                "msg-2",
                "sess-1",
                r#"{"type":"text","text":"Hi there!"}"#,
            ],
        )
        .unwrap();

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-1"));
        assert_eq!(convs[0].title.as_deref(), Some("Test Session"));
        assert_eq!(convs[0].messages.len(), 2);
        assert_eq!(convs[0].messages[0].role, "user");
        assert_eq!(convs[0].messages[0].content, "Hello world");
        assert_eq!(convs[0].messages[1].role, "assistant");
        assert_eq!(convs[0].messages[1].content, "Hi there!");
        assert_eq!(convs[0].messages[1].author.as_deref(), Some("claude-3"));
    }

    #[test]
    fn sqlite_extract_empty_db() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn sqlite_extract_skips_empty_messages() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        conn.execute(
            "INSERT INTO session (id, title) VALUES (?1, ?2)",
            params!["sess-empty", "Empty Session"],
        )
        .unwrap();

        // Session with no messages should be skipped
        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert!(convs.is_empty());
    }

    #[test]
    fn sqlite_extract_with_tool_parts() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        conn.execute(
            "INSERT INTO session (id, title) VALUES (?1, ?2)",
            params!["sess-tools", "Tool Session"],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params!["msg-t1", "sess-tools", r#"{"role":"assistant"}"#],
        )
        .unwrap();

        // Text part
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "p1",
                "msg-t1",
                "sess-tools",
                r#"{"type":"text","text":"Let me check that."}"#,
            ],
        )
        .unwrap();

        // Tool part with output
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "p2",
                "msg-t1",
                "sess-tools",
                r#"{"type":"tool","state":{"output":"file.rs: 42 lines"}}"#,
            ],
        )
        .unwrap();

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert!(convs[0].messages[0].content.contains("Let me check that."));
        assert!(convs[0].messages[0].content.contains("[Tool Output]"));
        assert!(convs[0].messages[0].content.contains("file.rs: 42 lines"));
    }

    #[test]
    fn sqlite_extract_deduplicates_sessions() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        // Two sessions with different IDs
        for (sid, title) in &[("sess-a", "Session A"), ("sess-b", "Session B")] {
            conn.execute(
                "INSERT INTO session (id, title) VALUES (?1, ?2)",
                params![*sid, *title],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
                params![format!("msg-{sid}"), *sid, r#"{"role":"user"}"#],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
                params![
                    format!("p-{sid}"),
                    format!("msg-{sid}"),
                    *sid,
                    r#"{"type":"text","text":"Hello"}"#,
                ],
            )
            .unwrap();
        }

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 2);
    }

    #[test]
    fn sqlite_extract_groups_bulk_scanned_messages_by_session() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        for session_id in ["sess-a", "sess-b"] {
            conn.execute(
                "INSERT INTO session (id, title) VALUES (?1, ?2)",
                params![session_id, format!("Session {session_id}")],
            )
            .unwrap();
        }

        for (message_id, session_id, role, created_at) in [
            ("msg-a-late", "sess-a", "assistant", 30_i64),
            ("msg-b-only", "sess-b", "user", 20_i64),
            ("msg-a-early", "sess-a", "user", 10_i64),
        ] {
            conn.execute(
                "INSERT INTO message (id, session_id, data, time_created)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    message_id,
                    session_id,
                    format!(r#"{{"role":"{role}"}}"#),
                    created_at
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO part (id, message_id, session_id, data, time_created)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    format!("part-{message_id}"),
                    message_id,
                    session_id,
                    format!(r#"{{"type":"text","text":"content for {message_id}"}}"#),
                    created_at
                ],
            )
            .unwrap();
        }

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 2);

        let sess_a = convs
            .iter()
            .find(|conv| conv.external_id.as_deref() == Some("sess-a"))
            .expect("sess-a conversation");
        assert_eq!(sess_a.messages.len(), 2);
        assert_eq!(sess_a.messages[0].idx, 0);
        assert_eq!(sess_a.messages[0].content, "content for msg-a-early");
        assert_eq!(sess_a.messages[1].idx, 1);
        assert_eq!(sess_a.messages[1].content, "content for msg-a-late");

        let sess_b = convs
            .iter()
            .find(|conv| conv.external_id.as_deref() == Some("sess-b"))
            .expect("sess-b conversation");
        assert_eq!(sess_b.messages.len(), 1);
        assert_eq!(sess_b.messages[0].idx, 0);
        assert_eq!(sess_b.messages[0].content, "content for msg-b-only");
    }

    /// Test that SQLite extraction handles integer timestamps (epoch seconds)
    /// which Drizzle ORM may use instead of TEXT ISO 8601 strings.
    #[test]
    fn sqlite_extract_handles_integer_timestamps() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("opencode.db");
        let conn = open_test_connection(&db_path);

        // Create schema with INTEGER timestamp columns (Drizzle ORM integer mode)
        conn.execute_batch(
            "CREATE TABLE session (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                title TEXT,
                directory TEXT,
                time_created INTEGER,
                time_updated INTEGER
            );
            CREATE TABLE message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL,
                time_created INTEGER,
                time_updated INTEGER
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                data TEXT NOT NULL,
                time_created INTEGER,
                time_updated INTEGER
            );",
        )
        .unwrap();

        // Insert session with epoch second timestamps
        conn.execute(
            "INSERT INTO session (id, project_id, title, time_created, time_updated) VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["sess-int", "proj-1", "Integer TS Session", 1700000000_i64, 1700000100_i64],
        ).unwrap();

        conn.execute(
            "INSERT INTO message (id, session_id, data, time_created) VALUES (?1, ?2, ?3, ?4)",
            params!["msg-int", "sess-int", r#"{"role":"user"}"#, 1700000050_i64],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-int",
                "msg-int",
                "sess-int",
                r#"{"type":"text","text":"Integer timestamps!"}"#,
            ],
        )
        .unwrap();

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        // Epoch seconds should be normalized to milliseconds
        assert_eq!(convs[0].started_at, Some(1_700_000_000_000));
        assert_eq!(convs[0].ended_at, Some(1_700_000_100_000));
        assert!(convs[0].messages[0].content.contains("Integer timestamps!"));
    }

    #[test]
    fn sqlite_extract_metadata_includes_source() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);

        conn.execute(
            "INSERT INTO session (id, project_id, title) VALUES (?1, ?2, ?3)",
            params!["sess-meta", "proj-meta", "Meta Session"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params!["msg-meta", "sess-meta", r#"{"role":"user"}"#],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "p-meta",
                "msg-meta",
                "sess-meta",
                r#"{"type":"text","text":"Test"}"#,
            ],
        )
        .unwrap();

        drop(conn);

        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].metadata["source"], "sqlite");
        assert_eq!(convs[0].metadata["project_id"], "proj-meta");
    }

    // =====================================================
    // normalize_sqlite_ts_value() Tests
    // =====================================================

    #[test]
    fn normalize_sqlite_ts_value_integer_epoch_seconds() {
        let val = SqliteValue::Integer(1_700_000_000);
        assert_eq!(normalize_sqlite_ts_value(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn normalize_sqlite_ts_value_integer_epoch_millis() {
        let val = SqliteValue::Integer(1_700_000_000_000);
        // Already in ms range, should pass through
        assert_eq!(normalize_sqlite_ts_value(&val), Some(1_700_000_000_000));
    }

    #[test]
    fn normalize_sqlite_ts_value_text_sqlite_format() {
        let val = SqliteValue::Text("2024-01-15 14:30:00".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        // Should parse to 2024-01-15T14:30:00 UTC epoch millis
        assert_eq!(result, 1_705_329_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_iso8601_t_separator() {
        let val = SqliteValue::Text("2024-01-15T14:30:00".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_fractional_seconds() {
        let val = SqliteValue::Text("2024-01-15 14:30:00.123".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_123);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_t_fractional() {
        let val = SqliteValue::Text("2024-01-15T14:30:00.456".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_456);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_rfc3339_z() {
        let val = SqliteValue::Text("2024-01-15T14:30:00Z".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_rfc3339_offset() {
        let val = SqliteValue::Text("2024-01-15T14:30:00+00:00".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_705_329_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_text_integer_string() {
        let val = SqliteValue::Text("1700000000".into());
        let result = normalize_sqlite_ts_value(&val).unwrap();
        assert_eq!(result, 1_700_000_000_000);
    }

    #[test]
    fn normalize_sqlite_ts_value_null() {
        let val = SqliteValue::Null;
        assert_eq!(normalize_sqlite_ts_value(&val), None);
    }

    #[test]
    fn normalize_sqlite_ts_value_unparseable_text() {
        let val = SqliteValue::Text("not a date".into());
        assert_eq!(normalize_sqlite_ts_value(&val), None);
    }

    #[test]
    fn normalize_sqlite_ts_value_empty_text() {
        let val = SqliteValue::Text("".into());
        assert_eq!(normalize_sqlite_ts_value(&val), None);
    }

    #[test]
    fn normalize_sqlite_ts_value_real() {
        let val = SqliteValue::Real(1_700_000_000.5);
        assert_eq!(normalize_sqlite_ts_value(&val), Some(1_700_000_000_000));
    }

    // =====================================================
    // Regression: issue #174 — SQLite DB discovery
    // =====================================================

    /// Regression for issue #174: the candidate list must put XDG paths
    /// reachable from `$HOME` ahead of `dirs::data_local_dir()` so macOS
    /// users (where `data_local_dir()` resolves to `~/Library/Application
    /// Support`) still have their canonical `~/.local/share/opencode/
    /// opencode.db` found. The explicit override must always win.
    #[test]
    fn sqlite_db_candidates_from_orders_home_xdg_before_platform_dirs() {
        let home = PathBuf::from("/home/testuser");
        let xdg_data = PathBuf::from("/var/lib/xdg");
        let xdg_config = PathBuf::from("/etc/xdg");

        // No override → home-XDG paths must come first.
        let list = OpenCodeConnector::sqlite_db_candidates_from(
            None,
            Some(&home),
            Some(&xdg_data),
            Some(&xdg_config),
        );
        assert_eq!(list.len(), 4);
        assert_eq!(list[0], home.join(".local/share/opencode/opencode.db"));
        assert_eq!(list[1], home.join(".config/opencode/opencode.db"));
        assert_eq!(list[2], xdg_data.join("opencode/opencode.db"));
        assert_eq!(list[3], xdg_config.join("opencode/opencode.db"));

        // Explicit override always wins.
        let override_path = PathBuf::from("/custom/opencode.db");
        let list = OpenCodeConnector::sqlite_db_candidates_from(
            Some(override_path.clone()),
            Some(&home),
            Some(&xdg_data),
            Some(&xdg_config),
        );
        assert_eq!(list[0], override_path);
        assert_eq!(list.len(), 5);
    }

    /// Regression for issue #174: when two dirs helpers resolve to the
    /// same path (common on macOS where config_dir == data_local_dir),
    /// the candidate list must deduplicate while preserving priority.
    #[test]
    fn sqlite_db_candidates_from_deduplicates_overlapping_roots() {
        let home = PathBuf::from("/Users/testuser");
        // On macOS, both of these map to ~/Library/Application Support.
        let overlap = PathBuf::from("/Users/testuser/Library/Application Support");
        let list = OpenCodeConnector::sqlite_db_candidates_from(
            None,
            Some(&home),
            Some(&overlap),
            Some(&overlap),
        );
        // 2 home-XDG paths + 1 overlap path (deduplicated) = 3.
        assert_eq!(list.len(), 3, "list = {list:?}");
        assert_eq!(list[0], home.join(".local/share/opencode/opencode.db"));
        assert_eq!(list[1], home.join(".config/opencode/opencode.db"));
        assert_eq!(list[2], overlap.join("opencode/opencode.db"));
    }

    /// Regression for issue #174: when the caller passes an explicit
    /// directory that contains `opencode.db`, the scanner must discover
    /// it. This is the ctx.data_dir-as-parent path.
    #[test]
    fn scan_finds_sqlite_db_when_data_dir_is_db_parent() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        conn.execute(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-parent",
                "proj-p",
                "Parent Session",
                "/home/user/parent",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-parent",
                "sess-parent",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-parent",
                "msg-parent",
                "sess-parent",
                r#"{"type":"text","text":"Parent content"}"#,
            ],
        )
        .unwrap();

        // Pass the parent directory (not the .db file itself).
        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-parent"));
    }

    /// Regression for issue #174: when the caller passes an explicit
    /// scan root (use_default_detection() == false) that does NOT
    /// contain opencode.db, the scanner must still find a DB via the
    /// ctx.data_dir-as-parent candidate if one is present.
    #[test]
    fn scan_finds_sqlite_db_via_data_dir_even_with_explicit_scan_roots() {
        use crate::connectors::scan::ScanRoot;

        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        conn.execute(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-roots",
                "proj-roots",
                "Roots Session",
                "/home/user/roots",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-roots",
                "sess-roots",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-roots",
                "msg-roots",
                "sess-roots",
                r#"{"type":"text","text":"Roots content"}"#,
            ],
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![ScanRoot::local(dir.path().to_path_buf())],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(
            convs.len(),
            1,
            "explicit scan_roots must still check ctx.data_dir for opencode.db"
        );
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-roots"));
    }

    #[test]
    fn scan_finds_sqlite_db_with_explicit_config_root() {
        use crate::connectors::scan::ScanRoot;

        let dir = TempDir::new().unwrap();
        let config_root = dir.path().join(".config");
        let opencode_dir = config_root.join("opencode");
        std::fs::create_dir_all(&opencode_dir).unwrap();

        let db_path = create_test_sqlite_db(&opencode_dir);
        let conn = open_test_connection(&db_path);
        conn.execute(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-config",
                "proj-config",
                "Config Session",
                "/home/user/config",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-config",
                "sess-config",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-config",
                "msg-config",
                "sess-config",
                r#"{"type":"text","text":"Config content"}"#,
            ],
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::with_roots(
            dir.path().to_path_buf(),
            vec![ScanRoot::local(config_root)],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-config"));
    }

    /// Regression: when `ctx.data_dir` points directly at an
    /// `opencode.db` FILE (not the parent directory), the scanner must
    /// use it as-is — without trying to join `opencode.db` onto it
    /// again (which would produce a nonsense candidate like
    /// `/path/to/opencode.db/opencode.db`).
    #[test]
    fn scan_accepts_data_dir_as_direct_db_file() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        conn.execute(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params![
                "sess-direct",
                "proj-direct",
                "Direct Session",
                "/home/user/direct",
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-direct",
                "sess-direct",
                r#"{"role":"user","time":{"created":1700000000000}}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-direct",
                "msg-direct",
                "sess-direct",
                r#"{"type":"text","text":"Direct content"}"#,
            ],
        )
        .unwrap();

        let connector = OpenCodeConnector::new();
        // Pass the db file itself as data_dir.
        let ctx = ScanContext::local_default(db_path.clone(), None);
        let convs = connector.scan(&ctx).unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].external_id.as_deref(), Some("sess-direct"));
    }

    /// Regression: a nonexistent `.db` path passed as `ctx.data_dir`
    /// must not be silently treated as a directory (which would have
    /// produced a bogus `/path/to/missing.db/opencode.db` candidate in
    /// an earlier draft). The scanner simply finds nothing.
    #[test]
    fn scan_handles_nonexistent_db_path_in_data_dir() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing.db");
        // No file on disk at `missing`.

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::with_roots(
            missing,
            vec![crate::connectors::scan::ScanRoot::local(
                dir.path().to_path_buf(),
            )],
            None,
        );
        let convs = connector.scan(&ctx).unwrap();
        assert!(
            convs.is_empty(),
            "nonexistent .db path should not produce sessions"
        );
    }

    #[test]
    fn assemble_caps_oversized_single_part() {
        let big = "x".repeat(MAX_PART_CONTENT_BYTES + 50_000);
        let parts = vec![PartInfo {
            id: Some("p1".into()),
            index: None,
            message_id: Some("m1".into()),
            part_type: Some("tool".into()),
            text: None,
            state: Some(ToolState {
                output: Some(big.clone()),
            }),
        }];
        let content = assemble_content_from_parts(&parts);
        assert!(
            content.len() < big.len(),
            "oversized tool output must be truncated"
        );
        assert!(content.contains("[Tool Output]"));
        assert!(
            content.contains("[… truncated"),
            "a truncated part must carry the byte-count marker"
        );
        assert!(
            content.contains(&"x".repeat(1000)),
            "the head of the output must be preserved"
        );
    }

    #[test]
    fn assemble_caps_total_message_content() {
        // Ten ~200 KB text parts sum to ~2 MB, exceeding the 1 MB per-message cap.
        let chunk = "y".repeat(200 * 1024);
        let parts: Vec<PartInfo> = (0..10)
            .map(|i| PartInfo {
                id: Some(format!("p{i}")),
                index: Some(i),
                message_id: Some("m1".into()),
                part_type: Some("text".into()),
                text: Some(chunk.clone()),
                state: None,
            })
            .collect();
        let content = assemble_content_from_parts(&parts);
        assert!(
            content.contains("[… message content truncated]"),
            "an assembled message exceeding the cap must be marked truncated"
        );
        assert!(
            content.len() <= MAX_MESSAGE_CONTENT_BYTES + MAX_PART_CONTENT_BYTES + 1024,
            "assembled content must stay bounded, got {}",
            content.len()
        );
    }

    #[test]
    fn assemble_no_stray_marker_when_only_noop_parts_follow_cap() {
        // Four 256 KiB text parts cross the 1 MiB per-message cap; a trailing
        // control part (step-finish) contributes nothing. The marker must NOT
        // appear — no real content was dropped after the last real part.
        let chunk = "z".repeat(MAX_PART_CONTENT_BYTES);
        let mut parts: Vec<PartInfo> = (0..4)
            .map(|i| PartInfo {
                id: Some(format!("p{i}")),
                index: Some(i),
                message_id: None,
                part_type: Some("text".into()),
                text: Some(chunk.clone()),
                state: None,
            })
            .collect();
        parts.push(PartInfo {
            id: Some("pf".into()),
            index: Some(99),
            message_id: None,
            part_type: Some("step-finish".into()),
            text: None,
            state: None,
        });
        let content = assemble_content_from_parts(&parts);
        assert!(
            !content.contains("message content truncated"),
            "a trailing no-op part must not produce a stray truncation marker"
        );

        // Sanity: a trailing REAL part that IS dropped does produce the marker.
        let mut with_real = parts;
        with_real.pop(); // remove the step-finish
        with_real.push(PartInfo {
            id: Some("p5".into()),
            index: Some(5),
            message_id: None,
            part_type: Some("text".into()),
            text: Some(chunk.clone()),
            state: None,
        });
        assert!(
            assemble_content_from_parts(&with_real).contains("message content truncated"),
            "a real part dropped past the cap must produce the truncation marker"
        );
    }

    #[test]
    fn supports_streaming_scan_is_true() {
        assert!(OpenCodeConnector::new().supports_streaming_scan());
    }

    #[test]
    fn stream_from_sqlite_emits_each_session_once() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        for s in ["sess-a", "sess-b"] {
            conn.execute(
                "INSERT INTO session (id, title) VALUES (?1, ?2)",
                params![s, format!("Session {s}")],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
                params![
                    format!("msg-{s}"),
                    s,
                    r#"{"role":"user","time":{"created":1700000000000}}"#
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
                params![
                    format!("part-{s}"),
                    format!("msg-{s}"),
                    s,
                    r#"{"type":"text","text":"hello"}"#
                ],
            )
            .unwrap();
        }

        // Drive the streaming core directly on this fixture DB. This bypasses
        // scan()'s candidate expansion, so a real opencode.db on the host can't
        // leak extra sessions into the assertion.
        let mut seen = std::collections::HashSet::new();
        let mut streamed: Vec<String> = Vec::new();
        OpenCodeConnector::stream_from_sqlite(&db_path, None, &mut seen, &mut |c| {
            if let Some(id) = c.external_id {
                streamed.push(id);
            }
            Ok(())
        })
        .unwrap();
        streamed.sort();
        assert_eq!(
            streamed,
            vec!["sess-a".to_string(), "sess-b".to_string()],
            "streaming must emit each session exactly once"
        );

        // The collector wrapper returns the same set of sessions.
        let collected: std::collections::HashSet<String> =
            OpenCodeConnector::extract_from_sqlite(&db_path, None)
                .unwrap()
                .into_iter()
                .filter_map(|c| c.external_id)
                .collect();
        assert_eq!(
            collected,
            streamed
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            "extract_from_sqlite must collect the same sessions stream_from_sqlite emits"
        );
    }

    #[test]
    fn scan_warns_and_returns_empty_when_only_session_message_populated() {
        let dir = TempDir::new().unwrap();
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        // A session exists, but content lives only in the newer `session_message`
        // table this connector does not read; `message`/`part` are empty.
        conn.execute(
            "INSERT INTO session (id, title) VALUES (?1, ?2)",
            params!["sess-1", "Drifted"],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TABLE session_message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                type TEXT NOT NULL,
                data TEXT NOT NULL,
                seq INTEGER NOT NULL
            );
            INSERT INTO session_message (id, session_id, type, data, seq)
                VALUES ('sm-1', 'sess-1', 'text', '{\"text\":\"hi\"}', 0);",
        )
        .unwrap();

        // Must not panic; returns empty because the readable tables are empty.
        let convs = OpenCodeConnector::extract_from_sqlite(&db_path, None).unwrap();
        assert!(
            convs.is_empty(),
            "no readable message/part rows -> zero conversations (drift guard warns)"
        );
    }

    /// Once `opencode.db` exists it is authoritative: opencode's v1.2 migration
    /// imports the pre-v1.2 file storage into the DB and stops writing the
    /// files. So when both are present in the same root, the connector must
    /// ignore the legacy tree — both for raw-mirror source discovery (otherwise
    /// it captures the migrated install's 100k+ per-part files one-by-one and
    /// stalls the indexer) and for scanning (otherwise it re-reads them only to
    /// dedup them away).
    #[test]
    fn db_present_supersedes_legacy_file_storage() {
        let dir = TempDir::new().unwrap();

        // (1) A populated SQLite DB at <dir>/opencode.db.
        let db_path = create_test_sqlite_db(dir.path());
        let conn = open_test_connection(&db_path);
        conn.execute(
            "INSERT INTO session (id, project_id, title, directory) VALUES (?1, ?2, ?3, ?4)",
            params!["sess-db", "proj-db", "DB Session", "/home/user/db"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, data) VALUES (?1, ?2, ?3)",
            params![
                "msg-db",
                "sess-db",
                r#"{"role":"user","time":{"created":1700000000000}}"#
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, data) VALUES (?1, ?2, ?3, ?4)",
            params![
                "part-db",
                "msg-db",
                "sess-db",
                r#"{"type":"text","text":"From DB"}"#
            ],
        )
        .unwrap();
        drop(conn);

        // (2) Legacy file storage in the SAME root, holding a session that only
        //     exists on disk (un-pruned pre-migration leftover).
        write_session(
            dir.path(),
            "proj-legacy",
            &json!({"id": "sess-legacy", "title": "Legacy", "projectID": "proj-legacy"}),
        );
        write_message(
            dir.path(),
            "sess-legacy",
            &json!({"id": "msg-legacy", "role": "user", "sessionID": "sess-legacy", "time": {"created": 1700000000}}),
        );
        write_part(
            dir.path(),
            "msg-legacy",
            &json!({"id": "p-legacy", "messageID": "msg-legacy", "type": "text", "text": "From legacy file"}),
        );

        let connector = OpenCodeConnector::new();
        let ctx = ScanContext::local_default(dir.path().to_path_buf(), None);

        // Raw-mirror source discovery: only the DB, never the legacy files.
        let sources = connector.discover_source_files(&ctx).unwrap();
        assert!(
            sources
                .iter()
                .any(|s| s.role == DiscoveredSourceRole::SqliteDatabase),
            "the SQLite database must still be discovered"
        );
        assert!(
            !sources.iter().any(|s| matches!(
                s.role,
                DiscoveredSourceRole::PrimarySessionLog | DiscoveredSourceRole::MetadataSidecar
            )),
            "legacy file sources must not be discovered when opencode.db is present: {:?}",
            sources.iter().map(|s| s.role).collect::<Vec<_>>()
        );

        // Scan: the DB is authoritative, so the legacy-only session is not
        // re-indexed from files.
        let convs = connector.scan(&ctx).unwrap();
        let ids: Vec<&str> = convs.iter().filter_map(|c| c.external_id.as_deref()).collect();
        assert_eq!(ids, vec!["sess-db"], "only the DB session should be scanned");
    }
}
