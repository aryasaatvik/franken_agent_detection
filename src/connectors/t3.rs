//! Read T3 Code's current SQLite projections without starting its server.
//!
//! Enable the `t3` feature. Discovery checks `T3CODE_HOME`, `~/.t3/userdata`,
//! and `~/.t3/dev`; explicit scan roots accept T3 homes or database files.
//! `source_path` is a virtual `<database>/<encoded-thread-id>` reference.
//! `load_thread` resolves it without scanning unrelated conversations.
//! Current snapshots include archived threads, persisted tool activity and fork
//! prefixes. Output bodies are capped at 1 MiB with explicit truncation metadata.
//! Database, WAL and shared-memory files are declared separately for consumers;
//! these raw artifacts are not advertised as a consistent backup bundle.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Value, json};

use super::{Connector, DiscoveredSourceFile, DiscoveredSourceRole, ScanContext, ScanRoot};
use crate::types::{
    DetectionResult, LineageRelation, NormalizedConversation, NormalizedInvocation,
    NormalizedMessage,
};

const MAX_ITEM_BYTES: usize = 1024 * 1024;
const MAX_FORK_DEPTH: usize = 128;

#[derive(Default)]
pub struct T3Connector;

impl T3Connector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn default_roots() -> Vec<ScanRoot> {
        let configured = dotenvy::var("T3CODE_HOME")
            .ok()
            .filter(|path| !path.trim().is_empty());
        let mut roots = Vec::new();
        if let Some(path) = configured {
            roots.push(ScanRoot::local(crate::expand_leading_tilde(
                &path,
                dirs::home_dir().as_deref(),
            )));
        }
        if let Some(home) = dirs::home_dir() {
            roots.push(ScanRoot::local(home.join(".t3")));
        }
        roots
    }

    fn databases(ctx: &ScanContext) -> Vec<ScanRoot> {
        let mut roots = ctx.scan_roots.clone();
        roots.push(ScanRoot::local(ctx.data_dir.clone()));
        if ctx.use_default_detection() {
            roots.extend(Self::default_roots());
        }
        let mut seen = HashSet::new();
        let mut databases = Vec::new();
        for root in roots {
            let candidates = if root.path.is_file() {
                // Explicit file roots are still schema-validated before parsing.
                vec![root.path.clone()]
            } else {
                vec![
                    root.path.join("statev2.sqlite"),
                    root.path.join("userdata/statev2.sqlite"),
                    root.path.join("dev/statev2.sqlite"),
                ]
            };
            for candidate in candidates {
                if !candidate.is_file() {
                    continue;
                }
                let canonical = candidate.canonicalize().unwrap_or(candidate);
                if canonical
                    .file_name()
                    .is_none_or(|name| name != "statev2.sqlite")
                    && !Connection::open_with_flags(&canonical, OpenFlags::SQLITE_OPEN_READ_ONLY)
                        .and_then(|connection| connection.query_row(
                            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='orchestration_v2_projection_threads')", [], |row| row.get::<_, bool>(0)
                        )).unwrap_or(false)
                {
                    continue;
                }
                if seen.insert(canonical.clone()) {
                    databases.push(root.with_path(canonical));
                }
            }
        }
        databases
    }

    /// Load one thread by the exact reference emitted in `source_path`.
    ///
    /// This does not scan other threads; fork ancestors are read only when needed.
    pub fn load_thread(db_path: &Path, thread_id: &str) -> Result<NormalizedConversation> {
        let canonical = db_path
            .canonicalize()
            .with_context(|| format!("resolve T3 database {}", db_path.display()))?;
        let mut connection = open_database(&canonical)?;
        let transaction = connection.transaction()?;
        let projection = Projection::read(&transaction, thread_id)?;
        let visible = visible_items(&transaction, &projection, &mut HashSet::new())?;
        conversation(
            &transaction,
            &ScanRoot::local(canonical),
            &projection,
            visible,
        )
    }
}

impl Connector for T3Connector {
    fn detect(&self) -> DetectionResult {
        let ctx = ScanContext::local_default(PathBuf::new(), None);
        let roots: Vec<_> = Self::databases(&ctx)
            .into_iter()
            .filter_map(|root| root.path.parent().map(Path::to_path_buf))
            .collect();
        DetectionResult {
            detected: !roots.is_empty(),
            evidence: roots
                .iter()
                .map(|path| format!("T3 SQLite at {}", path.display()))
                .collect(),
            root_paths: roots,
        }
    }

    fn supports_streaming_scan(&self) -> bool {
        true
    }

    fn scan(&self, ctx: &ScanContext) -> Result<Vec<NormalizedConversation>> {
        let mut conversations = Vec::new();
        self.scan_with_callback(ctx, &mut |conversation| {
            conversations.push(conversation);
            Ok(())
        })?;
        Ok(conversations)
    }

    fn discover_source_files(&self, ctx: &ScanContext) -> Result<Vec<DiscoveredSourceFile>> {
        let mut files = Vec::new();
        for root in Self::databases(ctx) {
            let parent = root.with_path(
                root.path
                    .parent()
                    .context("T3 database has no parent")?
                    .to_path_buf(),
            );
            files.push(
                DiscoveredSourceFile::new(
                    "t3",
                    &parent,
                    root.path.clone(),
                    DiscoveredSourceRole::SqliteDatabase,
                    true,
                )
                .with_fs_metadata(),
            );
            for suffix in ["-wal", "-shm"] {
                let sidecar = PathBuf::from(format!("{}{suffix}", root.path.display()));
                if sidecar.is_file() {
                    files.push(
                        DiscoveredSourceFile::new(
                            "t3",
                            &parent,
                            sidecar,
                            DiscoveredSourceRole::MetadataSidecar,
                            suffix == "-wal",
                        )
                        .with_fs_metadata(),
                    );
                }
            }
        }
        Ok(files)
    }

    fn scan_with_callback(
        &self,
        ctx: &ScanContext,
        emit: &mut dyn FnMut(NormalizedConversation) -> Result<()>,
    ) -> Result<()> {
        for root in Self::databases(ctx) {
            let mut connection = open_database(&root.path)?;
            let ids = {
                let transaction = connection.transaction()?;
                let mut statement = transaction.prepare(
                "SELECT thread_id FROM orchestration_v2_projection_threads AS thread
                 WHERE deleted_at IS NULL AND (
                   ?1 IS NULL OR unixepoch(updated_at, 'subsec') * 1000 >= ?1
                   OR json_extract(payload_json, '$.forkedFrom') IS NOT NULL
                   OR EXISTS (SELECT 1 FROM orchestration_v2_projection_turn_items AS item
                     WHERE item.thread_id=thread.thread_id AND unixepoch(item.updated_at, 'subsec') * 1000 >= ?1)
                   OR EXISTS (SELECT 1 FROM orchestration_v2_projection_messages AS message
                     WHERE message.thread_id=thread.thread_id AND unixepoch(message.updated_at, 'subsec') * 1000 >= ?1)
                   OR EXISTS (SELECT 1 FROM orchestration_v2_projection_provider_threads AS provider
                     WHERE provider.thread_id=thread.thread_id AND unixepoch(provider.updated_at, 'subsec') * 1000 >= ?1)
                 ) ORDER BY thread_id"
            )?;
                statement
                    .query_map([ctx.since_ts], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            for id in ids {
                if let Some(tick) = &ctx.progress_tick {
                    tick();
                }
                let snapshot = {
                    let transaction = connection.transaction()?;
                    let projection = Projection::read(&transaction, &id)?;
                    let visible = visible_items(&transaction, &projection, &mut HashSet::new())?;
                    conversation(&transaction, &root, &projection, visible)?
                };
                // Consumer backpressure must not pin the live application's WAL.
                emit(snapshot)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "Keep the live SQLite fixtures beside the Connector boundary tests"
)]
mod tests {
    use super::*;

    const AT: &str = "2026-10-27T10:00:00.000Z";

    fn fixture() -> (tempfile::TempDir, Connection, PathBuf) {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("statev2.sqlite");
        let writer = Connection::open(&path).expect("writer");
        writer.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE projection_projects(project_id TEXT PRIMARY KEY, workspace_root TEXT);
             INSERT INTO projection_projects VALUES ('project','/test/workspace');
             CREATE TABLE orchestration_v2_projection_threads(thread_id TEXT PRIMARY KEY, updated_at TEXT, deleted_at TEXT, payload_json TEXT);
             CREATE TABLE orchestration_v2_projection_turn_items(turn_item_id TEXT PRIMARY KEY, thread_id TEXT, ordinal INTEGER, updated_at TEXT, payload_json TEXT);
             CREATE TABLE orchestration_v2_projection_messages(message_id TEXT PRIMARY KEY, thread_id TEXT, created_at TEXT, updated_at TEXT, payload_json TEXT);
             CREATE TABLE orchestration_v2_projection_runs(run_id TEXT PRIMARY KEY, thread_id TEXT, ordinal INTEGER, payload_json TEXT);
             CREATE TABLE orchestration_v2_projection_run_attempts(attempt_id TEXT PRIMARY KEY, thread_id TEXT, payload_json TEXT);
             CREATE TABLE orchestration_v2_projection_provider_threads(provider_thread_id TEXT PRIMARY KEY, thread_id TEXT, updated_at TEXT, payload_json TEXT);"
        ).expect("schema");
        (directory, writer, path)
    }

    fn thread(writer: &Connection, id: &str, fork: Value, archived: bool) {
        let mut payload = json!({"id":id,"title":format!("Thread {id}"),"projectId":"project","createdAt":AT,"updatedAt":AT,"worktreePath":null,"archivedAt":if archived {Some(AT)} else {None},"lineage":{"parentThreadId":null,"relationshipToParent":null}});
        payload["forkedFrom"] = fork;
        writer
            .execute(
                "INSERT INTO orchestration_v2_projection_threads VALUES (?1,?2,NULL,?3)",
                rusqlite::params![id, AT, payload.to_string()],
            )
            .expect("thread");
    }

    fn item(
        writer: &Connection,
        owner: &str,
        id: &str,
        ordinal: u32,
        kind: &str,
        body: &str,
        run: Option<&str>,
    ) {
        let payload = json!({"id":id,"threadId":owner,"type":kind,"ordinal":ordinal,"text":body,"message":body,"input":body,"output":"resultword","status":"completed","runId":run,"updatedAt":AT,"startedAt":AT});
        writer
            .execute(
                "INSERT INTO orchestration_v2_projection_turn_items VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![id, owner, ordinal, AT, payload.to_string()],
            )
            .expect("item");
    }

    fn run(writer: &Connection, owner: &str, id: &str, ordinal: u32, status: &str) {
        let payload = json!({"id":id,"status":status,"ordinal":ordinal});
        writer
            .execute(
                "INSERT INTO orchestration_v2_projection_runs VALUES (?1,?2,?3,?4)",
                rusqlite::params![id, owner, ordinal, payload.to_string()],
            )
            .expect("run");
    }

    fn context(path: &Path, since: Option<i64>) -> ScanContext {
        ScanContext::with_roots(
            path.to_path_buf(),
            vec![ScanRoot::local(path.to_path_buf())],
            since,
        )
    }

    #[test]
    fn t3_reads_active_archived_and_settled_timeline_from_live_wal() {
        let (_directory, writer, path) = fixture();
        for (id, archived) in [("active", false), ("archived", true), ("settled", false)] {
            thread(&writer, id, Value::Null, archived);
            item(
                &writer,
                id,
                &format!("{id}-user"),
                0,
                "user_message",
                "questionword",
                None,
            );
            item(
                &writer,
                id,
                &format!("{id}-tool"),
                1,
                "command_execution",
                "commandword",
                None,
            );
        }
        let original_db = std::fs::read(&path).expect("db bytes");
        let connector = T3Connector::new();
        let conversations = connector.scan(&context(&path, None)).expect("scan");
        assert_eq!(conversations.len(), 3);
        for conversation in &conversations {
            assert_eq!(conversation.agent_slug, "t3");
            assert_eq!(conversation.messages.len(), 2);
            assert_eq!(conversation.messages[0].role, "user");
            assert!(conversation.messages[1].content.contains("resultword"));
            assert_eq!(conversation.messages[1].invocations[0].name, "bash");
            assert_eq!(
                conversation.workspace.as_deref(),
                Some(Path::new("/test/workspace"))
            );
        }
        assert_eq!(std::fs::read(&path).expect("db after"), original_db);
        let sources = connector
            .discover_source_files(&context(&path, None))
            .expect("discovery");
        assert!(sources.iter().any(
            |source| source.source_path.to_string_lossy().ends_with("-wal")
                && source.required_for_reconstruction
        ));
        let loaded = T3Connector::load_thread(&path, "active").expect("single-thread read");
        assert_eq!(loaded.messages.len(), 2);
    }

    #[test]
    fn t3_deduplicates_chat_and_reads_current_message_projection() {
        let (_directory, writer, path) = fixture();
        thread(&writer, "thread", Value::Null, false);
        let message = json!({"id":"message","threadId":"thread","text":"currentword","role":"assistant","createdAt":AT,"updatedAt":AT,"streaming":false});
        writer.execute("INSERT INTO orchestration_v2_projection_messages VALUES ('message','thread',?1,?1,?2)",rusqlite::params![AT,message.to_string()]).expect("message");
        let item = json!({"id":"item","threadId":"thread","messageId":"message","type":"assistant_message","text":"partialword","updatedAt":AT});
        writer.execute("INSERT INTO orchestration_v2_projection_turn_items VALUES ('item','thread',0,?1,?2)",rusqlite::params![AT,item.to_string()]).expect("item");
        let loaded = T3Connector::load_thread(&path, "thread").expect("load");
        assert_eq!(loaded.messages.len(), 1);
        assert_eq!(loaded.messages[0].content, "currentword");
        let same_timestamp = timestamp(&json!({"updatedAt":AT}), "updatedAt").expect("timestamp");
        assert_eq!(
            T3Connector::new()
                .scan(&context(&path, same_timestamp))
                .expect("boundary scan")
                .len(),
            1
        );
    }

    #[test]
    fn t3_message_only_notices_keep_their_chronological_position() {
        let (_directory, writer, path) = fixture();
        thread(&writer, "thread", Value::Null, false);
        item(
            &writer,
            "thread",
            "first",
            0,
            "user_message",
            "firstword",
            None,
        );
        item(
            &writer,
            "thread",
            "last",
            1,
            "assistant_message",
            "lastword",
            None,
        );
        writer.execute("UPDATE orchestration_v2_projection_turn_items SET payload_json=json_set(payload_json,'$.startedAt','2026-10-27T10:00:02.000Z') WHERE turn_item_id='last'",[]).expect("later turn");
        let notice = json!({"id":"notice","threadId":"thread","role":"system","text":"middleword","createdAt":"2026-10-27T10:00:01.000Z","updatedAt":AT});
        writer.execute("INSERT INTO orchestration_v2_projection_messages VALUES('notice','thread',?1,?1,?2)",rusqlite::params![AT,notice.to_string()]).expect("notice");
        let loaded = T3Connector::load_thread(&path, "thread").expect("ordered notices");
        assert_eq!(
            loaded
                .messages
                .iter()
                .map(|message| message.content.as_str())
                .collect::<Vec<_>>(),
            vec!["firstword", "middleword", "lastword"]
        );
    }

    #[test]
    fn t3_fork_prefix_stops_at_source_run_and_filters_local_rollbacks() {
        let (_directory, writer, path) = fixture();
        thread(&writer, "parent", Value::Null, false);
        run(&writer, "parent", "before", 1, "completed");
        run(&writer, "parent", "after", 2, "completed");
        item(
            &writer,
            "parent",
            "included",
            0,
            "user_message",
            "prefixword",
            Some("before"),
        );
        item(
            &writer,
            "parent",
            "excluded",
            1,
            "assistant_message",
            "futureword",
            Some("after"),
        );
        thread(
            &writer,
            "child",
            json!({"type":"run","threadId":"parent","runId":"before"}),
            false,
        );
        run(&writer, "child", "rolledback", 1, "rolled_back");
        item(
            &writer,
            "child",
            "hidden",
            0,
            "assistant_message",
            "hiddenword",
            Some("rolledback"),
        );
        item(
            &writer,
            "child",
            "local",
            1,
            "assistant_message",
            "localword",
            None,
        );
        let loaded = T3Connector::load_thread(&path, "child").expect("fork");
        let contents: Vec<_> = loaded
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect();
        assert!(contents.contains(&"prefixword"));
        assert!(contents.contains(&"localword"));
        assert!(!contents.contains(&"futureword"));
        assert!(!contents.contains(&"hiddenword"));
        assert_eq!(loaded.lineage_relation, Some(LineageRelation::Fork));
        writer.execute("UPDATE orchestration_v2_projection_turn_items SET payload_json=json_set(payload_json,'$.messageId','parent-message') WHERE turn_item_id='included'",[]).expect("reference parent message");
        let current = json!({"id":"parent-message","threadId":"parent","role":"user","text":"completedprefix","createdAt":AT,"updatedAt":AT});
        writer.execute("INSERT INTO orchestration_v2_projection_messages VALUES('parent-message','parent',?1,?1,?2)",rusqlite::params![AT,current.to_string()]).expect("parent message");
        let loaded = T3Connector::load_thread(&path, "child").expect("completed fork");
        assert!(
            loaded
                .messages
                .iter()
                .any(|message| message.content == "completedprefix")
        );
        assert!(
            !loaded
                .messages
                .iter()
                .any(|message| message.content == "prefixword")
        );
    }

    #[test]
    fn t3_rejects_cycles_bad_json_and_unknown_item_types() {
        let (_directory, writer, path) = fixture();
        thread(
            &writer,
            "thread",
            json!({"type":"run","threadId":"thread","runId":"run"}),
            false,
        );
        run(&writer, "thread", "run", 1, "completed");
        assert!(
            T3Connector::load_thread(&path, "thread")
                .expect_err("cycle")
                .to_string()
                .contains("cyclic")
        );
        writer
            .execute(
                "UPDATE orchestration_v2_projection_threads SET payload_json='{broken'",
                [],
            )
            .expect("corrupt");
        assert!(T3Connector::load_thread(&path, "thread").is_err());
        assert!(item_content(&json!({"type":"future_unknown_variant"})).is_err());
    }

    #[test]
    fn t3_empty_and_deleted_sources_emit_nothing_and_callback_errors_propagate() {
        let (_directory, writer, path) = fixture();
        let connector = T3Connector::new();
        assert!(
            connector
                .scan(&context(&path, None))
                .expect("empty")
                .is_empty()
        );
        thread(&writer, "thread", Value::Null, false);
        item(&writer, "thread", "item", 0, "user_message", "word", None);
        connector
            .scan_with_callback(&context(&path, None), &mut |_| {
                let busy: i64 =
                    writer.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))?;
                assert_eq!(
                    busy, 0,
                    "consumer callback must run after the source read transaction ends"
                );
                Ok(())
            })
            .expect("checkpoint from callback");
        assert!(
            connector
                .scan_with_callback(&context(&path, None), &mut |_| anyhow::bail!(
                    "consumer stopped"
                ))
                .expect_err("callback")
                .to_string()
                .contains("consumer stopped")
        );
        writer
            .execute(
                "UPDATE orchestration_v2_projection_threads SET deleted_at=?1",
                [AT],
            )
            .expect("deleted");
        assert!(
            connector
                .scan(&context(&path, None))
                .expect("deleted scan")
                .is_empty()
        );
    }

    #[test]
    fn t3_preserves_models_across_provider_changes_and_inherited_history() {
        let (_directory, writer, path) = fixture();
        thread(&writer, "parent", Value::Null, false);
        for (id, ordinal, model, provider, driver) in [
            ("r1", 1, "model-a", "p1", "codex"),
            ("r2", 2, "model-b", "p2", "claude"),
        ] {
            run(&writer, "parent", id, ordinal, "completed");
            writer.execute("UPDATE orchestration_v2_projection_runs SET payload_json=json_set(payload_json,'$.modelSelection',json(?1),'$.providerThreadId',?2,'$.providerInstanceId',?2) WHERE run_id=?3", rusqlite::params![json!({"model":model}).to_string(), provider, id]).expect("model");
            let provider_payload =
                json!({"id":provider,"appThreadId":"parent","driver":driver,"updatedAt":AT});
            writer.execute("INSERT INTO orchestration_v2_projection_provider_threads VALUES (?1,'parent',?2,?3)",rusqlite::params![provider, AT, provider_payload.to_string()]).expect("provider");
            item(
                &writer,
                "parent",
                &format!("item-{id}"),
                ordinal,
                "assistant_message",
                model,
                Some(id),
            );
        }
        thread(
            &writer,
            "child",
            json!({"type":"run","threadId":"parent","runId":"r2"}),
            false,
        );
        let loaded = T3Connector::load_thread(&path, "child").expect("inherited models");
        assert_eq!(loaded.messages[0].author.as_deref(), Some("model-a"));
        assert_eq!(loaded.messages[1].author.as_deref(), Some("model-b"));
        assert_eq!(loaded.messages[0].extra["driver"], "codex");
        assert_eq!(loaded.messages[1].extra["driver"], "claude");
    }

    #[test]
    fn t3_old_item_wal_edit_is_incremental_and_stream_completion_keeps_identity() {
        let (_directory, writer, path) = fixture();
        thread(&writer, "thread", Value::Null, false);
        item(
            &writer,
            "thread",
            "item",
            0,
            "assistant_message",
            "partialword",
            None,
        );
        let before = T3Connector::load_thread(&path, "thread").expect("before");
        let old_db = std::fs::read(&path).expect("db");
        let changed = "2026-10-27T11:00:00.000Z";
        writer.execute("UPDATE orchestration_v2_projection_turn_items SET updated_at=?1,payload_json=json_set(payload_json,'$.text','completedword','$.streaming',json('false'),'$.updatedAt',?1)",[changed]).expect("WAL edit");
        assert_eq!(std::fs::read(&path).expect("main db unchanged"), old_db);
        let since = timestamp(&json!({"updatedAt":changed}), "updatedAt").expect("timestamp");
        let after = T3Connector::new()
            .scan(&context(&path, since))
            .expect("incremental");
        assert_eq!(after.len(), 1);
        assert_eq!(before.messages[0].msg_uid, after[0].messages[0].msg_uid);
        assert_eq!(after[0].messages[0].content, "completedword");
    }

    #[test]
    fn t3_renders_all_current_variants_and_caps_unicode_output() {
        let variants = [
            "user_message",
            "assistant_message",
            "reasoning",
            "proposed_plan",
            "todo_list",
            "command_execution",
            "dynamic_tool",
            "file_change",
            "file_search",
            "web_search",
            "subagent",
            "user_input_request",
            "approval_request",
            "notification",
            "system_notice",
            "run_interrupt_request",
            "run_interrupt_result",
            "error",
            "compaction",
            "handoff",
            "fork",
            "thread_created",
            "checkpoint",
            "secret_request",
        ];
        for variant in variants {
            let value = json!({"type":variant,"text":"text","markdown":"plan","steps":[{"text":"step"}],"input":"command","output":"result","fileName":"file.rs","results":["match"],"prompt":"prompt","questions":["question"],"summary":"summary","message":"notice","failure":{"message":"failed"},"source":{"threadId":"source"},"targetThreadId":"child","files":["file.rs"],"label":"credential name","secretStatus":"saved","secretValue":"mustnotappear"});
            let (content, _, _) = item_content(&value).expect("supported type");
            assert!(!content.is_empty(), "{variant}");
            assert!(!content.contains("mustnotappear"));
        }
        let (_directory, writer, path) = fixture();
        thread(&writer, "thread", Value::Null, false);
        item(
            &writer,
            "thread",
            "large",
            0,
            "assistant_message",
            &"界".repeat(MAX_ITEM_BYTES),
            None,
        );
        let loaded = T3Connector::load_thread(&path, "thread").expect("large item");
        assert_eq!(loaded.messages[0].extra["truncated"], true);
        assert!(loaded.messages[0].content.len() <= MAX_ITEM_BYTES + 32);
    }

    #[test]
    fn t3_explicit_copies_are_schema_detected_and_have_separate_namespaces() {
        let (directory, writer, path) = fixture();
        thread(&writer, "thread", Value::Null, false);
        item(&writer, "thread", "item", 0, "user_message", "word", None);
        drop(writer);
        let copied = directory.path().join("copied.sqlite");
        std::fs::copy(&path, &copied).expect("copy closed database");
        let roots = vec![
            ScanRoot::local(path.clone()),
            ScanRoot::local(copied.clone()),
        ];
        let ctx = ScanContext::with_roots(directory.path().join("unrelated"), roots, None);
        let loaded = T3Connector::new().scan(&ctx).expect("two databases");
        assert_eq!(loaded.len(), 2);
        assert_ne!(loaded[0].external_id, loaded[1].external_id);
        assert_ne!(loaded[0].source_path, loaded[1].source_path);
    }

    #[test]
    fn t3_hides_cancelled_queued_inputs_and_unpaired_superseded_interrupts() {
        let (_directory, writer, path) = fixture();
        thread(&writer, "thread", Value::Null, false);
        run(&writer, "thread", "cancelled", 1, "cancelled");
        item(
            &writer,
            "thread",
            "queued",
            0,
            "user_message",
            "neverdelivered",
            Some("cancelled"),
        );
        writer.execute("UPDATE orchestration_v2_projection_turn_items SET payload_json=json_set(payload_json,'$.inputIntent','queued_turn') WHERE turn_item_id='queued'",[]).expect("queued input");
        run(&writer, "thread", "steered", 2, "completed");
        item(
            &writer,
            "thread",
            "stopped",
            1,
            "run_interrupt_result",
            "supersededword",
            Some("steered"),
        );
        writer.execute("UPDATE orchestration_v2_projection_turn_items SET payload_json=json_set(payload_json,'$.nodeId','root') WHERE turn_item_id='stopped'",[]).expect("node");
        writer.execute("INSERT INTO orchestration_v2_projection_run_attempts VALUES ('attempt','thread',?1)",[json!({"runId":"steered","rootNodeId":"root","status":"superseded"}).to_string()]).expect("attempt");
        let hidden = T3Connector::load_thread(&path, "thread").expect("hidden");
        assert!(hidden.messages.is_empty());
        item(
            &writer,
            "thread",
            "paired",
            2,
            "run_interrupt_request",
            "stop request",
            Some("steered"),
        );
        let visible = T3Connector::load_thread(&path, "thread").expect("paired stop");
        assert_eq!(visible.messages.len(), 2);
        assert!(visible.messages[0].content.contains("supersededword"));
    }
}

fn open_database(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open T3 database {}", path.display()))?;
    connection.busy_timeout(Duration::from_secs(2))?;
    // Preparing this query validates the required current-schema boundary without writes.
    connection.prepare("SELECT thread_id, payload_json, deleted_at FROM orchestration_v2_projection_threads LIMIT 0")
        .with_context(|| format!("unsupported T3 schema at {}", path.display()))?;
    Ok(connection)
}

fn text<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn required_text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    text(value, field).with_context(|| format!("T3 record missing string {field}"))
}

fn timestamp(value: &Value, field: &str) -> Result<Option<i64>> {
    let Some(raw) = value.get(field).filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    super::parse_timestamp(raw)
        .map(Some)
        .with_context(|| format!("invalid T3 timestamp in {field}"))
}

fn json_rows(connection: &Connection, query: &str, thread: &str) -> Result<Vec<Value>> {
    let mut statement = connection.prepare(query)?;
    let mut rows = statement.query([thread])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        let payload: String = row.get(0)?;
        let record: Value = serde_json::from_str(&payload)
            .with_context(|| format!("invalid T3 JSON for thread {thread}"))?;
        ensure!(
            record.is_object(),
            "T3 projection for thread {thread} must be an object"
        );
        records.push(record);
    }
    Ok(records)
}

struct Projection {
    thread: Value,
    items: Vec<Value>,
    messages: Vec<Value>,
    runs: Vec<Value>,
    attempts: Vec<Value>,
    providers: Vec<Value>,
    updated_at: i64,
}

impl Projection {
    fn read(connection: &Connection, id: &str) -> Result<Self> {
        let thread = json_rows(
            connection,
            "SELECT payload_json FROM orchestration_v2_projection_threads WHERE thread_id=?1",
            id,
        )?
        .into_iter()
        .next()
        .with_context(|| format!("T3 thread {id} is missing"))?;
        ensure!(
            required_text(&thread, "id")? == id,
            "T3 thread identity mismatch for {id}"
        );
        let items = json_rows(
            connection,
            "SELECT payload_json FROM orchestration_v2_projection_turn_items WHERE thread_id=?1 ORDER BY ordinal, turn_item_id",
            id,
        )?;
        let messages = json_rows(
            connection,
            "SELECT payload_json FROM orchestration_v2_projection_messages WHERE thread_id=?1 ORDER BY created_at, message_id",
            id,
        )?;
        let runs = json_rows(
            connection,
            "SELECT payload_json FROM orchestration_v2_projection_runs WHERE thread_id=?1 ORDER BY ordinal",
            id,
        )?;
        let attempts = json_rows(
            connection,
            "SELECT payload_json FROM orchestration_v2_projection_run_attempts WHERE thread_id=?1",
            id,
        )?;
        let providers = json_rows(
            connection,
            "SELECT payload_json FROM orchestration_v2_projection_provider_threads WHERE thread_id=?1",
            id,
        )?;
        let mut updated_at =
            timestamp(&thread, "updatedAt")?.context("T3 thread missing updatedAt")?;
        for item in items.iter().chain(&messages).chain(&providers) {
            ensure!(
                text(item, "threadId")
                    .or_else(|| text(item, "appThreadId"))
                    .is_none_or(|owner| owner == id),
                "T3 projection belongs to another thread than {id}"
            );
            if let Some(updated) = timestamp(item, "updatedAt")? {
                updated_at = updated_at.max(updated);
            }
        }
        Ok(Self {
            thread,
            items,
            messages,
            runs,
            attempts,
            providers,
            updated_at,
        })
    }

    fn superseded_interrupt(&self, item: &Value) -> bool {
        text(item, "type") == Some("run_interrupt_result")
            && text(item, "runId").is_some()
            && text(item, "nodeId").is_some()
            && self.attempts.iter().any(|attempt| {
                text(attempt, "runId") == text(item, "runId")
                    && text(attempt, "rootNodeId") == text(item, "nodeId")
                    && text(attempt, "status") == Some("superseded")
            })
            && !self.items.iter().any(|candidate| {
                text(candidate, "type") == Some("run_interrupt_request")
                    && text(candidate, "runId") == text(item, "runId")
            })
    }

    fn visible(&self, item: &Value) -> bool {
        let status = text(item, "runId")
            .and_then(|run| {
                self.runs
                    .iter()
                    .find(|candidate| text(candidate, "id") == Some(run))
            })
            .and_then(|run| text(run, "status"));
        status != Some("rolled_back")
            && !(status == Some("cancelled")
                && text(item, "type") == Some("user_message")
                && text(item, "inputIntent") == Some("queued_turn"))
            && !self.superseded_interrupt(item)
    }

    fn annotated_item(&self, item: &Value) -> Value {
        let mut item = item.clone();
        if let Some(message) = text(&item, "messageId").and_then(|id| {
            self.messages
                .iter()
                .find(|message| text(message, "id") == Some(id))
        }) {
            item["text"] = message["text"].clone();
            item["attachments"] = message["attachments"].clone();
            item["streaming"] = message["streaming"].clone();
        }
        let run = text(&item, "runId")
            .and_then(|id| self.runs.iter().find(|run| text(run, "id") == Some(id)));
        let provider_id = text(&item, "providerThreadId")
            .or_else(|| run.and_then(|run| text(run, "providerThreadId")));
        let provider = provider_id.and_then(|id| {
            self.providers
                .iter()
                .find(|provider| text(provider, "id") == Some(id))
        });
        let model = run
            .and_then(|run| run.get("modelSelection"))
            .cloned()
            .unwrap_or(Value::Null);
        let driver = text(&item, "driver")
            .or_else(|| provider.and_then(|provider| text(provider, "driver")))
            .map(str::to_owned);
        let instance = run
            .and_then(|run| run.get("providerInstanceId"))
            .cloned()
            .unwrap_or(Value::Null);
        item["t3ModelSelection"] = model;
        item["t3Driver"] = json!(driver);
        item["t3ProviderInstanceId"] = instance;
        item
    }
}

fn visible_items(
    connection: &Connection,
    projection: &Projection,
    seen: &mut HashSet<String>,
) -> Result<Vec<Value>> {
    let id = required_text(&projection.thread, "id")?;
    ensure!(
        seen.len() < MAX_FORK_DEPTH && seen.insert(id.to_owned()),
        "cyclic or excessively deep T3 fork history at {id}"
    );
    let mut visible = Vec::new();
    if let Some(fork) = projection
        .thread
        .get("forkedFrom")
        .filter(|fork| text(fork, "type") == Some("run"))
    {
        let parent_id = required_text(fork, "threadId")?;
        let source_run = required_text(fork, "runId")?;
        let parent = Projection::read(connection, parent_id)?;
        let cutoff = parent
            .runs
            .iter()
            .find(|run| text(run, "id") == Some(source_run))
            .and_then(|run| run.get("ordinal"))
            .and_then(Value::as_u64)
            .with_context(|| format!("T3 fork source run {source_run} is missing"))?;
        visible.extend(
            visible_items(connection, &parent, seen)?
                .into_iter()
                .filter(|item| {
                    text(item, "threadId") != Some(parent_id) || text(item, "type") == Some("fork")
                }),
        );
        for item in &parent.items {
            let before = text(item, "runId").map_or_else(
                || text(&parent.thread, "historyOrigin") == Some("v1_import"),
                |run| {
                    parent
                        .runs
                        .iter()
                        .find(|candidate| text(candidate, "id") == Some(run))
                        .and_then(|run| run.get("ordinal"))
                        .and_then(Value::as_u64)
                        .is_some_and(|ordinal| ordinal <= cutoff)
                },
            );
            if before && !parent.superseded_interrupt(item) {
                visible.push(parent.annotated_item(item));
            }
        }
        visible.push(json!({"id":format!("fork:{id}"),"threadId":id,"type":"fork","source":fork,"targetThreadId":id,"updatedAt":projection.thread["createdAt"]}));
    }
    visible.extend(
        projection
            .items
            .iter()
            .filter(|item| projection.visible(item))
            .map(|item| projection.annotated_item(item)),
    );
    let represented: HashSet<_> = projection
        .items
        .iter()
        .filter_map(|item| text(item, "messageId"))
        .collect();
    // System notices may have a message projection without a corresponding turn item.
    for message in &projection.messages {
        if !represented.contains(required_text(message, "id")?) && projection.visible(message) {
            let mut item = projection.annotated_item(message);
            item["messageId"] = message["id"].clone();
            item["type"] = json!(match text(message, "role") {
                Some("user") => "user_message",
                Some("assistant") => "assistant_message",
                _ => "system_notice",
            });
            let created_at = timestamp(message, "createdAt")?;
            let mut position = visible.len();
            for (index, candidate) in visible.iter().enumerate() {
                if text(candidate, "threadId") != Some(id) {
                    continue;
                }
                let candidate_at = timestamp(candidate, "startedAt")?
                    .or(timestamp(candidate, "createdAt")?)
                    .or(timestamp(candidate, "updatedAt")?);
                if created_at
                    .zip(candidate_at)
                    .is_some_and(|(notice, turn)| notice < turn)
                {
                    position = index;
                    break;
                }
            }
            visible.insert(position, item);
        }
    }
    seen.remove(id);
    Ok(visible)
}

fn item_content(item: &Value) -> Result<(String, &'static str, Option<&'static str>)> {
    let kind = required_text(item, "type")?;
    if matches!(kind, "user_message" | "assistant_message" | "reasoning") {
        required_text(item, "text")?;
    }
    let (role, tool, fields): (&str, Option<&str>, &[&str]) = match kind {
        "user_message" => ("user", None, &["text", "attachments"]),
        "assistant_message" => ("assistant", None, &["text", "attachments"]),
        "reasoning" => ("assistant", None, &["text"]),
        "proposed_plan" => ("assistant", None, &["markdown"]),
        "todo_list" => ("assistant", None, &["explanation", "steps"]),
        "command_execution" => ("tool", Some("bash"), &["input", "output", "exitCode"]),
        "dynamic_tool" => (
            "tool",
            Some("dynamic_tool"),
            &["toolName", "input", "output"],
        ),
        "file_change" => (
            "tool",
            Some("file_change"),
            &["fileName", "diffStr", "oldStr", "newStr", "changes"],
        ),
        "file_search" => ("tool", Some("file_search"), &["pattern", "results"]),
        "web_search" => ("tool", Some("web_search"), &["patterns", "results"]),
        "subagent" => (
            "assistant",
            Some("subagent"),
            &["prompt", "progress", "result", "childThreadId"],
        ),
        "user_input_request" => ("assistant", None, &["questions", "questionAnswer"]),
        "approval_request" => ("system", None, &["prompt", "options"]),
        "notification" => ("system", None, &["summary", "detail"]),
        "system_notice" | "run_interrupt_request" | "run_interrupt_result" => {
            ("system", None, &["message", "text"])
        }
        "error" => ("system", None, &["failure", "retry"]),
        "compaction" => ("system", None, &["summary", "driver"]),
        "handoff" => (
            "system",
            None,
            &[
                "summary",
                "fromProviderThreadIds",
                "toProviderThreadId",
                "toModel",
            ],
        ),
        "fork" => ("system", None, &["source", "targetThreadId"]),
        "thread_created" => ("system", None, &["targetThreadId", "targetModel"]),
        "checkpoint" => ("system", None, &["files"]),
        "secret_request" => ("system", None, &["label", "reason", "secretStatus"]),
        other => bail!("unsupported T3 timeline item type {other}"),
    };
    let mut parts = Vec::new();
    if let Some(title) = text(item, "title") {
        parts.push(title.to_owned());
    }
    for field in fields {
        if let Some(value) = item.get(*field).filter(|value| !value.is_null()) {
            let content = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            if !content.is_empty() && content != "[]" {
                parts.push(content);
            }
        }
    }
    Ok((parts.join("\n"), role, tool))
}

fn normalized_messages(
    projection: &Projection,
    items: Vec<Value>,
) -> Result<(Vec<NormalizedMessage>, i64)> {
    let id = required_text(&projection.thread, "id")?;
    let mut messages = Vec::new();
    let current_messages: HashMap<_, _> = projection
        .messages
        .iter()
        .filter_map(|message| text(message, "id").map(|id| (id, message)))
        .collect();
    let mut seen_items = HashSet::new();
    let mut updated_at = projection.updated_at;
    for mut item in items {
        let item_id = required_text(&item, "id")?.to_owned();
        let owner = required_text(&item, "threadId")?.to_owned();
        if !seen_items.insert((owner.clone(), item_id.clone())) {
            continue;
        }
        if owner == id
            && let Some(message) = text(&item, "messageId").and_then(|id| current_messages.get(id))
        {
            item["text"] = message["text"].clone();
            item["attachments"] = message["attachments"].clone();
            item["streaming"] = message["streaming"].clone();
        }
        let (mut content, role, tool) = item_content(&item)?;
        if content.trim().is_empty() {
            continue;
        }
        let original_bytes = content.len();
        let mut end = original_bytes.min(MAX_ITEM_BYTES);
        while !content.is_char_boundary(end) {
            end -= 1;
        }
        content.truncate(end);
        if end < original_bytes {
            content.push_str("\n[T3 item truncated]");
        }
        let changed_at = timestamp(&item, "updatedAt")?;
        if let Some(changed) = changed_at {
            updated_at = updated_at.max(changed);
        }
        let provider = text(&item, "providerThreadId").and_then(|provider| {
            projection
                .providers
                .iter()
                .find(|candidate| text(candidate, "id") == Some(provider))
        });
        let author = item
            .get("t3ModelSelection")
            .and_then(|model| text(model, "model"))
            .or_else(|| text(&item, "t3Driver"))
            .or_else(|| {
                provider
                    .and_then(|provider| text(provider, "driver"))
                    .or_else(|| text(&item, "driver"))
            })
            .map(str::to_owned);
        let invocations = tool
            .map(|tool| NormalizedInvocation {
                kind: "tool".to_owned(),
                name: text(&item, "toolName").unwrap_or(tool).to_owned(),
                raw_name: None,
                call_id: Some(item_id.clone()),
                arguments: item
                    .get("input")
                    .filter(|input| input.to_string().len() <= MAX_ITEM_BYTES)
                    .cloned(),
            })
            .into_iter()
            .collect();
        messages.push(NormalizedMessage {
            idx: i64::try_from(messages.len())?, role: role.to_owned(), author,
            created_at: timestamp(&item, "startedAt")?.or(timestamp(&item, "createdAt")?).or(changed_at), content,
            msg_uid: Some(format!("{owner}:{item_id}")), invocations,
            extra: json!({"t3_item_id":item_id,"t3_thread_id":owner,"type":item["type"],"status":item["status"],"updated_at_ms":changed_at,"inherited":owner != id,"provider_thread_id":item["providerThreadId"],"driver":item["t3Driver"],"model_selection":item["t3ModelSelection"],"provider_instance_id":item["t3ProviderInstanceId"],"streaming":item["streaming"],"truncated":end < original_bytes,"original_bytes":original_bytes}),
            ..NormalizedMessage::default()
        });
    }
    Ok((messages, updated_at))
}

fn conversation(
    connection: &Connection,
    root: &ScanRoot,
    projection: &Projection,
    items: Vec<Value>,
) -> Result<NormalizedConversation> {
    let id = required_text(&projection.thread, "id")?;
    let namespace = root.path.to_string_lossy();
    let external = |thread: &str| format!("{}:{namespace}:{thread}", namespace.len());
    let (messages, updated_at) = normalized_messages(projection, items)?;
    let workspace = text(&projection.thread, "worktreePath")
        .map(str::to_owned)
        .or(connection
            .query_row(
                "SELECT workspace_root FROM projection_projects WHERE project_id=?1",
                [required_text(&projection.thread, "projectId")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
        .map(|path| PathBuf::from(root.rewrite_workspace(&path, Some("t3"))));
    let lineage = projection.thread.get("lineage");
    let parent = lineage
        .and_then(|lineage| text(lineage, "parentThreadId"))
        .or_else(|| {
            projection
                .thread
                .get("forkedFrom")
                .and_then(|fork| text(fork, "threadId"))
        });
    let relation = match lineage.and_then(|lineage| text(lineage, "relationshipToParent")) {
        Some("subagent") => LineageRelation::Subagent,
        _ if parent.is_some() => LineageRelation::Fork,
        _ => LineageRelation::Root,
    };
    Ok(NormalizedConversation {
        agent_slug: "t3".to_owned(),
        external_id: Some(external(id)),
        thread_external_id: Some(external(id)),
        parent_external_id: parent.map(external),
        lineage_relation: Some(relation),
        git_branch: text(&projection.thread, "branch").map(str::to_owned),
        title: Some(required_text(&projection.thread, "title")?.to_owned()),
        workspace,
        source_path: root.path.join(urlencoding::encode(id).as_ref()),
        started_at: timestamp(&projection.thread, "createdAt")?,
        ended_at: Some(updated_at),
        metadata: json!({"source":"t3_sqlite","t3_thread_id":id,"t3_database":root.path,"project_id":projection.thread["projectId"],"archived_at":projection.thread["archivedAt"],"settled_at":projection.thread["settledAt"],"model_selection":projection.thread["modelSelection"],"provider_threads":projection.providers,"updated_at_ms":updated_at,"origin":root.origin}),
        messages,
    })
}
