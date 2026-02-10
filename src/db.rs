use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA_VERSION: i32 = 4;

pub fn init_db(conn: &Connection, busy_timeout_ms: u64) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;
    PRAGMA auto_vacuum = INCREMENTAL;
    PRAGMA wal_autocheckpoint = 1000;
    PRAGMA journal_size_limit = 67108864;
    PRAGMA temp_store = MEMORY;
",
    )?;
    conn.busy_timeout(std::time::Duration::from_millis(busy_timeout_ms))?;

    conn.create_scalar_function(
        "regexp",
        2,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let pattern = ctx.get::<String>(0)?;
            let text = ctx.get::<String>(1).unwrap_or_default();
            let re = regex::Regex::new(&pattern)
                .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
            Ok(re.is_match(&text))
        },
    )?;

    conn.execute_batch(
        "
        -- Sessions: one per nsh wrap invocation
        CREATE TABLE IF NOT EXISTS sessions (
            id              TEXT PRIMARY KEY,
            tty             TEXT NOT NULL,
            shell           TEXT NOT NULL,
            pid             INTEGER NOT NULL,
            started_at      TEXT NOT NULL,
            ended_at        TEXT,
            hostname        TEXT,
            username        TEXT,
            last_heartbeat  TEXT,
            label           TEXT
        );

        -- Individual commands within sessions
        CREATE TABLE IF NOT EXISTS commands (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL REFERENCES sessions(id),
            command         TEXT NOT NULL,
            cwd             TEXT,
            exit_code       INTEGER,
            started_at      TEXT NOT NULL,
            duration_ms     INTEGER,
            output          TEXT,
            summary         TEXT,
            summary_status  TEXT DEFAULT NULL
        );

        -- FTS5 virtual table for full-text search
        CREATE VIRTUAL TABLE IF NOT EXISTS commands_fts USING fts5(
            command,
            output,
            summary,
            cwd,
            content='commands',
            content_rowid='id',
            tokenize='porter unicode61'
        );

        -- Triggers to keep FTS in sync
        CREATE TRIGGER IF NOT EXISTS commands_ai AFTER INSERT ON commands BEGIN
            INSERT INTO commands_fts(rowid, command, output, summary, cwd)
            VALUES (new.id, new.command, new.output, new.summary, new.cwd);
        END;

        CREATE TRIGGER IF NOT EXISTS commands_ad AFTER DELETE ON commands BEGIN
            INSERT INTO commands_fts(commands_fts, rowid, command, output, summary, cwd)
            VALUES ('delete', old.id, old.command, old.output, old.summary, old.cwd);
        END;

        CREATE TRIGGER IF NOT EXISTS commands_au AFTER UPDATE ON commands BEGIN
            INSERT INTO commands_fts(commands_fts, rowid, command, output, summary, cwd)
            VALUES ('delete', old.id, old.command, old.output, old.summary, old.cwd);
            INSERT INTO commands_fts(rowid, command, output, summary, cwd)
            VALUES (new.id, new.command, new.output, new.summary, new.cwd);
        END;

        -- Conversation history per session (LLM exchanges)
        CREATE TABLE IF NOT EXISTS conversations (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id            TEXT NOT NULL REFERENCES sessions(id),
            query                 TEXT NOT NULL,
            response_type         TEXT NOT NULL,
            response              TEXT NOT NULL,
            explanation           TEXT,
            executed              INTEGER DEFAULT 0,
            pending               INTEGER DEFAULT 0,
            created_at            TEXT NOT NULL,
            result_exit_code      INTEGER,
            result_output_snippet TEXT
        );

        -- Cost/usage tracking
        CREATE TABLE IF NOT EXISTS usage (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id      TEXT NOT NULL,
            query_text      TEXT,
            model           TEXT NOT NULL,
            provider        TEXT NOT NULL,
            input_tokens    INTEGER,
            output_tokens   INTEGER,
            cost_usd        REAL,
            generation_id   TEXT,
            created_at      TEXT NOT NULL
        );

        -- Audit log
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT NOT NULL,
            query       TEXT NOT NULL,
            suggested_command TEXT,
            action      TEXT NOT NULL,
            risk_level  TEXT,
            created_at  TEXT NOT NULL
        );

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_commands_session
            ON commands(session_id, started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_commands_started
            ON commands(started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_sessions_tty
            ON sessions(tty, started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_conversations_session
            ON conversations(session_id, created_at DESC);

        -- Schema version tracking
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    ",
    )?;

    conn.execute_batch("BEGIN IMMEDIATE;")?;

    let current_version: i32 = conn
        .query_row(
            "SELECT COALESCE((SELECT value FROM meta WHERE key='schema_version'), '0')",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current_version < 2 {
        conn.execute_batch("ALTER TABLE sessions ADD COLUMN last_heartbeat TEXT;")
            .ok();
    }

    if current_version < 3 {
        conn.execute_batch("ALTER TABLE commands ADD COLUMN summary TEXT;")
            .ok();
        conn.execute_batch("ALTER TABLE commands ADD COLUMN summary_status TEXT DEFAULT NULL;")
            .ok();
        conn.execute_batch("ALTER TABLE sessions ADD COLUMN label TEXT;")
            .ok();
        conn.execute_batch("ALTER TABLE conversations ADD COLUMN result_exit_code INTEGER;")
            .ok();
        conn.execute_batch("ALTER TABLE conversations ADD COLUMN result_output_snippet TEXT;")
            .ok();

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS usage (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT NOT NULL,
                query_text      TEXT,
                model           TEXT NOT NULL,
                provider        TEXT NOT NULL,
                input_tokens    INTEGER,
                output_tokens   INTEGER,
                cost_usd        REAL,
                generation_id   TEXT,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                query       TEXT NOT NULL,
                suggested_command TEXT,
                action      TEXT NOT NULL,
                risk_level  TEXT,
                created_at  TEXT NOT NULL
            );",
        )?;

        conn.execute_batch(
            "DROP TRIGGER IF EXISTS commands_ai;
             DROP TRIGGER IF EXISTS commands_ad;
             DROP TRIGGER IF EXISTS commands_au;
             DROP TABLE IF EXISTS commands_fts;

             CREATE VIRTUAL TABLE commands_fts USING fts5(
                 command, output, summary, cwd,
                 content='commands', content_rowid='id',
                 tokenize='porter unicode61'
             );

             CREATE TRIGGER commands_ai AFTER INSERT ON commands BEGIN
                 INSERT INTO commands_fts(rowid, command, output, summary, cwd)
                 VALUES (new.id, new.command, new.output, new.summary, new.cwd);
             END;

             CREATE TRIGGER commands_ad AFTER DELETE ON commands BEGIN
                 INSERT INTO commands_fts(commands_fts, rowid, command, output, summary, cwd)
                 VALUES ('delete', old.id, old.command, old.output, old.summary, old.cwd);
             END;

             CREATE TRIGGER commands_au AFTER UPDATE ON commands BEGIN
                 INSERT INTO commands_fts(commands_fts, rowid, command, output, summary, cwd)
                 VALUES ('delete', old.id, old.command, old.output, old.summary, old.cwd);
                 INSERT INTO commands_fts(rowid, command, output, summary, cwd)
                 VALUES (new.id, new.command, new.output, new.summary, new.cwd);
             END;

             INSERT INTO commands_fts(commands_fts) VALUES('rebuild');",
        )?;
    }

    if current_version < 4 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS memories (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                key         TEXT NOT NULL,
                value       TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_memories_key ON memories(key);",
        )?;
    }

    if current_version < SCHEMA_VERSION {
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
            params![SCHEMA_VERSION],
        )?;
    }

    conn.execute_batch("COMMIT;")?;

    if let Err(e) = conn.execute(
        "SELECT count(*) FROM commands_fts WHERE commands_fts MATCH 'test'",
        [],
    ) {
        tracing::warn!("FTS5 index may be corrupt, rebuilding: {e}");
        conn.execute_batch("INSERT INTO commands_fts(commands_fts) VALUES('rebuild')")?;
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn with_db<F, T>(f: F) -> anyhow::Result<T>
where
    F: FnOnce(&Db) -> anyhow::Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let db = Db::open()?;
        f(&db)
    })
    .await?
}

pub struct Db {
    conn: Connection,
    max_output_bytes: usize,
}

impl Db {
    pub fn open() -> anyhow::Result<Self> {
        let dir = crate::config::Config::nsh_dir();
        std::fs::create_dir_all(&dir)?;
        let config = crate::config::Config::load().unwrap_or_default();
        let mut conn = Connection::open(dir.join("nsh.db"))?;
        init_db(&conn, config.db.busy_timeout_ms)?;
        conn.set_transaction_behavior(rusqlite::TransactionBehavior::Immediate);
        let db = Self {
            conn,
            max_output_bytes: config.context.max_output_storage_bytes,
        };
        let _ = db.cleanup_orphaned_sessions();
        crate::history_import::import_if_needed(&db);
        Ok(db)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        init_db(&conn, 10000)?;
        Ok(Self {
            conn,
            max_output_bytes: 32768,
        })
    }

    // ── Session management ─────────────────────────────────────────

    pub fn create_session(
        &self,
        id: &str,
        tty: &str,
        shell: &str,
        pid: i64,
    ) -> rusqlite::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let hostname = gethostname();
        let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
        self.conn.execute(
            "INSERT OR IGNORE INTO sessions \
             (id, tty, shell, pid, started_at, hostname, username, last_heartbeat) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![id, tty, shell, pid, now, hostname, username, now],
        )?;
        Ok(())
    }

    pub fn end_session(&self, session_id: &str) -> rusqlite::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE sessions SET ended_at = ? WHERE id = ?",
            params![now, session_id],
        )?;
        Ok(())
    }

    pub fn set_session_label(&self, session_id: &str, label: &str) -> rusqlite::Result<bool> {
        let updated = self.conn.execute(
            "UPDATE sessions SET label = ? WHERE id = ?",
            params![label, session_id],
        )?;
        Ok(updated > 0)
    }

    pub fn get_session_label(&self, session_id: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT label FROM sessions WHERE id = ?",
                params![session_id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => rusqlite::Error::QueryReturnedNoRows,
                other => other,
            })
            .or(Ok(None))
    }

    // ── Command recording ──────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub fn insert_command(
        &self,
        session_id: &str,
        command: &str,
        cwd: &str,
        exit_code: Option<i32>,
        started_at: &str,
        duration_ms: Option<i64>,
        output: Option<&str>,
        tty: &str,
        shell: &str,
        pid: i32,
    ) -> rusqlite::Result<i64> {
        let now = chrono::Utc::now().to_rfc3339();
        let max_bytes = self.max_output_bytes;
        let truncated_output = output.map(|s| {
            if s.len() > max_bytes {
                let mut end = max_bytes;
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}\n... [truncated by nsh]", &s[..end])
            } else {
                s.to_string()
            }
        });

        let tx = self.conn.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO sessions (id, tty, shell, pid, started_at, last_heartbeat) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
               tty=excluded.tty, \
               shell=excluded.shell, \
               pid=excluded.pid, \
               last_heartbeat=excluded.last_heartbeat",
            params![session_id, tty, shell, pid, started_at, now],
        )?;

        tx.execute(
            "INSERT INTO commands \
             (session_id, command, cwd, exit_code, \
              started_at, duration_ms, output) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                session_id,
                command,
                cwd,
                exit_code,
                started_at,
                duration_ms,
                truncated_output.as_deref()
            ],
        )?;
        let rowid = tx.last_insert_rowid();

        tx.commit()?;
        Ok(rowid)
    }

    // ── FTS5 search ────────────────────────────────────────────────

    pub fn search_history(&self, query: &str, limit: usize) -> rusqlite::Result<Vec<HistoryMatch>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.session_id, c.command, c.cwd,
                    c.exit_code, c.started_at, c.output,
                    highlight(commands_fts, 0, '>>>', '<<<') as cmd_hl,
                    highlight(commands_fts, 1, '>>>', '<<<') as out_hl
             FROM commands_fts f
             JOIN commands c ON c.id = f.rowid
             WHERE commands_fts MATCH ?
             ORDER BY bm25(commands_fts, 1.0, 0.5, 2.0, 0.5)
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![query, limit as i64], |row| {
            Ok(HistoryMatch {
                id: row.get(0)?,
                session_id: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                exit_code: row.get(4)?,
                started_at: row.get(5)?,
                output: row.get(6)?,
                cmd_highlight: row.get(7)?,
                output_highlight: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    // ── Cross-TTY context ──────────────────────────────────────────

    #[allow(dead_code)]
    pub fn recent_commands_other_sessions(
        &self,
        current_session: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<OtherSessionCommand>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.command, c.cwd, c.exit_code, c.started_at,
                    s.tty, c.session_id
             FROM commands c
             JOIN sessions s ON s.id = c.session_id
             WHERE c.session_id != ?
               AND s.ended_at IS NULL
               AND (s.last_heartbeat IS NULL
                    OR s.last_heartbeat > datetime('now', '-5 minutes'))
             ORDER BY c.started_at DESC
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![current_session, limit as i64], |row| {
            Ok(OtherSessionCommand {
                command: row.get(0)?,
                cwd: row.get(1)?,
                exit_code: row.get(2)?,
                started_at: row.get(3)?,
                tty: row.get(4)?,
                session_id: row.get(5)?,
            })
        })?;
        rows.collect()
    }

    // ── Conversation history ───────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub fn insert_conversation(
        &self,
        session_id: &str,
        query: &str,
        response_type: &str,
        response: &str,
        explanation: Option<&str>,
        executed: bool,
        pending: bool,
    ) -> rusqlite::Result<i64> {
        let now = chrono::Utc::now().to_rfc3339();
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO conversations \
             (session_id, query, response_type, response, \
              explanation, executed, pending, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                session_id,
                query,
                response_type,
                response,
                explanation,
                executed as i32,
                pending as i32,
                now
            ],
        )?;
        let rowid = tx.last_insert_rowid();
        tx.commit()?;
        Ok(rowid)
    }

    pub fn get_conversations(
        &self,
        session_id: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<ConversationExchange>> {
        let mut stmt = self.conn.prepare(
            "SELECT query, response_type, response, explanation, \
                    result_exit_code, result_output_snippet
             FROM conversations
             WHERE session_id = ?
             ORDER BY created_at DESC
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![session_id, limit as i64], |row| {
            Ok(ConversationExchange {
                query: row.get(0)?,
                response_type: row.get(1)?,
                response: row.get(2)?,
                explanation: row.get(3)?,
                result_exit_code: row.get(4)?,
                result_output_snippet: row.get(5)?,
            })
        })?;
        let mut results: Vec<ConversationExchange> = rows.collect::<Result<_, _>>()?;
        results.reverse(); // chronological order
        Ok(results)
    }

    pub fn clear_conversations(&self, session_id: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM conversations WHERE session_id = ?",
            params![session_id],
        )?;
        Ok(())
    }

    /// Prune old data beyond retention period
    pub fn prune(&self, retention_days: u32) -> rusqlite::Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let deleted = self.conn.execute(
            "DELETE FROM commands WHERE started_at < ?",
            params![cutoff_str],
        )?;
        self.conn.execute(
            "DELETE FROM sessions \
             WHERE ended_at IS NOT NULL AND ended_at < ?",
            params![cutoff_str],
        )?;
        self.conn.execute_batch(
            "INSERT INTO commands_fts(commands_fts) VALUES('optimize');
             PRAGMA incremental_vacuum;",
        )?;
        Ok(deleted)
    }

    pub fn update_heartbeat(&self, session_id: &str) -> rusqlite::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE sessions SET last_heartbeat = ? WHERE id = ?",
            params![now, session_id],
        )?;
        Ok(())
    }

    pub fn cleanup_orphaned_sessions(&self) -> rusqlite::Result<usize> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, pid FROM sessions WHERE ended_at IS NULL")?;
        let orphans: Vec<(String, i64)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();

        let now = chrono::Utc::now().to_rfc3339();
        let mut cleaned = 0usize;
        for (id, pid) in &orphans {
            if *pid <= 0 {
                continue;
            }
            let alive = unsafe { libc::kill(*pid as i32, 0) };
            if alive == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    self.conn.execute(
                        "UPDATE sessions SET ended_at = ? WHERE id = ?",
                        params![now, id],
                    )?;
                    cleaned += 1;
                }
            }
        }
        Ok(cleaned)
    }

    pub fn rebuild_fts(&self) -> rusqlite::Result<()> {
        self.conn
            .execute_batch("INSERT INTO commands_fts(commands_fts) VALUES('rebuild')")
    }

    pub fn optimize_fts(&self) -> rusqlite::Result<()> {
        self.conn
            .execute_batch("INSERT INTO commands_fts(commands_fts) VALUES('optimize')")
    }

    pub fn check_fts_integrity(&self) -> rusqlite::Result<()> {
        self.conn
            .execute_batch("INSERT INTO commands_fts(commands_fts) VALUES('integrity-check')")
    }

    #[allow(dead_code)]
    pub fn prune_if_due(&self, retention_days: u32) -> rusqlite::Result<()> {
        let should_prune: bool = self
            .conn
            .query_row(
                "SELECT COALESCE( \
                   (SELECT value FROM meta WHERE key='last_prune_at'), \
                   '2000-01-01T00:00:00Z' \
                 ) < datetime('now', '-1 day')",
                [],
                |row| row.get(0),
            )
            .unwrap_or(true);

        if should_prune {
            self.prune(retention_days)?;
            let now = chrono::Utc::now().to_rfc3339();
            self.conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('last_prune_at', ?)",
                params![now],
            )?;
        }
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?",
                params![key],
                |row| row.get(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
    }

    pub fn set_meta(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn command_count(&self) -> rusqlite::Result<usize> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM commands",
            [],
            |row| row.get::<_, i64>(0).map(|v| v as usize),
        )
    }

    // ── Memory system ──────────────────────────────────────────────

    pub fn upsert_memory(&self, key: &str, value: &str) -> rusqlite::Result<(i64, bool)> {
        let now = chrono::Utc::now().to_rfc3339();
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM memories WHERE LOWER(key) = LOWER(?)",
                params![key],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(id) = existing {
            self.conn.execute(
                "UPDATE memories SET value = ?, key = ?, updated_at = ? WHERE id = ?",
                params![value, key, now, id],
            )?;
            Ok((id, true))
        } else {
            self.conn.execute(
                "INSERT INTO memories (key, value, created_at, updated_at) VALUES (?, ?, ?, ?)",
                params![key, value, now, now],
            )?;
            Ok((self.conn.last_insert_rowid(), false))
        }
    }

    pub fn delete_memory(&self, id: i64) -> rusqlite::Result<bool> {
        let rows = self
            .conn
            .execute("DELETE FROM memories WHERE id = ?", params![id])?;
        Ok(rows > 0)
    }

    pub fn update_memory(
        &self,
        id: i64,
        key: Option<&str>,
        value: Option<&str>,
    ) -> rusqlite::Result<bool> {
        if key.is_none() && value.is_none() {
            return Ok(false);
        }
        let now = chrono::Utc::now().to_rfc3339();
        let mut parts = Vec::new();
        let mut vals: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(k) = key {
            parts.push("key = ?");
            vals.push(Box::new(k.to_string()));
        }
        if let Some(v) = value {
            parts.push("value = ?");
            vals.push(Box::new(v.to_string()));
        }
        parts.push("updated_at = ?");
        vals.push(Box::new(now));
        vals.push(Box::new(id));

        let sql = format!("UPDATE memories SET {} WHERE id = ?", parts.join(", "));
        let params: Vec<&dyn rusqlite::types::ToSql> = vals.iter().map(|v| v.as_ref()).collect();
        let rows = self.conn.execute(&sql, params.as_slice())?;
        Ok(rows > 0)
    }

    pub fn get_memories(&self, limit: usize) -> rusqlite::Result<Vec<Memory>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, key, value, created_at, updated_at \
             FROM memories ORDER BY updated_at DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(Memory {
                id: row.get(0)?,
                key: row.get(1)?,
                value: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub fn search_memories(&self, query: &str) -> rusqlite::Result<Vec<Memory>> {
        let pattern = format!("%{query}%");
        let mut stmt = self.conn.prepare(
            "SELECT id, key, value, created_at, updated_at \
             FROM memories \
             WHERE key LIKE ? OR value LIKE ? \
             ORDER BY updated_at DESC LIMIT 20",
        )?;
        let rows = stmt.query_map(params![pattern, pattern], |row| {
            Ok(Memory {
                id: row.get(0)?,
                key: row.get(1)?,
                value: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    #[allow(dead_code)]
    pub fn get_memory_by_id(&self, id: i64) -> rusqlite::Result<Option<Memory>> {
        self.conn
            .query_row(
                "SELECT id, key, value, created_at, updated_at FROM memories WHERE id = ?",
                params![id],
                |row| {
                    Ok(Memory {
                        id: row.get(0)?,
                        key: row.get(1)?,
                        value: row.get(2)?,
                        created_at: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .optional()
    }

    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub fn insert_usage(
        &self,
        session_id: &str,
        query_text: Option<&str>,
        model: &str,
        provider: &str,
        input_tokens: Option<u32>,
        output_tokens: Option<u32>,
        cost_usd: Option<f64>,
        generation_id: Option<&str>,
    ) -> rusqlite::Result<i64> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO usage (session_id, query_text, model, provider, \
             input_tokens, output_tokens, cost_usd, generation_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                session_id,
                query_text,
                model,
                provider,
                input_tokens,
                output_tokens,
                cost_usd,
                generation_id,
                now,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    #[allow(dead_code)]
    pub fn update_usage_cost(&self, generation_id: &str, cost_usd: f64) -> rusqlite::Result<bool> {
        let updated = self.conn.execute(
            "UPDATE usage SET cost_usd = ? WHERE generation_id = ?",
            params![cost_usd, generation_id],
        )?;
        Ok(updated > 0)
    }

    #[allow(clippy::type_complexity)]
    pub fn get_usage_stats(
        &self,
        since: Option<&str>,
    ) -> rusqlite::Result<Vec<(String, i64, i64, i64, f64)>> {
        let sql = if let Some(since_expr) = since {
            format!(
                "SELECT model, COUNT(*) as calls, \
                 COALESCE(SUM(input_tokens), 0), \
                 COALESCE(SUM(output_tokens), 0), \
                 COALESCE(SUM(cost_usd), 0.0) \
                 FROM usage WHERE created_at >= {since_expr} \
                 GROUP BY model ORDER BY calls DESC"
            )
        } else {
            "SELECT model, COUNT(*) as calls, \
             COALESCE(SUM(input_tokens), 0), \
             COALESCE(SUM(output_tokens), 0), \
             COALESCE(SUM(cost_usd), 0.0) \
             FROM usage GROUP BY model ORDER BY calls DESC"
                .to_string()
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, f64>(4)?,
            ))
        })?;
        rows.collect()
    }

    #[allow(dead_code)]
    pub fn get_pending_generation_ids(&self) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT generation_id FROM usage \
             WHERE generation_id IS NOT NULL AND cost_usd IS NULL \
             AND created_at > datetime('now', '-1 hour')",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect()
    }

    pub fn commands_needing_summary(
        &self,
        limit: usize,
    ) -> rusqlite::Result<Vec<CommandForSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, command, cwd, exit_code, output
             FROM commands
             WHERE output IS NOT NULL
               AND summary IS NULL
               AND summary_status IS NULL
             ORDER BY started_at DESC
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(CommandForSummary {
                id: row.get(0)?,
                command: row.get(1)?,
                cwd: row.get(2)?,
                exit_code: row.get(3)?,
                output: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub fn update_summary(&self, id: i64, summary: &str) -> rusqlite::Result<bool> {
        let updated = self.conn.execute(
            "UPDATE commands SET summary = ?, summary_status = 'done' WHERE id = ? AND summary IS NULL",
            params![summary, id],
        )?;
        Ok(updated > 0)
    }

    pub fn commands_needing_llm_summary(
        &self,
        limit: usize,
    ) -> rusqlite::Result<Vec<CommandForSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, command, cwd, exit_code, output
             FROM commands
             WHERE output IS NOT NULL AND summary IS NULL AND summary_status = 'needs_llm'
             ORDER BY started_at DESC
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(CommandForSummary {
                id: row.get(0)?,
                command: row.get(1)?,
                cwd: row.get(2)?,
                exit_code: row.get(3)?,
                output: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    pub fn mark_unsummarized_for_llm(&self) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE commands SET summary_status = 'needs_llm'
             WHERE output IS NOT NULL AND summary IS NULL AND summary_status IS NULL",
            [],
        )
    }

    pub fn mark_summary_error(&self, id: i64, error: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE commands SET summary_status = 'error', summary = ? WHERE id = ? AND summary IS NULL",
            params![format!("[error: {}]", error), id],
        )?;
        Ok(())
    }

    pub fn recent_commands_with_summaries(
        &self,
        session_id: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<CommandWithSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.command, c.cwd, c.exit_code, c.started_at,
                    c.duration_ms, c.summary
             FROM commands c
             WHERE c.session_id = ?
             ORDER BY c.started_at DESC
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![session_id, limit as i64], |row| {
            Ok(CommandWithSummary {
                command: row.get(0)?,
                cwd: row.get(1)?,
                exit_code: row.get(2)?,
                started_at: row.get(3)?,
                duration_ms: row.get(4)?,
                summary: row.get(5)?,
            })
        })?;
        let mut results: Vec<CommandWithSummary> = rows.collect::<Result<_, _>>()?;
        results.reverse();
        Ok(results)
    }

    pub fn other_sessions_with_summaries(
        &self,
        current_session: &str,
        max_ttys: usize,
        summaries_per_tty: usize,
    ) -> rusqlite::Result<Vec<OtherSessionSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.command, c.cwd, c.exit_code, c.started_at,
                    c.summary, s.tty, s.shell, c.session_id
             FROM commands c
             JOIN sessions s ON s.id = c.session_id
             WHERE c.session_id != ?
               AND s.ended_at IS NULL
               AND (s.last_heartbeat IS NULL
                    OR s.last_heartbeat > datetime('now', '-5 minutes'))
             ORDER BY c.started_at DESC
             LIMIT ?",
        )?;
        let total_limit = max_ttys * summaries_per_tty;
        let rows = stmt.query_map(params![current_session, total_limit as i64], |row| {
            Ok(OtherSessionSummary {
                command: row.get(0)?,
                cwd: row.get(1)?,
                exit_code: row.get(2)?,
                started_at: row.get(3)?,
                summary: row.get(4)?,
                tty: row.get(5)?,
                shell: row.get(6)?,
                session_id: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn search_history_advanced(
        &self,
        fts_query: Option<&str>,
        regex_pattern: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
        exit_code: Option<i32>,
        failed_only: bool,
        session_filter: Option<&str>,
        current_session: Option<&str>,
        limit: usize,
    ) -> rusqlite::Result<Vec<HistoryMatch>> {
        if let Some(fts) = fts_query {
            let mut sql = String::from(
                "SELECT c.id, c.session_id, c.command, c.cwd,
                        c.exit_code, c.started_at, c.output,
                        highlight(commands_fts, 0, '>>>', '<<<') as cmd_hl,
                        highlight(commands_fts, 1, '>>>', '<<<') as out_hl
                 FROM commands_fts f
                 JOIN commands c ON c.id = f.rowid
                 WHERE commands_fts MATCH ?1",
            );
            let mut param_idx = 2;
            let mut conditions = Vec::new();

            if since.is_some() {
                conditions.push(format!(" AND c.started_at >= ?{param_idx}"));
                param_idx += 1;
            }
            if until.is_some() {
                conditions.push(format!(" AND c.started_at <= ?{param_idx}"));
                param_idx += 1;
            }
            if exit_code.is_some() {
                conditions.push(format!(" AND c.exit_code = ?{param_idx}"));
                param_idx += 1;
            }
            if failed_only {
                conditions.push(" AND c.exit_code != 0".to_string());
            }
            if session_filter.is_some() {
                conditions.push(format!(" AND c.session_id = ?{param_idx}"));
                param_idx += 1;
            }
            let _ = param_idx;

            for cond in &conditions {
                sql.push_str(cond);
            }
            sql.push_str(" ORDER BY bm25(commands_fts, 1.0, 0.5, 2.0, 0.5) LIMIT ?");

            // Build params dynamically - collect into Vec<Box<dyn rusqlite::types::ToSql>>
            let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            params_vec.push(Box::new(fts.to_string()));
            if let Some(s) = since {
                params_vec.push(Box::new(s.to_string()));
            }
            if let Some(u) = until {
                params_vec.push(Box::new(u.to_string()));
            }
            if let Some(ec) = exit_code {
                params_vec.push(Box::new(ec));
            }
            if let Some(sf) = session_filter {
                params_vec.push(Box::new(sf.to_string()));
            }
            params_vec.push(Box::new(limit as i64));

            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params_vec.iter().map(|p| p.as_ref()).collect();

            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(params_refs.as_slice(), |row| {
                Ok(HistoryMatch {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    command: row.get(2)?,
                    cwd: row.get(3)?,
                    exit_code: row.get(4)?,
                    started_at: row.get(5)?,
                    output: row.get(6)?,
                    cmd_highlight: row.get(7)?,
                    output_highlight: row.get(8)?,
                })
            })?;
            let mut results: Vec<HistoryMatch> = rows.collect::<Result<_, _>>()?;

            if let Some(pattern) = regex_pattern {
                if let Ok(re) = regex::Regex::new(pattern) {
                    results.retain(|r| {
                        re.is_match(&r.command)
                            || r.output.as_deref().is_some_and(|o| re.is_match(o))
                    });
                }
            }

            return Ok(results);
        }

        // No FTS query - use regex or plain scan
        let mut sql = String::from(
            "SELECT c.id, c.session_id, c.command, c.cwd,
                    c.exit_code, c.started_at, c.output,
                    c.command as cmd_hl,
                    c.output as out_hl
             FROM commands c WHERE 1=1",
        );
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(pattern) = regex_pattern {
            sql.push_str(" AND (c.command REGEXP ? OR COALESCE(c.output, '') REGEXP ? OR COALESCE(c.summary, '') REGEXP ?)");
            params_vec.push(Box::new(pattern.to_string()));
            params_vec.push(Box::new(pattern.to_string()));
            params_vec.push(Box::new(pattern.to_string()));
        }
        if let Some(s) = since {
            sql.push_str(" AND c.started_at >= ?");
            params_vec.push(Box::new(s.to_string()));
        }
        if let Some(u) = until {
            sql.push_str(" AND c.started_at <= ?");
            params_vec.push(Box::new(u.to_string()));
        }
        if let Some(ec) = exit_code {
            sql.push_str(" AND c.exit_code = ?");
            params_vec.push(Box::new(ec));
        }
        if failed_only {
            sql.push_str(" AND c.exit_code != 0");
        }
        if let Some(sf) = session_filter {
            let resolved = if sf == "current" {
                current_session.unwrap_or("default")
            } else {
                sf
            };
            sql.push_str(" AND c.session_id = ?");
            params_vec.push(Box::new(resolved.to_string()));
        }
        sql.push_str(" ORDER BY c.started_at DESC LIMIT ?");
        params_vec.push(Box::new(limit as i64));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(HistoryMatch {
                id: row.get(0)?,
                session_id: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                exit_code: row.get(4)?,
                started_at: row.get(5)?,
                output: row.get(6)?,
                cmd_highlight: row.get(7)?,
                output_highlight: row.get(8)?,
            })
        })?;
        rows.collect()
    }

    pub fn find_pending_conversation(
        &self,
        session_id: &str,
    ) -> rusqlite::Result<Option<(i64, String)>> {
        self.conn
            .query_row(
                "SELECT id, response FROM conversations WHERE session_id = ? \
             AND response_type = 'command' AND result_exit_code IS NULL \
             ORDER BY created_at DESC LIMIT 1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
    }

    pub fn update_conversation_result(
        &self,
        conv_id: i64,
        exit_code: i32,
        output_snippet: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE conversations SET result_exit_code = ?, result_output_snippet = ? WHERE id = ?",
            params![exit_code, output_snippet, conv_id],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn update_command(
        &self,
        id: i64,
        exit_code: Option<i32>,
        output: Option<&str>,
    ) -> rusqlite::Result<bool> {
        let max_bytes = self.max_output_bytes;
        let truncated_output = output.map(|s| {
            if s.len() > max_bytes {
                let mut end = max_bytes;
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}\n... [truncated by nsh]", &s[..end])
            } else {
                s.to_string()
            }
        });
        let updated = self.conn.execute(
            "UPDATE commands SET exit_code = COALESCE(?, exit_code), \
             output = COALESCE(?, output) WHERE id = ?",
            params![exit_code, truncated_output, id],
        )?;
        Ok(updated > 0)
    }

    pub fn run_doctor(
        &self,
        retention_days: u32,
        no_prune: bool,
        no_vacuum: bool,
        config: &crate::config::Config,
    ) -> anyhow::Result<()> {
        eprintln!("nsh doctor: checking system health...\n");

        // 1. Config file validation
        eprint!("  Config file... ");
        let config_path = crate::config::Config::path();
        if config_path.exists() {
            match std::fs::read_to_string(&config_path) {
                Ok(content) => match toml::from_str::<toml::Value>(&content) {
                    Ok(_) => eprintln!("OK ({})", config_path.display()),
                    Err(e) => eprintln!("PARSE ERROR: {e}"),
                },
                Err(e) => eprintln!("READ ERROR: {e}"),
            }
        } else {
            eprintln!("not found (using defaults)");
        }

        // 2. API key reachability
        eprint!("  API key ({})... ", config.provider.default);
        let auth = match config.provider.default.as_str() {
            "openrouter" => config.provider.openrouter.as_ref(),
            "anthropic" => config.provider.anthropic.as_ref(),
            "openai" => config.provider.openai.as_ref(),
            "ollama" => config.provider.ollama.as_ref(),
            "gemini" => config.provider.gemini.as_ref(),
            _ => None,
        };
        match auth {
            Some(a) => match a.resolve_api_key(&config.provider.default) {
                Ok(_) => eprintln!("OK"),
                Err(e) => eprintln!("MISSING: {e}"),
            },
            None => eprintln!("no auth configured"),
        }

        // 3. Shell hook integrity
        eprint!("  Shell hooks... ");
        let shell = std::env::var("SHELL").unwrap_or_default();
        let shell_name = shell.rsplit('/').next().unwrap_or("");
        let rc_path = match shell_name {
            "zsh" => Some(dirs::home_dir().unwrap_or_default().join(".zshrc")),
            "bash" => {
                let bashrc = dirs::home_dir().unwrap_or_default().join(".bashrc");
                let bash_profile = dirs::home_dir().unwrap_or_default().join(".bash_profile");
                if bashrc.exists() {
                    Some(bashrc)
                } else if bash_profile.exists() {
                    Some(bash_profile)
                } else {
                    Some(bashrc)
                }
            }
            "fish" => Some(
                dirs::config_dir()
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"))
                    .join("fish/conf.d/nsh.fish"),
            ),
            _ => None,
        };
        if let Some(ref path) = rc_path {
            if path.exists() {
                let content = std::fs::read_to_string(path).unwrap_or_default();
                if content.contains("nsh init") || content.contains("nsh wrap") {
                    eprintln!("OK ({})", path.display());
                } else {
                    eprintln!("MISSING — nsh init not found in {}", path.display());
                }
            } else {
                eprintln!("rc file not found: {}", path.display());
            }
        } else {
            eprintln!("unknown shell: {shell_name}");
        }

        // 4. DB size report
        eprint!("  Database... ");
        let db_path = crate::config::Config::nsh_dir().join("nsh.db");
        let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
        let db_size_str = if db_size > 1_048_576 {
            format!("{:.1} MB", db_size as f64 / 1_048_576.0)
        } else {
            format!("{:.1} KB", db_size as f64 / 1024.0)
        };
        eprintln!("{db_size_str}");

        // 5. FTS5 integrity
        eprint!("  FTS5 integrity... ");
        match self.check_fts_integrity() {
            Ok(()) => eprintln!("OK"),
            Err(e) => {
                eprintln!("FAILED: {e}");
                eprint!("  Rebuilding FTS5 index... ");
                self.rebuild_fts()?;
                eprintln!("done");
            }
        }

        eprint!("  FTS5 optimize... ");
        self.optimize_fts()?;
        eprintln!("OK");

        // 6. Orphaned sessions
        eprint!("  Orphaned sessions... ");
        let cleaned = self.cleanup_orphaned_sessions()?;
        eprintln!("{cleaned} cleaned");

        // 7. Missing summaries count
        eprint!("  Missing summaries... ");
        let missing_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE output IS NOT NULL AND summary IS NULL AND summary_status IS NULL",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        if missing_count > 0 {
            eprintln!("{missing_count} commands without summaries");
        } else {
            eprintln!("none");
        }

        // 8. Orphaned socket/PID files
        eprint!("  Orphaned files... ");
        let nsh_dir = crate::config::Config::nsh_dir();
        let mut orphaned_count = 0;
        if let Ok(entries) = std::fs::read_dir(&nsh_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if (name.starts_with("daemon_")
                    && (name.ends_with(".sock") || name.ends_with(".pid")))
                    || name.starts_with("scrollback_") && !name.ends_with(".sock")
                    || name.starts_with("pending_cmd_")
                    || name.starts_with("pending_flag_")
                {
                    let session_id = name
                        .trim_start_matches("daemon_")
                        .trim_start_matches("scrollback_")
                        .trim_start_matches("pending_cmd_")
                        .trim_start_matches("pending_flag_")
                        .trim_end_matches(".sock")
                        .trim_end_matches(".pid")
                        .trim_end_matches(".tmp");
                    let session_active: bool = self
                        .conn
                        .query_row(
                            "SELECT COUNT(*) > 0 FROM sessions WHERE id = ? AND ended_at IS NULL",
                            params![session_id],
                            |row| row.get(0),
                        )
                        .unwrap_or(false);
                    if !session_active {
                        let _ = std::fs::remove_file(entry.path());
                        orphaned_count += 1;
                    }
                }
            }
        }
        eprintln!("{orphaned_count} removed");

        // 9. Pruning
        if !no_prune {
            eprint!("  Pruning old data ({retention_days} days)... ");
            let pruned = self.prune(retention_days)?;
            eprintln!("{pruned} commands removed");
        } else {
            eprintln!("  Pruning... skipped (--no-prune)");
        }

        // 10. Vacuum
        if !no_vacuum {
            eprint!("  Incremental vacuum... ");
            self.conn.execute_batch("PRAGMA incremental_vacuum")?;
            eprintln!("OK");
        } else {
            eprintln!("  Vacuum... skipped (--no-vacuum)");
        }

        // 11. Integrity check
        eprint!("  Integrity check... ");
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        eprintln!("{result}");

        eprintln!("\nnsh doctor: done");

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Memory {
    pub id: i64,
    pub key: String,
    pub value: String,
    pub created_at: String,
    pub updated_at: String,
}

// ── Data types ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct HistoryMatch {
    #[allow(dead_code)]
    pub id: i64,
    #[allow(dead_code)]
    pub session_id: String,
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub output: Option<String>,
    pub cmd_highlight: String,
    pub output_highlight: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct OtherSessionCommand {
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub tty: String,
    pub session_id: String,
}

#[derive(Debug)]
pub struct CommandForSummary {
    pub id: i64,
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub output: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CommandWithSummary {
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub duration_ms: Option<i64>,
    pub summary: Option<String>,
}

#[derive(Debug)]
pub struct OtherSessionSummary {
    pub command: String,
    #[allow(dead_code)]
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub summary: Option<String>,
    pub tty: String,
    pub shell: String,
    #[allow(dead_code)]
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct ConversationExchange {
    pub query: String,
    pub response_type: String,
    pub response: String,
    pub explanation: Option<String>,
    pub result_exit_code: Option<i32>,
    pub result_output_snippet: Option<String>,
}

impl ConversationExchange {
    pub fn to_user_message(&self) -> crate::provider::Message {
        crate::provider::Message {
            role: crate::provider::Role::User,
            content: vec![crate::provider::ContentBlock::Text {
                text: self.query.clone(),
            }],
        }
    }

    pub fn to_assistant_message(&self, tool_id: &str) -> crate::provider::Message {
        use crate::provider::{ContentBlock, Message, Role};

        match self.response_type.as_str() {
            "command" => {
                let input = serde_json::json!({
                    "command": self.response,
                    "explanation": self.explanation
                        .as_deref().unwrap_or(""),
                });
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: tool_id.to_string(),
                        name: "command".into(),
                        input,
                    }],
                }
            }
            _ => {
                let input = serde_json::json!({
                    "response": self.response,
                });
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: tool_id.to_string(),
                        name: "chat".into(),
                        input,
                    }],
                }
            }
        }
    }

    pub fn to_tool_result_message(&self, tool_id: &str) -> crate::provider::Message {
        use crate::provider::{ContentBlock, Message, Role};

        let tool_name = match self.response_type.as_str() {
            "command" => "command",
            _ => "chat",
        };
        let mut raw_content = match self.response_type.as_str() {
            "command" => format!("Command prefilled: {}", self.response),
            _ => self.response.clone(),
        };
        if let Some(code) = &self.result_exit_code {
            let result_text = match &self.result_output_snippet {
                Some(output) => format!("\nUser executed. Exit {code}. Output:\n{output}"),
                None => format!("\nUser executed. Exit {code}."),
            };
            raw_content.push_str(&result_text);
        }
        let content = format!("<tool_result name=\"{tool_name}\">\n{raw_content}\n</tool_result>");
        Message {
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: tool_id.to_string(),
                content,
                is_error: false,
            }],
        }
    }
}

fn gethostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Db {
        Db::open_in_memory().expect("in-memory db")
    }

    #[test]
    fn test_create_and_end_session() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.end_session("s1").unwrap();

        let ended_at: Option<String> = db
            .conn
            .query_row(
                "SELECT ended_at FROM sessions WHERE id = ?",
                params!["s1"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            ended_at.is_some(),
            "ended_at should be set after end_session"
        );
    }

    #[test]
    fn test_insert_and_search_command() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo build --release",
            "/home/user/project",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db.search_history("cargo", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].cmd_highlight.contains("cargo"));
    }

    #[test]
    fn test_search_no_results() {
        let db = test_db();
        db.insert_command(
            "s1",
            "ls -la",
            "/tmp",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db.search_history("nonexistent_term_xyz", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_insert_and_get_conversations() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_conversation(
            "s1",
            "first query",
            "chat",
            "first response",
            None,
            false,
            false,
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        db.insert_conversation(
            "s1",
            "second query",
            "command",
            "ls -la",
            Some("list files"),
            false,
            false,
        )
        .unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 2);
        assert_eq!(convos[0].query, "first query");
        assert_eq!(convos[1].query, "second query");
        assert_eq!(convos[1].response, "ls -la");
        assert_eq!(convos[1].explanation.as_deref(), Some("list files"));
    }

    #[test]
    fn test_clear_conversations() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.insert_conversation("s1", "query", "chat", "response", None, false, false)
            .unwrap();

        db.clear_conversations("s1").unwrap();
        let convos = db.get_conversations("s1", 10).unwrap();
        assert!(convos.is_empty());
    }

    #[test]
    fn test_prune_old_commands() {
        let db = test_db();
        db.insert_command(
            "s1",
            "old command",
            "/tmp",
            Some(0),
            "2020-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "recent command",
            "/tmp",
            Some(0),
            "2099-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let deleted = db.prune(30).unwrap();
        assert_eq!(deleted, 1, "should delete 1 old command");

        let results = db.search_history("recent", 10).unwrap();
        assert_eq!(results.len(), 1);
        let old = db.search_history("old", 10).unwrap();
        assert!(old.is_empty());
    }

    #[test]
    fn test_recent_commands_other_sessions() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 100).unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 200).unwrap();

        db.insert_command(
            "s1",
            "cmd_in_s1",
            "/tmp",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "/dev/pts/0",
            "zsh",
            100,
        )
        .unwrap();
        db.insert_command(
            "s2",
            "cmd_in_s2",
            "/home",
            Some(0),
            "2025-01-01T00:00:01Z",
            None,
            None,
            "/dev/pts/1",
            "bash",
            200,
        )
        .unwrap();

        let other = db.recent_commands_other_sessions("s1", 10).unwrap();
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].command, "cmd_in_s2");
        assert_eq!(other[0].tty, "/dev/pts/1");
    }

    #[test]
    fn test_orphaned_session_cleanup() {
        let db = test_db();
        // Use a PID that almost certainly doesn't exist
        let dead_pid: i64 = 2_000_000_000;
        db.create_session("orphan1", "/dev/pts/9", "zsh", dead_pid)
            .unwrap();

        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert!(cleaned >= 1, "should clean up at least 1 orphaned session");

        let ended_at: Option<String> = db
            .conn
            .query_row(
                "SELECT ended_at FROM sessions WHERE id = ?",
                params!["orphan1"],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            ended_at.is_some(),
            "Orphaned session should have ended_at set after cleanup"
        );
    }

    #[test]
    fn test_fts5_rebuild() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo test",
            "/project",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "git push origin main",
            "/project",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        // Rebuild the FTS index
        db.rebuild_fts().unwrap();

        // Verify search still works after rebuild
        let results = db.search_history("cargo", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("cargo test"));

        let results = db.search_history("git", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("git push"));
    }

    #[test]
    fn test_output_truncation_over_max_bytes() {
        let db = test_db();
        // max_output_bytes defaults to 32768 in open_in_memory
        let large_output = "x".repeat(50_000);
        db.insert_command(
            "s1",
            "big_cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some(&large_output),
            "",
            "",
            0,
        )
        .unwrap();

        let stored: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE command = 'big_cmd'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let stored = stored.expect("output should be stored");
        assert!(
            stored.len() < large_output.len(),
            "stored output ({} bytes) should be truncated below original ({} bytes)",
            stored.len(),
            large_output.len()
        );
        assert!(
            stored.contains("[truncated by nsh]"),
            "truncated output should contain truncation marker"
        );
    }

    #[test]
    fn test_deduplication_via_insert() {
        let db = test_db();
        let session = "dedup_s1";
        let cmd = "echo dedup_test";
        let ts = "2025-06-01T12:00:00Z";

        // Insert the same command twice with the same timestamp
        let id1 = db
            .insert_command(session, cmd, "/tmp", Some(0), ts, None, None, "", "", 0)
            .unwrap();
        let id2 = db
            .insert_command(session, cmd, "/tmp", Some(0), ts, None, None, "", "", 0)
            .unwrap();

        // Both inserts succeed (DB doesn't deduplicate — shell hooks do)
        // but we verify the dedup guard exists in shell scripts
        assert_ne!(
            id1, id2,
            "DB assigns different IDs (dedup is in shell hooks)"
        );

        // Verify the shell dedup guard exists
        let zsh_script = include_str!("../shell/nsh.zsh");
        assert!(
            zsh_script.contains("__NSH_LAST_RECORDED_CMD"),
            "Zsh script should have deduplication guard variable"
        );
        assert!(
            zsh_script.contains("__NSH_LAST_RECORDED_START"),
            "Zsh script should have deduplication guard for timestamps"
        );

        let bash_script = include_str!("../shell/nsh.bash");
        assert!(
            bash_script.contains("__nsh_last_recorded_cmd"),
            "Bash script should have deduplication guard variable"
        );
        assert!(
            bash_script.contains("__nsh_last_recorded_start"),
            "Bash script should have deduplication guard for timestamps"
        );
    }

    #[test]
    fn test_regexp_function() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo test --release",
            "/project",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "git push origin main",
            "/project",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                None,
                Some("cargo.*release"),
                None,
                None,
                None,
                false,
                None,
                None,
                10,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("cargo test"));
    }

    #[test]
    fn test_summary_lifecycle() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo build",
            "/project",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("Compiling nsh v0.1.0\nFinished in 5.2s"),
            "",
            "",
            0,
        )
        .unwrap();

        let needing = db.commands_needing_summary(5).unwrap();
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0].command, "cargo build");

        let updated = db
            .update_summary(needing[0].id, "Built nsh successfully in 5.2s")
            .unwrap();
        assert!(updated);

        let needing_after = db.commands_needing_summary(5).unwrap();
        assert!(needing_after.is_empty());
    }

    #[test]
    fn test_search_history_advanced_with_since_until() {
        let db = test_db();
        db.insert_command(
            "s1", "early cmd", "/tmp", Some(0),
            "2025-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "middle cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "late cmd", "/tmp", Some(0),
            "2025-12-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            None, None,
            Some("2025-03-01T00:00:00Z"),
            Some("2025-09-01T00:00:00Z"),
            None, false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("middle"));
    }

    #[test]
    fn test_search_history_advanced_failed_only() {
        let db = test_db();
        db.insert_command(
            "s1", "good cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "bad cmd", "/tmp", Some(1),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            None, None, None, None, None, true, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("bad"));
        assert_eq!(results[0].exit_code, Some(1));
    }

    #[test]
    fn test_search_history_advanced_session_filter() {
        let db = test_db();
        db.insert_command(
            "sess_a", "cmd alpha", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "sess_b", "cmd beta", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            None, None, None, None, None, false,
            Some("sess_a"), None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("alpha"));
    }

    #[test]
    fn test_search_history_advanced_exit_code_filter() {
        let db = test_db();
        db.insert_command(
            "s1", "exit zero", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "exit two", "/tmp", Some(2),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "exit one", "/tmp", Some(1),
            "2025-06-01T00:02:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            None, None, None, None, Some(2), false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("exit two"));
    }

    #[test]
    fn test_pending_conversation_flow() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let conv_id = db.insert_conversation(
            "s1", "run tests", "command", "cargo test",
            Some("runs the test suite"), false, true,
        ).unwrap();
        assert!(conv_id > 0);

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_some());
        let (id, response) = pending.unwrap();
        assert_eq!(id, conv_id);
        assert_eq!(response, "cargo test");

        db.update_conversation_result(conv_id, 0, Some("all tests passed")).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].result_exit_code, Some(0));
        assert_eq!(convos[0].result_output_snippet.as_deref(), Some("all tests passed"));
    }

    #[test]
    fn test_insert_usage_and_get_usage_stats() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage(
            "s1", Some("hello"), "gpt-4", "openai",
            Some(100), Some(50), Some(0.01), None,
        ).unwrap();
        db.insert_usage(
            "s1", Some("world"), "gpt-4", "openai",
            Some(200), Some(100), Some(0.02), None,
        ).unwrap();

        let stats = db.get_usage_stats(None).unwrap();
        assert_eq!(stats.len(), 1);
        let (model, calls, input_tok, output_tok, cost) = &stats[0];
        assert_eq!(model, "gpt-4");
        assert_eq!(*calls, 2);
        assert_eq!(*input_tok, 300);
        assert_eq!(*output_tok, 150);
        assert!((cost - 0.03).abs() < 1e-9);
    }

    #[test]
    fn test_update_usage_cost() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage(
            "s1", Some("q"), "claude", "anthropic",
            Some(50), Some(25), None, Some("gen_abc"),
        ).unwrap();

        let updated = db.update_usage_cost("gen_abc", 0.05).unwrap();
        assert!(updated);

        let stats = db.get_usage_stats(None).unwrap();
        assert_eq!(stats.len(), 1);
        let (_, _, _, _, cost) = &stats[0];
        assert!((cost - 0.05).abs() < 1e-9);
    }

    #[test]
    fn test_get_pending_generation_ids() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage(
            "s1", Some("q"), "gpt-4", "openai",
            Some(10), Some(5), None, Some("gen_123"),
        ).unwrap();
        db.insert_usage(
            "s1", Some("q2"), "gpt-4", "openai",
            Some(10), Some(5), Some(0.01), Some("gen_456"),
        ).unwrap();

        let pending = db.get_pending_generation_ids().unwrap();
        assert!(pending.contains(&"gen_123".to_string()));
        assert!(!pending.contains(&"gen_456".to_string()));
    }

    #[test]
    fn test_update_command_output() {
        let db = test_db();
        let id = db.insert_command(
            "s1", "my cmd", "/tmp", None,
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let updated = db.update_command(id, Some(42), Some("some output")).unwrap();
        assert!(updated);

        let (exit_code, output): (Option<i32>, Option<String>) = db
            .conn
            .query_row(
                "SELECT exit_code, output FROM commands WHERE id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(exit_code, Some(42));
        assert_eq!(output.as_deref(), Some("some output"));
    }

    #[test]
    fn test_prune_if_due() {
        let db = test_db();
        db.insert_command(
            "s1", "old prunable", "/tmp", Some(0),
            "2020-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        db.prune_if_due(30).unwrap();

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_get_conversations_limit() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        for i in 0..5 {
            db.insert_conversation(
                "s1", &format!("query{i}"), "chat", &format!("resp{i}"),
                None, false, false,
            ).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let convos = db.get_conversations("s1", 3).unwrap();
        assert_eq!(convos.len(), 3);
        assert_eq!(convos[0].query, "query2");
        assert_eq!(convos[2].query, "query4");
    }

    #[test]
    fn test_get_conversations_empty_session() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        let convos = db.get_conversations("s1", 10).unwrap();
        assert!(convos.is_empty());
    }

    #[test]
    fn test_recent_commands_with_summaries() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db.insert_command(
            "s1", "cargo build", "/project", Some(0),
            "2025-06-01T00:00:00Z", Some(5200), Some("Compiled OK"), "", "", 0,
        ).unwrap();
        db.update_summary(id, "Built project successfully").unwrap();

        db.insert_command(
            "s1", "cargo test", "/project", Some(1),
            "2025-06-01T00:01:00Z", Some(3000), None, "", "", 0,
        ).unwrap();

        let cmds = db.recent_commands_with_summaries("s1", 10).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].command, "cargo build");
        assert_eq!(cmds[0].summary.as_deref(), Some("Built project successfully"));
        assert_eq!(cmds[0].duration_ms, Some(5200));
        assert_eq!(cmds[1].command, "cargo test");
        assert!(cmds[1].summary.is_none());
    }

    #[test]
    fn test_recent_commands_with_summaries_other_session_excluded() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 5678).unwrap();

        db.insert_command(
            "s1", "cmd_s1", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s2", "cmd_s2", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let cmds = db.recent_commands_with_summaries("s1", 10).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "cmd_s1");
    }

    #[test]
    fn test_other_sessions_with_summaries() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 5678).unwrap();

        db.insert_command(
            "s1", "cmd_mine", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "/dev/pts/0", "zsh", 1234,
        ).unwrap();
        db.insert_command(
            "s2", "cmd_other", "/home", Some(0),
            "2025-06-01T00:01:00Z", None, None, "/dev/pts/1", "bash", 5678,
        ).unwrap();

        let others = db.other_sessions_with_summaries("s1", 5, 5).unwrap();
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].command, "cmd_other");
        assert_eq!(others[0].tty, "/dev/pts/1");
        assert_eq!(others[0].shell, "bash");
    }

    #[test]
    fn test_search_history_fts() {
        let db = test_db();
        db.insert_command(
            "s1", "docker compose up", "/app", Some(0),
            "2025-06-01T00:00:00Z", None,
            Some("Starting containers... done"), "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "git log --oneline", "/app", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history("docker", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("docker"));

        let results = db.search_history("containers", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("docker"));
    }

    #[test]
    fn test_search_history_fts_with_advanced() {
        let db = test_db();
        db.insert_command(
            "s1", "make build", "/project", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "make test", "/project", Some(1),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("make"), None, None, None, None, true, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("make test"));
    }

    #[test]
    fn test_session_end_and_heartbeat() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.update_heartbeat("s1").unwrap();
        let hb: Option<String> = db.conn.query_row(
            "SELECT last_heartbeat FROM sessions WHERE id = 's1'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(hb.is_some());

        let ended: Option<String> = db.conn.query_row(
            "SELECT ended_at FROM sessions WHERE id = 's1'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(ended.is_none());

        db.end_session("s1").unwrap();
        let ended: Option<String> = db.conn.query_row(
            "SELECT ended_at FROM sessions WHERE id = 's1'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(ended.is_some());
    }

    #[test]
    fn test_prune_keeps_recent() {
        let db = test_db();
        db.insert_command(
            "s1", "ancient", "/tmp", Some(0),
            "2015-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "recent", "/tmp", Some(0),
            "2099-12-31T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let deleted = db.prune(365).unwrap();
        assert_eq!(deleted, 1);

        let count: i64 = db.conn.query_row(
            "SELECT COUNT(*) FROM commands", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        let results = db.search_history("recent", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_commands_needing_summary_excludes_no_output() {
        let db = test_db();
        db.insert_command(
            "s1", "no output cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert!(needing.is_empty());
    }

    #[test]
    fn test_commands_needing_summary_excludes_already_summarized() {
        let db = test_db();
        let id = db.insert_command(
            "s1", "summarized cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, Some("output text"), "", "", 0,
        ).unwrap();
        db.update_summary(id, "already done").unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert!(needing.is_empty());
    }

    #[test]
    fn test_mark_unsummarized_for_llm_and_needing_llm() {
        let db = test_db();
        db.insert_command(
            "s1", "cmd1", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, Some("output1"), "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "cmd2", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None, Some("output2"), "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "cmd3", "/tmp", Some(0),
            "2025-06-01T00:02:00Z", None, None, "", "", 0,
        ).unwrap();

        let marked = db.mark_unsummarized_for_llm().unwrap();
        assert_eq!(marked, 2);

        let needing = db.commands_needing_summary(10).unwrap();
        assert!(needing.is_empty());

        let needing_llm = db.commands_needing_llm_summary(10).unwrap();
        assert_eq!(needing_llm.len(), 2);
    }

    #[test]
    fn test_mark_summary_error() {
        let db = test_db();
        let id = db.insert_command(
            "s1", "failing cmd", "/tmp", Some(1),
            "2025-06-01T00:00:00Z", None, Some("error output"), "", "", 0,
        ).unwrap();

        db.mark_summary_error(id, "API timeout").unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert!(needing.is_empty());

        let summary: Option<String> = db.conn.query_row(
            "SELECT summary FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        assert!(summary.unwrap().contains("[error: API timeout]"));
    }

    #[test]
    fn test_update_conversation_result_thorough() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id1 = db.insert_conversation(
            "s1", "deploy", "command", "kubectl apply -f deploy.yaml",
            Some("deploy to k8s"), false, false,
        ).unwrap();
        let id2 = db.insert_conversation(
            "s1", "check status", "command", "kubectl get pods",
            None, false, false,
        ).unwrap();

        db.update_conversation_result(id1, 0, Some("deployment created")).unwrap();
        db.update_conversation_result(id2, 1, None).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 2);
        assert_eq!(convos[0].result_exit_code, Some(0));
        assert_eq!(convos[0].result_output_snippet.as_deref(), Some("deployment created"));
        assert_eq!(convos[1].result_exit_code, Some(1));
        assert!(convos[1].result_output_snippet.is_none());
    }

    #[test]
    fn test_find_pending_conversation_none() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn test_find_pending_conversation_ignores_chat() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_conversation(
            "s1", "what is rust", "chat", "Rust is a systems language",
            None, false, false,
        ).unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn test_find_pending_conversation_ignores_completed() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let conv_id = db.insert_conversation(
            "s1", "build", "command", "cargo build",
            None, false, false,
        ).unwrap();
        db.update_conversation_result(conv_id, 0, None).unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn test_insert_usage() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db.insert_usage(
            "s1", Some("hello world"), "claude-3-opus", "anthropic",
            Some(500), Some(200), Some(0.10), Some("gen_xyz"),
        ).unwrap();
        assert!(id > 0);

        let id2 = db.insert_usage(
            "s1", None, "gpt-4o", "openai",
            None, None, None, None,
        ).unwrap();
        assert!(id2 > id);

        let stats = db.get_usage_stats(None).unwrap();
        assert_eq!(stats.len(), 2);
    }

    #[test]
    fn test_session_label() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let label = db.get_session_label("s1").unwrap();
        assert!(label.is_none());

        let ok = db.set_session_label("s1", "dev-work").unwrap();
        assert!(ok);

        let label = db.get_session_label("s1").unwrap();
        assert_eq!(label.as_deref(), Some("dev-work"));

        let ok = db.set_session_label("nonexistent", "label").unwrap();
        assert!(!ok);
    }

    #[test]
    fn test_get_session_label_nonexistent() {
        let db = test_db();
        let label = db.get_session_label("no_such_session").unwrap();
        assert!(label.is_none());
    }

    #[test]
    fn test_optimize_and_integrity() {
        let db = test_db();
        db.insert_command(
            "s1", "test cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        db.optimize_fts().unwrap();
        db.check_fts_integrity().unwrap();
    }

    #[test]
    fn test_search_history_advanced_current_session_alias() {
        let db = test_db();
        db.insert_command(
            "my_sess", "cmd here", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "other_sess", "cmd there", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            None, None, None, None, None, false,
            Some("current"), Some("my_sess"), 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("cmd here"));
    }

    #[test]
    fn test_update_command() {
        let db = test_db();
        let id = db.insert_command(
            "s1", "running cmd", "/tmp", None,
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let updated = db.update_command(id, Some(0), Some("all good")).unwrap();
        assert!(updated);

        let updated_again = db.update_command(id, None, Some("extra output")).unwrap();
        assert!(updated_again);

        let (code, out): (Option<i32>, Option<String>) = db.conn.query_row(
            "SELECT exit_code, output FROM commands WHERE id = ?",
            params![id], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(code, Some(0));
        assert_eq!(out.as_deref(), Some("extra output"));
    }

    #[test]
    fn test_update_command_nonexistent() {
        let db = test_db();
        let updated = db.update_command(999999, Some(1), None).unwrap();
        assert!(!updated);
    }

    #[test]
    fn test_clear_conversations_idempotent() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.clear_conversations("s1").unwrap();
        db.clear_conversations("s1").unwrap();
        let convos = db.get_conversations("s1", 10).unwrap();
        assert!(convos.is_empty());
    }

    #[test]
    fn test_update_summary_idempotent() {
        let db = test_db();
        let id = db.insert_command(
            "s1", "cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, Some("output"), "", "", 0,
        ).unwrap();

        let first = db.update_summary(id, "summary v1").unwrap();
        assert!(first);

        let second = db.update_summary(id, "summary v2").unwrap();
        assert!(!second);

        let summary: Option<String> = db.conn.query_row(
            "SELECT summary FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        assert_eq!(summary.as_deref(), Some("summary v1"));
    }

    #[test]
    fn test_prune_also_removes_ended_sessions() {
        let db = test_db();
        db.create_session("old_sess", "/dev/pts/0", "zsh", 1234).unwrap();
        db.conn.execute(
            "UPDATE sessions SET ended_at = '2015-01-01T00:00:00Z' WHERE id = 'old_sess'",
            [],
        ).unwrap();

        db.prune(30).unwrap();

        let count: i64 = db.conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = 'old_sess'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_search_history_advanced_fts_with_regex_filter() {
        let db = test_db();
        db.insert_command(
            "s1", "cargo build --release", "/project", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "cargo test --release", "/project", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("cargo"), Some("test"), None, None, None, false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("cargo test"));
    }

    #[test]
    fn test_conversations_across_sessions_isolated() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 5678).unwrap();

        db.insert_conversation("s1", "q1", "chat", "r1", None, false, false).unwrap();
        db.insert_conversation("s2", "q2", "chat", "r2", None, false, false).unwrap();

        let c1 = db.get_conversations("s1", 10).unwrap();
        let c2 = db.get_conversations("s2", 10).unwrap();
        assert_eq!(c1.len(), 1);
        assert_eq!(c2.len(), 1);
        assert_eq!(c1[0].query, "q1");
        assert_eq!(c2[0].query, "q2");
    }

    #[test]
    fn test_search_history_multiple_results_ordered_by_relevance() {
        let db = test_db();
        db.insert_command(
            "s1", "cargo build", "/project", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "cargo test", "/project", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "cargo bench", "/project", Some(0),
            "2025-06-01T00:02:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history("cargo", 10).unwrap();
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.cmd_highlight.contains("cargo"));
        }
    }

    #[test]
    fn test_search_history_respects_limit() {
        let db = test_db();
        for i in 0..10 {
            db.insert_command(
                "s1", &format!("grep pattern{i}"), "/tmp", Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"), None, None, "", "", 0,
            ).unwrap();
        }

        let results = db.search_history("grep", 3).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_history_matches_output() {
        let db = test_db();
        db.insert_command(
            "s1", "run_script", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None,
            Some("unique_sentinel_output_value"), "", "", 0,
        ).unwrap();

        let results = db.search_history("unique_sentinel_output_value", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "run_script");
    }

    #[test]
    fn test_search_history_matches_summary_via_fts() {
        let db = test_db();
        let id = db.insert_command(
            "s1", "make deploy", "/app", Some(0),
            "2025-06-01T00:00:00Z", None, Some("deploying..."), "", "", 0,
        ).unwrap();
        db.update_summary(id, "deployed application to production kubernetes cluster").unwrap();

        let results = db.search_history("kubernetes", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "make deploy");
    }

    #[test]
    fn test_search_history_matches_cwd() {
        let db = test_db();
        db.insert_command(
            "s1", "ls", "/unique/searchable/directory", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history("searchable", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_init_db_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn, 10000).unwrap();
        init_db(&conn, 10000).unwrap();

        let version: String = conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_string());

        conn.execute(
            "INSERT INTO sessions (id, tty, shell, pid, started_at) VALUES ('x', 'tty', 'zsh', 1, '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO commands (session_id, command, started_at) VALUES ('x', 'echo hi', '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM commands_fts WHERE commands_fts MATCH 'echo'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_command_with_none_values() {
        let db = test_db();
        let id = db.insert_command(
            "s1", "echo hello", "/tmp",
            None, "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        assert!(id > 0);

        let (exit_code, duration, output): (Option<i32>, Option<i64>, Option<String>) =
            db.conn.query_row(
                "SELECT exit_code, duration_ms, output FROM commands WHERE id = ?",
                params![id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).unwrap();
        assert!(exit_code.is_none());
        assert!(duration.is_none());
        assert!(output.is_none());
    }

    #[test]
    fn test_insert_command_with_very_long_command() {
        let db = test_db();
        let long_cmd = "x".repeat(100_000);
        let id = db.insert_command(
            "s1", &long_cmd, "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        assert!(id > 0);

        let stored: String = db.conn.query_row(
            "SELECT command FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        assert_eq!(stored.len(), 100_000);
    }

    #[test]
    fn test_insert_command_with_unicode_output() {
        let db = test_db();
        let unicode_output = "日本語テスト 🦀 émojis résumé café";
        let id = db.insert_command(
            "s1", "echo intl", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, Some(unicode_output), "", "", 0,
        ).unwrap();

        let stored: Option<String> = db.conn.query_row(
            "SELECT output FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        assert_eq!(stored.as_deref(), Some(unicode_output));
    }

    #[test]
    fn test_insert_command_truncation_at_multibyte_boundary() {
        let db = Db {
            conn: Connection::open_in_memory().unwrap(),
            max_output_bytes: 10,
        };
        init_db(&db.conn, 10000).unwrap();

        let output = "aaaa日本語bbb";
        let id = db.insert_command(
            "s1", "cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, Some(output), "", "", 0,
        ).unwrap();

        let stored: Option<String> = db.conn.query_row(
            "SELECT output FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        let stored = stored.unwrap();
        assert!(stored.contains("[truncated by nsh]"));
        assert!(stored.is_char_boundary(0));
    }

    #[test]
    fn test_insert_usage_all_fields() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db.insert_usage(
            "s1",
            Some("translate this code"),
            "claude-3.5-sonnet",
            "anthropic",
            Some(1500),
            Some(800),
            Some(0.0234),
            Some("gen_full_test_123"),
        ).unwrap();
        assert!(id > 0);

        let (model, provider, input, output, cost, gen_id, query): (
            String, String, Option<u32>, Option<u32>, Option<f64>, Option<String>, Option<String>,
        ) = db.conn.query_row(
            "SELECT model, provider, input_tokens, output_tokens, cost_usd, generation_id, query_text FROM usage WHERE id = ?",
            params![id], |row| Ok((
                row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                row.get(4)?, row.get(5)?, row.get(6)?,
            )),
        ).unwrap();
        assert_eq!(model, "claude-3.5-sonnet");
        assert_eq!(provider, "anthropic");
        assert_eq!(input, Some(1500));
        assert_eq!(output, Some(800));
        assert!((cost.unwrap() - 0.0234).abs() < 1e-9);
        assert_eq!(gen_id.as_deref(), Some("gen_full_test_123"));
        assert_eq!(query.as_deref(), Some("translate this code"));
    }

    #[test]
    fn test_recent_commands_with_summaries_chronological_order() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id1 = db.insert_command(
            "s1", "first", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", Some(100), Some("out1"), "", "", 0,
        ).unwrap();
        db.update_summary(id1, "summary for first").unwrap();

        let id2 = db.insert_command(
            "s1", "second", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", Some(200), Some("out2"), "", "", 0,
        ).unwrap();
        db.update_summary(id2, "summary for second").unwrap();

        let id3 = db.insert_command(
            "s1", "third", "/tmp", Some(1),
            "2025-06-01T00:02:00Z", None, None, "", "", 0,
        ).unwrap();
        let _ = id3;

        let cmds = db.recent_commands_with_summaries("s1", 10).unwrap();
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].command, "first");
        assert_eq!(cmds[0].summary.as_deref(), Some("summary for first"));
        assert_eq!(cmds[0].duration_ms, Some(100));
        assert_eq!(cmds[1].command, "second");
        assert_eq!(cmds[1].summary.as_deref(), Some("summary for second"));
        assert_eq!(cmds[2].command, "third");
        assert!(cmds[2].summary.is_none());
        assert_eq!(cmds[2].exit_code, Some(1));
    }

    #[test]
    fn test_other_sessions_with_summaries_multiple_sessions() {
        let db = test_db();
        db.create_session("me", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("other1", "/dev/pts/1", "bash", 5678).unwrap();
        db.create_session("other2", "/dev/pts/2", "fish", 9012).unwrap();

        db.insert_command(
            "me", "my_cmd", "/home", Some(0),
            "2025-06-01T00:00:00Z", None, None, "/dev/pts/0", "zsh", 1234,
        ).unwrap();

        let id1 = db.insert_command(
            "other1", "their_cmd_1", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None, Some("output1"), "/dev/pts/1", "bash", 5678,
        ).unwrap();
        db.update_summary(id1, "summary for other1").unwrap();

        db.insert_command(
            "other2", "their_cmd_2", "/var", Some(1),
            "2025-06-01T00:02:00Z", None, None, "/dev/pts/2", "fish", 9012,
        ).unwrap();

        let others = db.other_sessions_with_summaries("me", 5, 5).unwrap();
        assert_eq!(others.len(), 2);
        assert_eq!(others[0].command, "their_cmd_2");
        assert_eq!(others[0].tty, "/dev/pts/2");
        assert_eq!(others[0].shell, "fish");
        assert!(others[0].summary.is_none());
        assert_eq!(others[1].command, "their_cmd_1");
        assert_eq!(others[1].summary.as_deref(), Some("summary for other1"));
    }

    #[test]
    fn test_other_sessions_excludes_ended() {
        let db = test_db();
        db.create_session("me", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("ended", "/dev/pts/1", "bash", 5678).unwrap();
        db.end_session("ended").unwrap();

        db.insert_command(
            "ended", "ended_cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "/dev/pts/1", "bash", 5678,
        ).unwrap();

        let others = db.other_sessions_with_summaries("me", 5, 5).unwrap();
        assert!(others.is_empty());
    }

    #[test]
    fn test_conversation_full_lifecycle() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id1 = db.insert_conversation(
            "s1", "how do I list files", "chat", "Use ls -la to list files",
            None, false, false,
        ).unwrap();

        let id2 = db.insert_conversation(
            "s1", "list files", "command", "ls -la",
            Some("lists all files including hidden"), false, true,
        ).unwrap();

        assert!(id2 > id1);

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_some());
        let (pid, resp) = pending.unwrap();
        assert_eq!(pid, id2);
        assert_eq!(resp, "ls -la");

        db.update_conversation_result(id2, 0, Some("total 42\ndrwxr-xr-x")).unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_none());

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 2);
        assert_eq!(convos[0].response_type, "chat");
        assert!(convos[0].result_exit_code.is_none());
        assert_eq!(convos[1].response_type, "command");
        assert_eq!(convos[1].result_exit_code, Some(0));
        assert_eq!(convos[1].explanation.as_deref(), Some("lists all files including hidden"));

        db.clear_conversations("s1").unwrap();
        let convos = db.get_conversations("s1", 10).unwrap();
        assert!(convos.is_empty());
    }

    #[test]
    fn test_insert_command_creates_session_on_conflict() {
        let db = test_db();
        db.insert_command(
            "auto_sess", "echo hello", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "/dev/pts/5", "zsh", 999,
        ).unwrap();

        let tty: String = db.conn.query_row(
            "SELECT tty FROM sessions WHERE id = 'auto_sess'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(tty, "/dev/pts/5");

        db.insert_command(
            "auto_sess", "echo world", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None, None, "/dev/pts/6", "bash", 1000,
        ).unwrap();

        let tty: String = db.conn.query_row(
            "SELECT tty FROM sessions WHERE id = 'auto_sess'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(tty, "/dev/pts/6");
    }

    #[test]
    fn test_search_history_empty_db() {
        let db = test_db();
        let results = db.search_history("anything", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_update_heartbeat_updates_timestamp() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let hb1: Option<String> = db.conn.query_row(
            "SELECT last_heartbeat FROM sessions WHERE id = 's1'",
            [], |row| row.get(0),
        ).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        db.update_heartbeat("s1").unwrap();

        let hb2: Option<String> = db.conn.query_row(
            "SELECT last_heartbeat FROM sessions WHERE id = 's1'",
            [], |row| row.get(0),
        ).unwrap();

        assert!(hb1.is_some());
        assert!(hb2.is_some());
        assert!(hb2.unwrap() > hb1.unwrap());
    }

    #[test]
    fn test_commands_needing_summary_respects_limit() {
        let db = test_db();
        for i in 0..5 {
            db.insert_command(
                "s1", &format!("cmd{i}"), "/tmp", Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"), None,
                Some(&format!("output{i}")), "", "", 0,
            ).unwrap();
        }

        let needing = db.commands_needing_summary(2).unwrap();
        assert_eq!(needing.len(), 2);
    }

    #[test]
    fn test_create_session_ignore_duplicate() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let count: i64 = db.conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = 's1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_command_with_all_fields() {
        let db = test_db();
        let id = db.insert_command(
            "s1", "cargo test --release", "/home/user/project",
            Some(0), "2025-06-01T12:30:00Z", Some(45000),
            Some("running 42 tests\ntest result: ok"), "/dev/pts/3", "zsh", 5555,
        ).unwrap();

        let (cmd, cwd, exit_code, duration, output): (
            String, Option<String>, Option<i32>, Option<i64>, Option<String>,
        ) = db.conn.query_row(
            "SELECT command, cwd, exit_code, duration_ms, output FROM commands WHERE id = ?",
            params![id], |row| Ok((
                row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
            )),
        ).unwrap();
        assert_eq!(cmd, "cargo test --release");
        assert_eq!(cwd.as_deref(), Some("/home/user/project"));
        assert_eq!(exit_code, Some(0));
        assert_eq!(duration, Some(45000));
        assert!(output.unwrap().contains("running 42 tests"));
    }

    #[test]
    fn test_search_history_advanced_regex_only_no_fts() {
        let db = test_db();
        db.insert_command(
            "s1", "curl https://api.example.com/v1/users", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "wget https://api.example.com/v2/data", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            None, Some(r"https://api\.example\.com/v1"), None, None,
            None, false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("curl"));
    }

    #[test]
    fn test_prune_cleans_fts_index() {
        let db = test_db();
        db.insert_command(
            "s1", "old_prunable_unique_cmd", "/tmp", Some(0),
            "2020-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let before = db.search_history("old_prunable_unique_cmd", 10).unwrap();
        assert_eq!(before.len(), 1);

        db.prune(30).unwrap();

        let after = db.search_history("old_prunable_unique_cmd", 10).unwrap();
        assert!(after.is_empty());
    }

    #[test]
    fn test_update_usage_cost_nonexistent() {
        let db = test_db();
        let updated = db.update_usage_cost("nonexistent_gen_id", 1.0).unwrap();
        assert!(!updated);
    }

    #[test]
    fn test_cleanup_orphaned_sessions_skips_zero_pid() {
        let db = test_db();
        db.conn
            .execute(
                "INSERT INTO sessions (id, tty, shell, pid, started_at) \
                 VALUES ('zero_pid', '/dev/pts/0', 'zsh', 0, '2025-01-01T00:00:00Z')",
                [],
            )
            .unwrap();

        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert_eq!(cleaned, 0, "should skip sessions with pid <= 0");

        let ended_at: Option<String> = db
            .conn
            .query_row(
                "SELECT ended_at FROM sessions WHERE id = 'zero_pid'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(ended_at.is_none());
    }

    #[test]
    fn test_cleanup_orphaned_sessions_skips_negative_pid() {
        let db = test_db();
        db.conn
            .execute(
                "INSERT INTO sessions (id, tty, shell, pid, started_at) \
                 VALUES ('neg_pid', '/dev/pts/0', 'zsh', -1, '2025-01-01T00:00:00Z')",
                [],
            )
            .unwrap();

        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert_eq!(cleaned, 0);
    }

    #[test]
    fn test_get_usage_stats_with_since_filter() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage(
            "s1", Some("old query"), "gpt-4", "openai",
            Some(100), Some(50), Some(0.01), None,
        ).unwrap();
        db.insert_usage(
            "s1", Some("new query"), "gpt-4", "openai",
            Some(200), Some(100), Some(0.02), None,
        ).unwrap();

        let stats = db.get_usage_stats(Some("datetime('now', '-1 hour')")).unwrap();
        assert_eq!(stats.len(), 1);
        let (model, calls, _, _, _) = &stats[0];
        assert_eq!(model, "gpt-4");
        assert_eq!(*calls, 2);
    }

    #[test]
    fn test_search_history_advanced_fts_with_since() {
        let db = test_db();
        db.insert_command(
            "s1", "early cargo build", "/tmp", Some(0),
            "2020-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "late cargo test", "/tmp", Some(0),
            "2099-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("cargo"), None,
            Some("2025-01-01T00:00:00Z"), None,
            None, false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("late"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_until() {
        let db = test_db();
        db.insert_command(
            "s1", "early cargo build", "/tmp", Some(0),
            "2020-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "late cargo test", "/tmp", Some(0),
            "2099-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("cargo"), None,
            None, Some("2025-01-01T00:00:00Z"),
            None, false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("early"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_exit_code() {
        let db = test_db();
        db.insert_command(
            "s1", "cargo build ok", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "cargo build fail", "/tmp", Some(1),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("cargo"), None, None, None,
            Some(1), false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("fail"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_session_filter() {
        let db = test_db();
        db.insert_command(
            "sess_x", "cargo run alpha", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "sess_y", "cargo run beta", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("cargo"), None, None, None,
            None, false, Some("sess_x"), None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("alpha"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_all_filters() {
        let db = test_db();
        db.insert_command(
            "s1", "npm test pass", "/app", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "npm test fail", "/app", Some(1),
            "2025-06-01T12:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s2", "npm test other", "/app", Some(1),
            "2025-06-01T12:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("npm"), None,
            Some("2025-06-01T06:00:00Z"),
            Some("2025-06-01T18:00:00Z"),
            Some(1), false, Some("s1"), None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("npm test fail"));
    }

    #[test]
    fn test_search_history_advanced_fts_failed_only() {
        let db = test_db();
        db.insert_command(
            "s1", "make build success", "/project", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "make build failure", "/project", Some(2),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("make"), None, None, None,
            None, true, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("failure"));
    }

    #[test]
    fn test_update_command_truncation() {
        let db = Db {
            conn: Connection::open_in_memory().unwrap(),
            max_output_bytes: 20,
        };
        init_db(&db.conn, 10000).unwrap();

        let id = db.insert_command(
            "s1", "cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let long_output = "a".repeat(100);
        let updated = db.update_command(id, None, Some(&long_output)).unwrap();
        assert!(updated);

        let stored: Option<String> = db.conn.query_row(
            "SELECT output FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        let stored = stored.unwrap();
        assert!(stored.contains("[truncated by nsh]"));
        assert!(stored.len() < long_output.len());
    }

    #[test]
    fn test_update_command_truncation_multibyte() {
        let db = Db {
            conn: Connection::open_in_memory().unwrap(),
            max_output_bytes: 8,
        };
        init_db(&db.conn, 10000).unwrap();

        let id = db.insert_command(
            "s1", "cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let output = "aaa日本語bbb";
        let updated = db.update_command(id, None, Some(output)).unwrap();
        assert!(updated);

        let stored: Option<String> = db.conn.query_row(
            "SELECT output FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        let stored = stored.unwrap();
        assert!(stored.contains("[truncated by nsh]"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_since_and_until() {
        let db = test_db();
        db.insert_command(
            "s1", "git commit early", "/repo", Some(0),
            "2025-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "git commit middle", "/repo", Some(0),
            "2025-06-15T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "git commit late", "/repo", Some(0),
            "2025-12-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("git"), None,
            Some("2025-03-01T00:00:00Z"),
            Some("2025-09-01T00:00:00Z"),
            None, false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("middle"));
    }

    #[test]
    fn test_search_history_advanced_fts_session_filter_literal() {
        let db = test_db();
        db.insert_command(
            "my_session", "docker build target", "/app", Some(0),
            "2025-06-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();
        db.insert_command(
            "other_session", "docker push target", "/app", Some(0),
            "2025-06-01T00:01:00Z", None, None, "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("docker"), None, None, None,
            None, false, Some("my_session"), None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("docker build"));
    }

    #[test]
    fn test_insert_command_output_truncation_boundary_exact() {
        let db = Db {
            conn: Connection::open_in_memory().unwrap(),
            max_output_bytes: 5,
        };
        init_db(&db.conn, 10000).unwrap();

        let output = "hello";
        let id = db.insert_command(
            "s1", "cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, Some(output), "", "", 0,
        ).unwrap();

        let stored: Option<String> = db.conn.query_row(
            "SELECT output FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        assert_eq!(stored.as_deref(), Some("hello"));
    }

    #[test]
    fn test_insert_command_output_truncation_one_over() {
        let db = Db {
            conn: Connection::open_in_memory().unwrap(),
            max_output_bytes: 5,
        };
        init_db(&db.conn, 10000).unwrap();

        let output = "hello!";
        let id = db.insert_command(
            "s1", "cmd", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None, Some(output), "", "", 0,
        ).unwrap();

        let stored: Option<String> = db.conn.query_row(
            "SELECT output FROM commands WHERE id = ?",
            params![id], |row| row.get(0),
        ).unwrap();
        let stored = stored.unwrap();
        assert!(stored.contains("[truncated by nsh]"));
        assert!(stored.starts_with("hello"));
    }

    #[test]
    fn test_prune_if_due_skips_when_recently_pruned() {
        let db = test_db();
        db.insert_command(
            "s1", "old cmd", "/tmp", Some(0),
            "2020-01-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        db.prune_if_due(30).unwrap();
        let count1: i64 = db.conn.query_row(
            "SELECT COUNT(*) FROM commands", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count1, 0);

        db.insert_command(
            "s1", "another old cmd", "/tmp", Some(0),
            "2020-02-01T00:00:00Z", None, None, "", "", 0,
        ).unwrap();

        db.prune_if_due(30).unwrap();
        let count2: i64 = db.conn.query_row(
            "SELECT COUNT(*) FROM commands", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count2, 1, "should NOT prune again since last_prune_at is recent");
    }

    #[test]
    fn test_recent_commands_with_summaries_limit() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        for i in 0..10 {
            db.insert_command(
                "s1", &format!("cmd_{i}"), "/tmp", Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"), None, None, "", "", 0,
            ).unwrap();
        }

        let cmds = db.recent_commands_with_summaries("s1", 3).unwrap();
        assert_eq!(cmds.len(), 3);
    }

    #[test]
    fn test_recent_commands_with_summaries_empty() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let cmds = db.recent_commands_with_summaries("s1", 10).unwrap();
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_get_usage_stats_empty() {
        let db = test_db();
        let stats = db.get_usage_stats(None).unwrap();
        assert!(stats.is_empty());
    }

    #[test]
    fn test_get_usage_stats_multiple_models() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage("s1", None, "gpt-4", "openai", Some(100), Some(50), Some(0.01), None).unwrap();
        db.insert_usage("s1", None, "claude", "anthropic", Some(200), Some(100), Some(0.05), None).unwrap();
        db.insert_usage("s1", None, "gpt-4", "openai", Some(150), Some(75), Some(0.02), None).unwrap();

        let stats = db.get_usage_stats(None).unwrap();
        assert_eq!(stats.len(), 2);
        let gpt4 = stats.iter().find(|(m, _, _, _, _)| m == "gpt-4").unwrap();
        assert_eq!(gpt4.1, 2);
        assert_eq!(gpt4.2, 250);
        assert_eq!(gpt4.3, 125);
    }

    #[test]
    fn test_search_history_advanced_fts_regex_filters_output() {
        let db = test_db();
        db.insert_command(
            "s1", "run script1", "/tmp", Some(0),
            "2025-06-01T00:00:00Z", None,
            Some("error: connection refused"), "", "", 0,
        ).unwrap();
        db.insert_command(
            "s1", "run script2", "/tmp", Some(0),
            "2025-06-01T00:01:00Z", None,
            Some("success: all good"), "", "", 0,
        ).unwrap();

        let results = db.search_history_advanced(
            Some("run"), Some("connection"), None, None,
            None, false, None, None, 100,
        ).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("script1"));
    }

    #[test]
    fn test_cleanup_orphaned_sessions_ignores_ended() {
        let db = test_db();
        db.create_session("ended_sess", "/dev/pts/0", "zsh", 2_000_000_000).unwrap();
        db.end_session("ended_sess").unwrap();

        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert_eq!(cleaned, 0, "ended sessions should not be counted");
    }

    #[test]
    fn test_conversation_exchange_to_user_message() {
        let exchange = ConversationExchange {
            query: "what is rust".to_string(),
            response_type: "chat".to_string(),
            response: "A systems language".to_string(),
            explanation: None,
            result_exit_code: None,
            result_output_snippet: None,
        };
        let msg = exchange.to_user_message();
        assert!(matches!(msg.role, crate::provider::Role::User));
        match &msg.content[0] {
            crate::provider::ContentBlock::Text { text } => {
                assert_eq!(text, "what is rust");
            }
            _ => panic!("expected Text content block"),
        }
    }

    #[test]
    fn test_conversation_exchange_to_assistant_message_command() {
        let exchange = ConversationExchange {
            query: "build it".to_string(),
            response_type: "command".to_string(),
            response: "cargo build".to_string(),
            explanation: Some("builds the project".to_string()),
            result_exit_code: None,
            result_output_snippet: None,
        };
        let msg = exchange.to_assistant_message("tool_1");
        assert!(matches!(msg.role, crate::provider::Role::Assistant));
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "tool_1");
                assert_eq!(name, "command");
                assert_eq!(input["command"], "cargo build");
                assert_eq!(input["explanation"], "builds the project");
            }
            _ => panic!("expected ToolUse content block"),
        }
    }

    #[test]
    fn test_conversation_exchange_to_assistant_message_chat() {
        let exchange = ConversationExchange {
            query: "explain".to_string(),
            response_type: "chat".to_string(),
            response: "here is the explanation".to_string(),
            explanation: None,
            result_exit_code: None,
            result_output_snippet: None,
        };
        let msg = exchange.to_assistant_message("tool_2");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolUse { name, input, .. } => {
                assert_eq!(name, "chat");
                assert_eq!(input["response"], "here is the explanation");
            }
            _ => panic!("expected ToolUse content block"),
        }
    }

    #[test]
    fn test_conversation_exchange_to_tool_result_command_with_result() {
        let exchange = ConversationExchange {
            query: "run tests".to_string(),
            response_type: "command".to_string(),
            response: "cargo test".to_string(),
            explanation: None,
            result_exit_code: Some(0),
            result_output_snippet: Some("all passed".to_string()),
        };
        let msg = exchange.to_tool_result_message("tool_3");
        assert!(matches!(msg.role, crate::provider::Role::Tool));
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolResult { tool_use_id, content, is_error } => {
                assert_eq!(tool_use_id, "tool_3");
                assert!(content.contains("command"));
                assert!(content.contains("cargo test"));
                assert!(content.contains("Exit 0"));
                assert!(content.contains("all passed"));
                assert!(!is_error);
            }
            _ => panic!("expected ToolResult content block"),
        }
    }

    #[test]
    fn test_conversation_exchange_to_tool_result_command_no_output() {
        let exchange = ConversationExchange {
            query: "deploy".to_string(),
            response_type: "command".to_string(),
            response: "kubectl apply".to_string(),
            explanation: None,
            result_exit_code: Some(1),
            result_output_snippet: None,
        };
        let msg = exchange.to_tool_result_message("tool_4");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolResult { content, .. } => {
                assert!(content.contains("Exit 1"));
                assert!(!content.contains("Output:"));
            }
            _ => panic!("expected ToolResult content block"),
        }
    }

    #[test]
    fn test_conversation_exchange_to_tool_result_chat() {
        let exchange = ConversationExchange {
            query: "hi".to_string(),
            response_type: "chat".to_string(),
            response: "hello there".to_string(),
            explanation: None,
            result_exit_code: None,
            result_output_snippet: None,
        };
        let msg = exchange.to_tool_result_message("tool_5");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolResult { content, .. } => {
                assert!(content.contains("chat"));
                assert!(content.contains("hello there"));
            }
            _ => panic!("expected ToolResult content block"),
        }
    }

    #[test]
    fn test_conversation_exchange_to_assistant_command_no_explanation() {
        let exchange = ConversationExchange {
            query: "list".to_string(),
            response_type: "command".to_string(),
            response: "ls".to_string(),
            explanation: None,
            result_exit_code: None,
            result_output_snippet: None,
        };
        let msg = exchange.to_assistant_message("t1");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolUse { input, .. } => {
                assert_eq!(input["explanation"], "");
            }
            _ => panic!("expected ToolUse"),
        }
    }
}
