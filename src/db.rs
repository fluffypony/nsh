use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA_VERSION: i32 = 3;

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
}
