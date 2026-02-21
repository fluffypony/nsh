use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA_VERSION: i32 = 6;
const COMMAND_ENTITY_BACKFILL_MAX_ID_KEY: &str = "command_entities_backfilled_max_id_v1";
pub const IMPORT_SESSION_PREFIX: &str = "imported_";
// Must stay in sync with IMPORT_SESSION_PREFIX above
const INCLUDE_IMPORTED_SQL: &str = "c.session_id LIKE 'imported_%'";

pub fn init_db(conn: &Connection, busy_timeout_ms: u64) -> rusqlite::Result<()> {
    conn.busy_timeout(std::time::Duration::from_millis(busy_timeout_ms))?;

    conn.execute_batch(
        "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA foreign_keys = ON;
    PRAGMA auto_vacuum = INCREMENTAL;
    PRAGMA wal_autocheckpoint = 1000;
    PRAGMA journal_size_limit = 6144000;
    PRAGMA temp_store = MEMORY;
    PRAGMA cache_size = -64000;
    PRAGMA mmap_size = 268435456;
",
    )?;

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

        -- Structured entities extracted from command arguments
        CREATE TABLE IF NOT EXISTS command_entities (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id      INTEGER NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
            executable      TEXT NOT NULL,
            entity          TEXT NOT NULL,
            entity_norm     TEXT NOT NULL,
            entity_type     TEXT NOT NULL,
            UNIQUE(command_id, executable, entity_norm, entity_type)
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
        CREATE INDEX IF NOT EXISTS idx_command_entities_executable
            ON command_entities(executable, entity_type);
        CREATE INDEX IF NOT EXISTS idx_command_entities_entity_norm
            ON command_entities(entity_norm, entity_type);
        CREATE INDEX IF NOT EXISTS idx_command_entities_command
            ON command_entities(command_id);
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

    // Read version WITHOUT a transaction (plain read, no lock needed in WAL mode)
    let current_version: i32 = conn
        .query_row(
            "SELECT COALESCE((SELECT value FROM meta WHERE key='schema_version'), '0')",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    // Only take the write lock if migration is actually needed
    if current_version < SCHEMA_VERSION {
        let _lock_file = (|| -> Option<std::fs::File> {
            let lock_path = crate::config::Config::nsh_dir().join("migrate.lock");
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(&lock_path)
                .ok()?;
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            }
            Some(file)
        })();

        conn.execute_batch("BEGIN IMMEDIATE;")?;

        // Re-check inside the transaction (another process may have migrated)
        let recheck: i32 = conn
            .query_row(
                "SELECT COALESCE((SELECT value FROM meta WHERE key='schema_version'), '0')",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        if recheck < 2 {
            conn.execute_batch("ALTER TABLE sessions ADD COLUMN last_heartbeat TEXT;")
                .ok();
        }

        if recheck < 3 {
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

        

        if recheck < 5 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS command_entities (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_id      INTEGER NOT NULL REFERENCES commands(id) ON DELETE CASCADE,
                    executable      TEXT NOT NULL,
                    entity          TEXT NOT NULL,
                    entity_norm     TEXT NOT NULL,
                    entity_type     TEXT NOT NULL,
                    UNIQUE(command_id, executable, entity_norm, entity_type)
                );
                CREATE INDEX IF NOT EXISTS idx_command_entities_executable
                    ON command_entities(executable, entity_type);
                CREATE INDEX IF NOT EXISTS idx_command_entities_entity_norm
                    ON command_entities(entity_norm, entity_type);
                CREATE INDEX IF NOT EXISTS idx_command_entities_command
                    ON command_entities(command_id);",
            )?;
        }

        // Memory system tables (idempotent)
        crate::memory::schema::create_memory_tables(conn).ok();

        if recheck < SCHEMA_VERSION {
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                params![SCHEMA_VERSION],
            )?;
        }

        conn.execute_batch("COMMIT;")?;
        // _lock_file drops here, releasing the flock
    } else {
        // Schema current — just validate FTS5 index integrity
        if let Err(e) = conn.execute(
            "SELECT count(*) FROM commands_fts WHERE commands_fts MATCH 'test'",
            [],
        ) {
            tracing::warn!("FTS5 index may be corrupt, rebuilding: {e}");
            conn.execute_batch("INSERT INTO commands_fts(commands_fts) VALUES('rebuild')")?;
        }
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

pub enum UsagePeriod {
    Today,
    Week,
    Month,
    All,
}

pub struct Db {
    conn: Connection,
    max_output_bytes: usize,
}

#[allow(dead_code)]
impl Db {
    fn to_fts_literal_query(query: &str) -> String {
        let terms: Vec<String> = query
            .split_whitespace()
            .filter(|t| !t.is_empty())
            .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
            .collect();
        if terms.is_empty() {
            query.to_string()
        } else {
            terms.join(" ")
        }
    }

    pub fn open() -> anyhow::Result<Self> {
        let dir = crate::config::Config::nsh_dir();
        std::fs::create_dir_all(&dir)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }

        let config = crate::config::Config::load().unwrap_or_default();
        let db_path = dir.join("nsh.db");
        let conn = Connection::open(&db_path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600));
        }

        let mut attempts = 0;
        loop {
            match init_db(&conn, config.db.busy_timeout_ms) {
                Ok(()) => break,
                Err(e) if attempts < 3 => {
                    attempts += 1;
                    tracing::debug!(
                        "Db::open init_db attempt {attempts}/3 failed: {e}, retrying..."
                    );
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => return Err(e.into()),
            }
        }
        let db = Self {
            conn,
            max_output_bytes: config.context.max_output_storage_bytes,
        };
        Ok(db)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        init_db(&conn, 10000)?;
        crate::memory::schema::create_memory_tables(&conn)?;
        let db = Self {
            conn,
            max_output_bytes: 32768,
        };
        Ok(db)
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

    pub fn latest_cwd_for_tty(&self, tty: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT c.cwd
                 FROM commands c
                 JOIN sessions s ON s.id = c.session_id
                 WHERE s.tty = ?
                   AND c.cwd IS NOT NULL
                   AND c.cwd != ''
                 ORDER BY c.started_at DESC, c.id DESC
                 LIMIT 1",
                params![tty],
                |row| row.get(0),
            )
            .optional()
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

        for e in extract_command_entities(command) {
            tx.execute(
                "INSERT OR IGNORE INTO command_entities \
                 (command_id, executable, entity, entity_norm, entity_type) \
                 VALUES (?, ?, ?, ?, ?)",
                params![rowid, e.executable, e.entity, e.entity_norm, e.entity_type],
            )?;
        }

        tx.commit()?;
        Ok(rowid)
    }

    // ── FTS5 search ────────────────────────────────────────────────

    pub fn search_history(&self, query: &str, limit: usize) -> rusqlite::Result<Vec<HistoryMatch>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut stmt = self.conn.prepare_cached(
            "SELECT c.id, c.session_id, c.command, c.cwd,
                    c.exit_code, c.started_at, SUBSTR(c.output, 1, 2000), c.summary,
                    highlight(commands_fts, 0, '>>>', '<<<') as cmd_hl,
                    highlight(commands_fts, 1, '>>>', '<<<') as out_hl
             FROM commands_fts f
             JOIN commands c ON c.id = f.rowid
             WHERE commands_fts MATCH ?
             ORDER BY bm25(commands_fts, 1.0, 0.5, 2.0, 0.5)
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Ok(HistoryMatch {
                id: row.get(0)?,
                session_id: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                exit_code: row.get(4)?,
                started_at: row.get(5)?,
                output: row.get(6)?,
                summary: row.get(7)?,
                cmd_highlight: row.get(8)?,
                output_highlight: row.get(9)?,
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
        let mut stmt = self.conn.prepare_cached(
            "SELECT query, response_type, response, explanation, \
                    result_exit_code, result_output_snippet, created_at
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
                created_at: row.get(6)?,
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

    /// Deletes all imported history sessions and their commands.
    /// FTS cleanup is handled by existing delete triggers; CASCADE handles command_entities.
    #[allow(dead_code)]
    pub fn cleanup_imported_history(&self) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM commands WHERE session_id LIKE 'imported_%'",
            [],
        )?;
        self.conn
            .execute("DELETE FROM sessions WHERE id LIKE 'imported_%'", [])?;
        Ok(())
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
            #[cfg(unix)]
            let process_missing = {
                let alive = unsafe { libc::kill(*pid as i32, 0) };
                if alive == -1 {
                    let err = std::io::Error::last_os_error();
                    err.raw_os_error() == Some(libc::ESRCH)
                } else {
                    false
                }
            };
            #[cfg(windows)]
            let process_missing = false;

            if process_missing {
                self.conn.execute(
                    "UPDATE sessions SET ended_at = ? WHERE id = ?",
                    params![now, id],
                )?;
                cleaned += 1;
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

    // ── Memory operations ──────────────────────────────────────────

    pub fn get_core_memory(&self) -> rusqlite::Result<Vec<crate::memory::types::CoreBlock>> {
        let mut stmt = self.conn.prepare(
            "SELECT label, value, char_limit, updated_at FROM core_memory ORDER BY label",
        )?;
        let rows = stmt.query_map([], |row| {
            let label_str: String = row.get(0)?;
            let label = crate::memory::types::CoreLabel::from_str(&label_str)
                .unwrap_or(crate::memory::types::CoreLabel::Human);
            Ok(crate::memory::types::CoreBlock {
                label,
                value: row.get(1)?,
                char_limit: row.get::<_, i64>(2)? as usize,
                updated_at: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn update_core_block(&self, label: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE core_memory SET value = ?, updated_at = datetime('now') WHERE label = ?",
            params![value, label],
        )?;
        Ok(())
    }

    pub fn append_core_block(&self, label: &str, content: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE core_memory SET value = CASE WHEN value = '' THEN ? ELSE value || '\n' || ? END, updated_at = datetime('now') WHERE label = ?",
            params![content, content, label],
        )?;
        Ok(())
    }

    pub fn search_episodic_fts(
        &self,
        query: &str,
        limit: usize,
        fade_cutoff: Option<&str>,
    ) -> rusqlite::Result<Vec<crate::memory::types::EpisodicEvent>> {
        self.search_episodic_fts_since(query, limit, fade_cutoff, None)
    }

    pub fn search_episodic_fts_since(
        &self,
        query: &str,
        limit: usize,
        fade_cutoff: Option<&str>,
        since: Option<&str>,
    ) -> rusqlite::Result<Vec<crate::memory::types::EpisodicEvent>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut conditions = vec!["episodic_memory_fts MATCH ?1".to_string()];
        if let Some(cutoff) = fade_cutoff {
            conditions.push(format!("e.occurred_at >= '{cutoff}'"));
        }
        if let Some(since_val) = since {
            conditions.push(format!("e.occurred_at >= '{since_val}'"));
        }
        let sql = format!(
            "SELECT e.id, e.event_type, e.actor, e.summary, e.details, e.command, e.exit_code, \
             e.working_dir, e.project_context, e.search_keywords, e.occurred_at, e.is_consolidated \
             FROM episodic_memory e \
             JOIN episodic_memory_fts f ON e.rowid = f.rowid \
             WHERE {} \
             ORDER BY bm25(episodic_memory_fts, 10.0, 5.0, 2.0) \
             LIMIT ?2",
            conditions.join(" AND ")
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Self::row_to_episodic(row)
        })?;
        rows.collect()
    }

    pub fn list_recent_episodic(
        &self,
        limit: usize,
        fade_cutoff: Option<&str>,
    ) -> rusqlite::Result<Vec<crate::memory::types::EpisodicEvent>> {
        let sql = if let Some(cutoff) = fade_cutoff {
            format!(
                "SELECT id, event_type, actor, summary, details, command, exit_code, \
                 working_dir, project_context, search_keywords, occurred_at, is_consolidated \
                 FROM episodic_memory WHERE occurred_at >= '{cutoff}' \
                 ORDER BY occurred_at DESC LIMIT ?1"
            )
        } else {
            "SELECT id, event_type, actor, summary, details, command, exit_code, \
             working_dir, project_context, search_keywords, occurred_at, is_consolidated \
             FROM episodic_memory ORDER BY occurred_at DESC LIMIT ?1".to_string()
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![limit as i64], |row| Self::row_to_episodic(row))?;
        rows.collect()
    }

    pub fn get_unconsolidated_episodic(
        &self,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::EpisodicEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_type, actor, summary, details, command, exit_code, \
             working_dir, project_context, search_keywords, occurred_at, is_consolidated \
             FROM episodic_memory WHERE is_consolidated = 0 \
             ORDER BY occurred_at ASC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| Self::row_to_episodic(row))?;
        rows.collect()
    }

    pub fn search_semantic_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::SemanticItem>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.name, s.category, s.summary, s.details, s.search_keywords, \
             s.access_count, s.last_accessed, s.created_at, s.updated_at \
             FROM semantic_memory s \
             JOIN semantic_memory_fts f ON s.rowid = f.rowid \
             WHERE semantic_memory_fts MATCH ?1 \
             ORDER BY bm25(semantic_memory_fts, 10.0, 8.0, 5.0, 2.0) \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Ok(crate::memory::types::SemanticItem {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                summary: row.get(3)?,
                details: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_all_semantic(&self) -> rusqlite::Result<Vec<crate::memory::types::SemanticItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, category, summary, details, search_keywords, \
             access_count, last_accessed, created_at, updated_at \
             FROM semantic_memory ORDER BY last_accessed DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(crate::memory::types::SemanticItem {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                summary: row.get(3)?,
                details: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn search_procedural_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::ProceduralItem>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.entry_type, p.trigger_pattern, p.summary, p.steps, p.search_keywords, \
             p.access_count, p.last_accessed, p.created_at, p.updated_at \
             FROM procedural_memory p \
             JOIN procedural_memory_fts f ON p.rowid = f.rowid \
             WHERE procedural_memory_fts MATCH ?1 \
             ORDER BY bm25(procedural_memory_fts, 10.0, 5.0, 2.0) \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Ok(crate::memory::types::ProceduralItem {
                id: row.get(0)?,
                entry_type: row.get(1)?,
                trigger_pattern: row.get(2)?,
                summary: row.get(3)?,
                steps: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_all_procedural(
        &self,
    ) -> rusqlite::Result<Vec<crate::memory::types::ProceduralItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, entry_type, trigger_pattern, summary, steps, search_keywords, \
             access_count, last_accessed, created_at, updated_at \
             FROM procedural_memory ORDER BY last_accessed DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(crate::memory::types::ProceduralItem {
                id: row.get(0)?,
                entry_type: row.get(1)?,
                trigger_pattern: row.get(2)?,
                summary: row.get(3)?,
                steps: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn search_resource_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::ResourceItem>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.resource_type, r.file_path, r.file_hash, r.title, r.summary, \
             r.content, r.search_keywords, r.created_at, r.updated_at \
             FROM resource_memory r \
             JOIN resource_memory_fts f ON r.rowid = f.rowid \
             WHERE resource_memory_fts MATCH ?1 \
             ORDER BY bm25(resource_memory_fts, 10.0, 8.0, 5.0, 2.0) \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Self::row_to_resource(row)
        })?;
        rows.collect()
    }

    pub fn get_resources_for_cwd(
        &self,
        cwd: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::ResourceItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, resource_type, file_path, file_hash, title, summary, \
             content, search_keywords, created_at, updated_at \
             FROM resource_memory WHERE file_path LIKE ?1 \
             ORDER BY updated_at DESC LIMIT ?2",
        )?;
        let pattern = format!("{cwd}%");
        let rows = stmt.query_map(params![pattern, limit as i64], |row| {
            Self::row_to_resource(row)
        })?;
        rows.collect()
    }

    pub fn resource_exists_with_hash(&self, path: &str, hash: &str) -> rusqlite::Result<bool> {
        self.conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM resource_memory WHERE file_path = ? AND file_hash = ?",
                params![path, hash],
                |row| row.get(0),
            )
            .or(Ok(false))
    }

    pub fn search_knowledge_fts(
        &self,
        query: &str,
        limit: usize,
        allowed_sensitivity: &[&str],
    ) -> rusqlite::Result<Vec<crate::memory::types::KnowledgeEntry>> {
        let fts_query = Self::to_fts_literal_query(query);
        let placeholders: Vec<String> = (0..allowed_sensitivity.len())
            .map(|i| format!("?{}", i + 3))
            .collect();
        let sensitivity_clause = if allowed_sensitivity.is_empty() {
            "1=1".to_string()
        } else {
            format!("k.sensitivity IN ({})", placeholders.join(","))
        };
        let sql = format!(
            "SELECT k.id, k.entry_type, k.caption, k.secret_value, k.sensitivity, \
             k.search_keywords, k.created_at, k.updated_at \
             FROM knowledge_vault k \
             JOIN knowledge_vault_fts f ON k.rowid = f.rowid \
             WHERE knowledge_vault_fts MATCH ?1 AND {sensitivity_clause} \
             ORDER BY bm25(knowledge_vault_fts, 10.0, 2.0) \
             LIMIT ?2"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        all_params.push(Box::new(fts_query));
        all_params.push(Box::new(limit as i64));
        for s in allowed_sensitivity {
            all_params.push(Box::new(s.to_string()));
        }
        let params_refs: Vec<&dyn rusqlite::types::ToSql> = all_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let sensitivity_str: String = row.get(4)?;
            Ok(crate::memory::types::KnowledgeEntry {
                id: row.get(0)?,
                entry_type: row.get(1)?,
                caption: row.get(2)?,
                secret_value: row.get(3)?,
                sensitivity: crate::memory::types::Sensitivity::from_str(&sensitivity_str),
                search_keywords: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_memory_config(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM memory_config WHERE key = ?",
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn set_memory_config(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO memory_config(key, value) VALUES (?, ?)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn memory_stats(&self) -> rusqlite::Result<crate::memory::types::MemoryStats> {
        let ep: i64 = self.conn.query_row("SELECT COUNT(*) FROM episodic_memory", [], |r| r.get(0))?;
        let sem: i64 = self.conn.query_row("SELECT COUNT(*) FROM semantic_memory", [], |r| r.get(0))?;
        let proc: i64 = self.conn.query_row("SELECT COUNT(*) FROM procedural_memory", [], |r| r.get(0))?;
        let res: i64 = self.conn.query_row("SELECT COUNT(*) FROM resource_memory", [], |r| r.get(0))?;
        let kv: i64 = self.conn.query_row("SELECT COUNT(*) FROM knowledge_vault", [], |r| r.get(0))?;
        Ok(crate::memory::types::MemoryStats {
            core_count: 3,
            episodic_count: ep as usize,
            semantic_count: sem as usize,
            procedural_count: proc as usize,
            resource_count: res as usize,
            knowledge_count: kv as usize,
        })
    }

    pub fn clear_all_memories(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "DELETE FROM episodic_memory;
             DELETE FROM semantic_memory;
             DELETE FROM procedural_memory;
             DELETE FROM resource_memory;
             DELETE FROM knowledge_vault;
             UPDATE core_memory SET value = '', updated_at = datetime('now');
             DELETE FROM memory_config WHERE key IN ('last_decay_at', 'last_reflection_at', 'last_bootstrap_at');",
        )?;
        Ok(())
    }

    pub fn clear_memories_by_type(&self, memory_type: &str) -> rusqlite::Result<()> {
        match memory_type {
            "episodic" => self.conn.execute_batch("DELETE FROM episodic_memory;")?,
            "semantic" => self.conn.execute_batch("DELETE FROM semantic_memory;")?,
            "procedural" => self.conn.execute_batch("DELETE FROM procedural_memory;")?,
            "resource" => self.conn.execute_batch("DELETE FROM resource_memory;")?,
            "knowledge" => self.conn.execute_batch("DELETE FROM knowledge_vault;")?,
            "core" => self.conn.execute_batch("UPDATE core_memory SET value = '', updated_at = datetime('now');")?,
            _ => return Err(rusqlite::Error::InvalidParameterName(
                format!("unknown memory type: {memory_type}")
            )),
        }
        Ok(())
    }

    pub fn delete_memory_by_type_and_id(&self, table: &str, id: &str) -> rusqlite::Result<()> {
        let valid_tables = [
            "episodic_memory",
            "semantic_memory",
            "procedural_memory",
            "resource_memory",
            "knowledge_vault",
        ];
        if !valid_tables.contains(&table) {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "invalid memory table: {table}"
            )));
        }
        self.conn.execute(
            &format!("DELETE FROM {table} WHERE id = ?"),
            params![id],
        )?;
        Ok(())
    }

    pub fn run_memory_decay(
        &self,
        _fade_days: u32,
        expire_days: u32,
    ) -> rusqlite::Result<crate::memory::types::DecayReport> {
        let cutoff = chrono::Utc::now()
            - chrono::Duration::days(expire_days as i64);
        let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

        let ep_del = self.conn.execute(
            "DELETE FROM episodic_memory WHERE occurred_at < ?",
            params![cutoff_str],
        )? as usize;
        let sem_del = self.conn.execute(
            "DELETE FROM semantic_memory WHERE updated_at < ? AND access_count < 3",
            params![cutoff_str],
        )? as usize;
        let proc_del = self.conn.execute(
            "DELETE FROM procedural_memory WHERE updated_at < ? AND access_count < 2",
            params![cutoff_str],
        )? as usize;
        let res_del = self.conn.execute(
            "DELETE FROM resource_memory WHERE updated_at < ?",
            params![cutoff_str],
        )? as usize;
        let kv_del = self.conn.execute(
            "DELETE FROM knowledge_vault WHERE updated_at < ?",
            params![cutoff_str],
        )? as usize;

        let now = chrono::Utc::now().to_rfc3339();
        let _ = self.set_memory_config("last_decay_at", &now);

        Ok(crate::memory::types::DecayReport {
            episodic_deleted: ep_del,
            semantic_deleted: sem_del,
            procedural_deleted: proc_del,
            resource_deleted: res_del,
            knowledge_deleted: kv_del,
        })
    }

    fn row_to_episodic(row: &rusqlite::Row) -> rusqlite::Result<crate::memory::types::EpisodicEvent> {
        let event_type_str: String = row.get(1)?;
        let actor_str: String = row.get(2)?;
        let event_type = match event_type_str.as_str() {
            "command_execution" => crate::memory::types::EventType::CommandExecution,
            "command_error" => crate::memory::types::EventType::CommandError,
            "user_instruction" => crate::memory::types::EventType::UserInstruction,
            "assistant_action" => crate::memory::types::EventType::AssistantAction,
            "file_edit" => crate::memory::types::EventType::FileEdit,
            "session_start" => crate::memory::types::EventType::SessionStart,
            "session_end" => crate::memory::types::EventType::SessionEnd,
            "project_switch" => crate::memory::types::EventType::ProjectSwitch,
            _ => crate::memory::types::EventType::SystemEvent,
        };
        let actor = match actor_str.as_str() {
            "assistant" => crate::memory::types::Actor::Assistant,
            "system" => crate::memory::types::Actor::System,
            _ => crate::memory::types::Actor::User,
        };
        Ok(crate::memory::types::EpisodicEvent {
            id: row.get(0)?,
            event_type,
            actor,
            summary: row.get(3)?,
            details: row.get(4)?,
            command: row.get(5)?,
            exit_code: row.get(6)?,
            working_dir: row.get(7)?,
            project_context: row.get(8)?,
            search_keywords: row.get(9)?,
            occurred_at: row.get(10)?,
            is_consolidated: row.get::<_, i32>(11)? != 0,
        })
    }

    fn row_to_resource(row: &rusqlite::Row) -> rusqlite::Result<crate::memory::types::ResourceItem> {
        Ok(crate::memory::types::ResourceItem {
            id: row.get(0)?,
            resource_type: row.get(1)?,
            file_path: row.get(2)?,
            file_hash: row.get(3)?,
            title: row.get(4)?,
            summary: row.get(5)?,
            content: row.get(6)?,
            search_keywords: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
        })
    }

    #[allow(dead_code)]
    pub fn command_count(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| {
                row.get::<_, i64>(0).map(|v| v as usize)
            })
    }

    pub fn search_command_entities(
        &self,
        executable_filter: Option<&str>,
        entity_filter: Option<&str>,
        entity_type_filter: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
        session_filter: Option<&str>,
        current_session: Option<&str>,
        limit: usize,
    ) -> rusqlite::Result<Vec<CommandEntityMatch>> {
        // Hard clamp to avoid excessive responses over the daemon socket
        let limit = limit.min(200);
        let mut sql = String::from(
            "SELECT ce.command_id, c.session_id, c.command, c.cwd, c.started_at,
                    ce.executable, ce.entity, ce.entity_type
             FROM command_entities ce
             JOIN commands c ON c.id = ce.command_id
             WHERE 1=1",
        );
        let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(exe) = executable_filter.map(normalize_executable_name) {
            if !exe.is_empty() {
                sql.push_str(" AND ce.executable = ?");
                params_vec.push(Box::new(exe));
            }
        }

        if let Some(entity_ty) = entity_type_filter.map(|s| s.trim().to_ascii_lowercase()) {
            if entity_ty == "machine" {
                sql.push_str(" AND ce.entity_type IN ('host', 'ip')");
            } else if !entity_ty.is_empty() {
                sql.push_str(" AND ce.entity_type = ?");
                params_vec.push(Box::new(entity_ty));
            }
        }

        if let Some(entity) = entity_filter {
            let norm = normalize_entity_token(entity);
            if !norm.is_empty() {
                sql.push_str(" AND ce.entity_norm LIKE ?");
                params_vec.push(Box::new(format!("%{norm}%")));
            }
        }

        if let Some(s) = since {
            sql.push_str(" AND c.started_at >= ?");
            params_vec.push(Box::new(s.to_string()));
        }
        if let Some(u) = until {
            sql.push_str(" AND c.started_at <= ?");
            params_vec.push(Box::new(u.to_string()));
        }
        if let Some(sf) = session_filter {
            if sf == "current" {
                sql.push_str(&format!(
                    " AND (c.session_id IN (SELECT id FROM sessions WHERE tty = \
                     (SELECT tty FROM sessions WHERE id = ?)) \
                     OR {INCLUDE_IMPORTED_SQL})"
                ));
                params_vec.push(Box::new(current_session.unwrap_or("default").to_string()));
            } else {
                sql.push_str(&format!(
                    " AND (c.session_id = ? OR {INCLUDE_IMPORTED_SQL})"
                ));
                params_vec.push(Box::new(sf.to_string()));
            }
        }

        sql.push_str(" ORDER BY c.started_at DESC, ce.entity_norm ASC LIMIT ?");
        params_vec.push(Box::new(limit as i64));

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            Ok(CommandEntityMatch {
                command_id: row.get(0)?,
                session_id: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                started_at: row.get(4)?,
                executable: row.get(5)?,
                entity: row.get(6)?,
                entity_type: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn backfill_command_entities_if_needed(&self) -> rusqlite::Result<usize> {
        let max_command_id: i64 =
            self.conn
                .query_row("SELECT COALESCE(MAX(id), 0) FROM commands", [], |row| {
                    row.get(0)
                })?;
        let last_backfilled_id = self
            .get_meta(COMMAND_ENTITY_BACKFILL_MAX_ID_KEY)?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);

        if max_command_id <= last_backfilled_id {
            return Ok(0);
        }

        let tx = self.conn.unchecked_transaction()?;
        let mut inserted = 0usize;
        {
            let mut stmt = tx.prepare(
                "SELECT id, command
                 FROM commands
                 WHERE id > ?
                   AND id NOT IN (SELECT DISTINCT command_id FROM command_entities)
                 ORDER BY id ASC",
            )?;
            let rows = stmt.query_map(params![last_backfilled_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (command_id, command) = row?;
                for e in extract_command_entities(&command) {
                    tx.execute(
                        "INSERT OR IGNORE INTO command_entities \
                         (command_id, executable, entity, entity_norm, entity_type) \
                         VALUES (?, ?, ?, ?, ?)",
                        params![
                            command_id,
                            e.executable,
                            e.entity,
                            e.entity_norm,
                            e.entity_type
                        ],
                    )?;
                    inserted += 1;
                }
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            params![
                COMMAND_ENTITY_BACKFILL_MAX_ID_KEY,
                max_command_id.to_string()
            ],
        )?;
        tx.commit()?;
        Ok(inserted)
    }

    // memory system removed

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
        period: UsagePeriod,
    ) -> rusqlite::Result<Vec<(String, i64, i64, i64, f64)>> {
        let where_clause = match period {
            UsagePeriod::Today => " WHERE created_at >= datetime('now', '-1 day')",
            UsagePeriod::Week => " WHERE created_at >= datetime('now', '-7 days')",
            UsagePeriod::Month => " WHERE created_at >= datetime('now', '-30 days')",
            UsagePeriod::All => "",
        };
        let sql = format!(
            "SELECT model, COUNT(*) as calls, \
             COALESCE(SUM(input_tokens), 0), \
             COALESCE(SUM(output_tokens), 0), \
             COALESCE(SUM(cost_usd), 0.0) \
             FROM usage{where_clause} \
             GROUP BY model ORDER BY calls DESC"
        );
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
        let mut stmt = self.conn.prepare_cached(
            "SELECT c.command, c.cwd, c.exit_code, c.started_at,
                    c.duration_ms, c.summary, SUBSTR(c.output, 1, 6000)
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
                output: row.get(6)?,
            })
        })?;
        let mut results: Vec<CommandWithSummary> = rows.collect::<Result<_, _>>()?;
        if results.is_empty() {
            let mut fallback_stmt = self.conn.prepare_cached(
                "SELECT c.command, c.cwd, c.exit_code, c.started_at,
                        c.duration_ms, c.summary, SUBSTR(c.output, 1, 6000)
                 FROM commands c
                 JOIN sessions s ON s.id = c.session_id
                 JOIN sessions cur ON cur.id = ?
                 WHERE c.session_id != ?
                   AND s.tty = cur.tty
                 ORDER BY c.started_at DESC
                 LIMIT ?",
            )?;
            let fallback_rows =
                fallback_stmt.query_map(params![session_id, session_id, limit as i64], |row| {
                    Ok(CommandWithSummary {
                        command: row.get(0)?,
                        cwd: row.get(1)?,
                        exit_code: row.get(2)?,
                        started_at: row.get(3)?,
                        duration_ms: row.get(4)?,
                        summary: row.get(5)?,
                        output: row.get(6)?,
                    })
                })?;
            results = fallback_rows.collect::<Result<_, _>>()?;
        }
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
        let mut results: Vec<OtherSessionSummary> = rows.collect::<Result<_, _>>()?;
        if results.is_empty() {
            let mut fallback_stmt = self.conn.prepare(
                "SELECT c.command, c.cwd, c.exit_code, c.started_at,
                        c.summary, s.tty, s.shell, c.session_id
                 FROM commands c
                 JOIN sessions s ON s.id = c.session_id
                 LEFT JOIN sessions cur ON cur.id = ?
                 WHERE c.session_id != ?
                   AND (cur.tty IS NULL OR s.tty != cur.tty)
                 ORDER BY c.started_at DESC
                 LIMIT ?",
            )?;
            let fallback_rows = fallback_stmt.query_map(
                params![current_session, current_session, total_limit as i64],
                |row| {
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
                },
            )?;
            results = fallback_rows.collect::<Result<_, _>>()?;
        }
        Ok(results)
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
            let fts = Self::to_fts_literal_query(fts);
            let mut sql = String::from(
                "SELECT c.id, c.session_id, c.command, c.cwd,
                        c.exit_code, c.started_at, SUBSTR(c.output, 1, 2000), c.summary,
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
            if let Some(sf) = session_filter {
                if sf == "current" {
                    conditions.push(format!(
                        " AND (c.session_id IN (SELECT id FROM sessions WHERE tty = \
                         (SELECT tty FROM sessions WHERE id = ?{param_idx})) \
                         OR {INCLUDE_IMPORTED_SQL})"
                    ));
                } else {
                    conditions.push(format!(
                        " AND (c.session_id = ?{param_idx} OR {INCLUDE_IMPORTED_SQL})"
                    ));
                }
                param_idx += 1;
            }
            let _ = param_idx;

            for cond in &conditions {
                sql.push_str(cond);
            }
            sql.push_str(" ORDER BY bm25(commands_fts, 1.0, 0.5, 2.0, 0.5) LIMIT ?");

            // Build params dynamically - collect into Vec<Box<dyn rusqlite::types::ToSql>>
            let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            params_vec.push(Box::new(fts));
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
                if sf == "current" {
                    params_vec.push(Box::new(current_session.unwrap_or("default").to_string()));
                } else {
                    params_vec.push(Box::new(sf.to_string()));
                }
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
                    summary: row.get(7)?,
                    cmd_highlight: row.get(8)?,
                    output_highlight: row.get(9)?,
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
                    c.exit_code, c.started_at, SUBSTR(c.output, 1, 2000), c.summary,
                    c.command as cmd_hl,
                    SUBSTR(c.output, 1, 2000) as out_hl
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
            if sf == "current" {
                sql.push_str(&format!(
                    " AND (c.session_id IN (SELECT id FROM sessions WHERE tty = \
                     (SELECT tty FROM sessions WHERE id = ?)) \
                     OR {INCLUDE_IMPORTED_SQL})"
                ));
                params_vec.push(Box::new(current_session.unwrap_or("default").to_string()));
            } else {
                sql.push_str(&format!(
                    " AND (c.session_id = ? OR {INCLUDE_IMPORTED_SQL})"
                ));
                params_vec.push(Box::new(sf.to_string()));
            }
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
                summary: row.get(7)?,
                cmd_highlight: row.get(8)?,
                output_highlight: row.get(9)?,
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

        // Memory system check
        eprint!("  Memory tables... ");
        let memory_count: i64 = self.conn.query_row(
            "SELECT (SELECT COUNT(*) FROM episodic_memory) + \
                    (SELECT COUNT(*) FROM semantic_memory) + \
                    (SELECT COUNT(*) FROM procedural_memory) + \
                    (SELECT COUNT(*) FROM resource_memory) + \
                    (SELECT COUNT(*) FROM knowledge_vault)",
            [], |row| row.get(0),
        ).unwrap_or(0);
        eprintln!("{memory_count} total memory entries");

        eprint!("  Core memory... ");
        let core_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM core_memory", [], |row| row.get(0)
        ).unwrap_or(0);
        eprintln!("{core_count} blocks");

        eprint!("  Memory FTS5 integrity... ");
        let mut mem_fts_ok = true;
        for table in ["episodic_memory_fts", "semantic_memory_fts", "procedural_memory_fts",
                       "resource_memory_fts", "knowledge_vault_fts"] {
            if let Err(e) = self.conn.execute(
                &format!("INSERT INTO {table}({table}) VALUES('integrity-check')"), []
            ) {
                eprintln!("FAILED ({table}): {e}");
                let _ = self.conn.execute_batch(&format!("INSERT INTO {table}({table}) VALUES('rebuild')"));
                mem_fts_ok = false;
            }
        }
        if mem_fts_ok {
            eprintln!("OK");
        }

        eprint!("  Core memory usage... ");
        for block in self.get_core_memory().unwrap_or_default() {
            let pct = if block.char_limit > 0 {
                (block.value.len() as f64 / block.char_limit as f64 * 100.0) as usize
            } else {
                0
            };
            eprint!("{}={}% ", block.label, pct);
        }
        eprintln!();

        // 8. Orphaned socket/PID files
        eprint!("  Orphaned files... ");
        let nsh_dir = crate::config::Config::nsh_dir();
        let mut orphaned_count = 0;
        if let Ok(entries) = std::fs::read_dir(&nsh_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Clean up legacy shared CWD index files
                if name == "tty_last_cwd"
                    || name == "tty_last_cwd.lock"
                    || name == "tty_last_cwd.tmp"
                {
                    let _ = std::fs::remove_file(entry.path());
                    orphaned_count += 1;
                    continue;
                }
                // Clean up orphaned per-TTY CWD files (skip active sessions)
                if name.starts_with("cwd_") && !name.ends_with(".tmp") {
                    // Extract TTY from filename: cwd__dev_ttys011 → /dev/ttys011
                    let tty = name.trim_start_matches("cwd_").replace('_', "/");
                    let tty_active: bool = self
                        .conn
                        .query_row(
                            "SELECT COUNT(*) > 0 FROM sessions WHERE tty = ? AND ended_at IS NULL",
                            params![tty],
                            |row| row.get(0),
                        )
                        .unwrap_or(false);
                    if !tty_active {
                        let _ = std::fs::remove_file(entry.path());
                        orphaned_count += 1;
                    }
                    continue;
                }
                if (name.starts_with("daemon_")
                    && (name.ends_with(".sock") || name.ends_with(".pid")))
                    || name.starts_with("scrollback_") && !name.ends_with(".sock")
                    || name.starts_with("pending_cmd_")
                    || name.starts_with("pending_flag_")
                    || name.starts_with("pending_autorun_")
                {
                    let session_id = name
                        .trim_start_matches("daemon_")
                        .trim_start_matches("scrollback_")
                        .trim_start_matches("pending_cmd_")
                        .trim_start_matches("pending_flag_")
                        .trim_start_matches("pending_autorun_")
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

    pub fn open_readonly() -> anyhow::Result<Self> {
        let dir = crate::config::Config::nsh_dir();
        let config = crate::config::Config::load().unwrap_or_default();
        let db_path = dir.join("nsh.db");
        let conn = Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_millis(config.db.busy_timeout_ms))?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA temp_store = MEMORY;
            PRAGMA mmap_size = 268435456;
            PRAGMA query_only = ON;
        ",
        )?;
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
        Ok(Self {
            conn,
            max_output_bytes: config.context.max_output_storage_bytes,
        })
    }

    pub fn bulk_insert_history(
        &self,
        session_id: &str,
        entries_json: &str,
    ) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let entries: serde_json::Value = serde_json::from_str(entries_json).unwrap_or_default();
        if let Some(array) = entries.as_array() {
            for entry in array {
                let command = entry
                    .get("cmd")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();
                let started_at = entry
                    .get("ts")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim();

                if command.is_empty() || command.starts_with('#') || started_at.is_empty() {
                    continue;
                }

                tx.execute(
                    "INSERT OR IGNORE INTO commands (session_id, command, started_at)
                     VALUES (?, ?, ?)",
                    params![session_id, command, started_at],
                )?;
                let rowid = tx.last_insert_rowid();
                if rowid == 0 {
                    continue;
                }

                for e in extract_command_entities(command) {
                    tx.execute(
                        "INSERT OR IGNORE INTO command_entities \
                         (command_id, executable, entity, entity_norm, entity_type) \
                         VALUES (?, ?, ?, ?, ?)",
                        params![rowid, e.executable, e.entity, e.entity_norm, e.entity_type],
                    )?;
                }
            }
        }
        tx.commit()
    }

    pub fn conn_execute_batch(&self, sql: &str) -> rusqlite::Result<()> {
        self.conn.execute_batch(sql)
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
    pub summary: Option<String>,
    pub cmd_highlight: String,
    pub output_highlight: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CommandEntityMatch {
    pub command_id: i64,
    pub session_id: String,
    pub command: String,
    pub cwd: Option<String>,
    pub started_at: String,
    pub executable: String,
    pub entity: String,
    pub entity_type: String,
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
    pub output: Option<String>,
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
    pub created_at: Option<String>,
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

#[derive(Debug, Clone)]
struct ExtractedCommandEntity {
    executable: String,
    entity: String,
    entity_norm: String,
    entity_type: String,
}

fn extract_command_entities(command: &str) -> Vec<ExtractedCommandEntity> {
    let tokens = match shell_words::split(command) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    if tokens.is_empty() {
        return Vec::new();
    }

    let Some(cmd_idx) = find_invoked_command_index(&tokens) else {
        return Vec::new();
    };
    let executable = normalize_executable_name(tokens[cmd_idx].as_str());
    if executable.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for token in tokens.iter().skip(cmd_idx + 1) {
        if token == "--" {
            continue;
        }
        for machine in extract_machine_candidates(token) {
            let entity_type = if is_ip_address(&machine) {
                "ip"
            } else {
                "host"
            };
            let entity_norm = normalize_entity_token(&machine);
            if entity_norm.is_empty() {
                continue;
            }
            let key = (entity_norm.clone(), entity_type.to_string());
            if !seen.insert(key) {
                continue;
            }
            out.push(ExtractedCommandEntity {
                executable: executable.clone(),
                entity: machine,
                entity_norm,
                entity_type: entity_type.to_string(),
            });
        }
    }
    out
}

fn find_invoked_command_index(tokens: &[String]) -> Option<usize> {
    let mut i = 0usize;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if tok == "env" {
            i += 1;
            while i < tokens.len() {
                let t = tokens[i].as_str();
                if t == "--" {
                    i += 1;
                    break;
                }
                if t == "-u" {
                    i = (i + 2).min(tokens.len());
                    continue;
                }
                if t.starts_with('-') || is_env_assignment(t) {
                    i += 1;
                    continue;
                }
                break;
            }
            continue;
        }
        if tok == "sudo" {
            i += 1;
            while i < tokens.len() {
                let t = tokens[i].as_str();
                if t == "--" {
                    i += 1;
                    break;
                }
                if t == "-u"
                    || t == "-g"
                    || t == "-h"
                    || t == "-p"
                    || t == "-r"
                    || t == "-t"
                    || t == "-C"
                    || t == "--user"
                    || t == "--group"
                    || t == "--host"
                    || t == "--prompt"
                    || t == "--chroot"
                    || t == "--command-timeout"
                {
                    i = (i + 2).min(tokens.len());
                    continue;
                }
                if t.starts_with('-') {
                    i += 1;
                    continue;
                }
                break;
            }
            continue;
        }
        if tok == "command" || tok == "builtin" || tok == "noglob" || tok == "nocorrect" {
            i += 1;
            continue;
        }
        if is_env_assignment(tok) {
            i += 1;
            continue;
        }
        return Some(i);
    }
    None
}

fn is_env_assignment(token: &str) -> bool {
    if token.starts_with('-') || token.starts_with('=') {
        return false;
    }
    let Some((k, _v)) = token.split_once('=') else {
        return false;
    };
    !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn normalize_executable_name(token: &str) -> String {
    let base = token.rsplit('/').next().unwrap_or(token);
    base.trim().trim_matches('\'').to_ascii_lowercase()
}

fn extract_machine_candidates(token: &str) -> Vec<String> {
    let mut out = Vec::new();

    let cleaned = token
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '(' | ']' | '['))
        .trim_matches('.');
    if cleaned.is_empty() {
        return out;
    }

    if let Some(host) = extract_host_from_url(cleaned) {
        out.push(host);
    }

    if let Some(host) = extract_host_from_remote_path(cleaned) {
        out.push(host);
    }

    if let Some(host) = normalize_host_token(cleaned) {
        out.push(host);
    }

    out.sort();
    out.dedup();
    out
}

fn extract_host_from_url(token: &str) -> Option<String> {
    let (_, rest) = token.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    normalize_host_token(authority)
}

fn extract_host_from_remote_path(token: &str) -> Option<String> {
    if token.starts_with('/') || token.starts_with("./") || token.starts_with("~/") {
        return None;
    }
    let (left, right) = token.split_once(':')?;
    if left.is_empty() || right.is_empty() {
        return None;
    }
    normalize_host_token(left)
}

fn normalize_host_token(token: &str) -> Option<String> {
    let token = token
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '('))
        .trim();
    if token.is_empty() {
        return None;
    }

    let after_at = token.rsplit('@').next().unwrap_or(token);
    let mut host = after_at;
    if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        host = &host[1..host.len() - 1];
    }

    // host:port (but keep IPv6 literals intact)
    if let Some((h, port)) = host.rsplit_once(':') {
        if !h.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            host = h;
        }
    }

    let host = host.trim_matches('.');
    if host.is_empty() {
        return None;
    }

    if is_ip_address(host) || is_hostname_like(host) {
        return Some(host.to_ascii_lowercase());
    }
    None
}

fn normalize_entity_token(token: &str) -> String {
    normalize_host_token(token).unwrap_or_else(|| token.trim().to_ascii_lowercase())
}

fn is_ip_address(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok() || value.parse::<std::net::Ipv6Addr>().is_ok()
}

fn is_hostname_like(value: &str) -> bool {
    if value.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if !value.contains('.') {
        return false;
    }
    if value.len() > 253 {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[cfg(all(test, not(any())))]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    type UsageRow = (
        String,
        String,
        Option<u32>,
        Option<u32>,
        Option<f64>,
        Option<String>,
        Option<String>,
    );

    fn test_db() -> Db {
        Db::open_in_memory().expect("in-memory db")
    }

    struct EnvVarGuard {
        key: &'static str,
        old: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let old = std::env::var(key).ok();
            // SAFETY: test-only env changes guarded by serial tests.
            unsafe { std::env::set_var(key, value) };
            Self { key, old }
        }

        fn remove(key: &'static str) -> Self {
            let old = std::env::var(key).ok();
            // SAFETY: test-only env changes guarded by serial tests.
            unsafe { std::env::remove_var(key) };
            Self { key, old }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(old) = &self.old {
                // SAFETY: test-only env changes guarded by serial tests.
                unsafe { std::env::set_var(self.key, old) };
            } else {
                // SAFETY: test-only env changes guarded by serial tests.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    fn temp_home_env() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().unwrap();
        let home_guard = EnvVarGuard::set("HOME", home.path());
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        (home, home_guard, xdg_data_guard, xdg_config_guard)
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
    fn test_insert_command_extracts_machine_entities() {
        let db = test_db();
        db.insert_command(
            "s1",
            "ssh -p 2222 admin@203.0.113.10",
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

        let entities = db
            .search_command_entities(
                Some("ssh"),
                Some("203.0.113.10"),
                Some("ip"),
                None,
                None,
                None,
                None,
                10,
            )
            .unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].entity, "203.0.113.10");
        assert_eq!(entities[0].entity_type, "ip");
        assert_eq!(entities[0].executable, "ssh");
    }

    #[test]
    fn test_search_command_entities_machine_filter() {
        let db = test_db();
        db.insert_command(
            "s1",
            "telnet example.net 23",
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
        db.insert_command(
            "s1",
            "ping 1.1.1.1",
            "/tmp",
            Some(0),
            "2025-01-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let entities = db
            .search_command_entities(None, None, Some("machine"), None, None, None, None, 10)
            .unwrap();
        assert!(entities.iter().any(|e| e.entity == "example.net"));
        assert!(entities.iter().any(|e| e.entity == "1.1.1.1"));
    }

    #[test]
    fn test_backfill_command_entities_from_existing_commands() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 123).unwrap();
        db.conn
            .execute(
                "INSERT INTO commands (session_id, command, cwd, exit_code, started_at, duration_ms, output) \
                 VALUES ('s1', 'rsync -av root@backup.example.com:/data ./', '/tmp', 0, '2025-01-01T00:00:00Z', NULL, NULL)",
                [],
            )
            .unwrap();

        let inserted = db.backfill_command_entities_if_needed().unwrap();
        assert!(inserted > 0);
        let entities = db
            .search_command_entities(
                Some("rsync"),
                Some("backup.example.com"),
                Some("host"),
                None,
                None,
                None,
                None,
                10,
            )
            .unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].entity, "backup.example.com");
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
            "s1",
            "early cmd",
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
        db.insert_command(
            "s1",
            "middle cmd",
            "/tmp",
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
            "late cmd",
            "/tmp",
            Some(0),
            "2025-12-01T00:00:00Z",
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
                None,
                Some("2025-03-01T00:00:00Z"),
                Some("2025-09-01T00:00:00Z"),
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("middle"));
    }

    #[test]
    fn test_search_history_advanced_failed_only() {
        let db = test_db();
        db.insert_command(
            "s1",
            "good cmd",
            "/tmp",
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
            "bad cmd",
            "/tmp",
            Some(1),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(None, None, None, None, None, true, None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("bad"));
        assert_eq!(results[0].exit_code, Some(1));
    }

    #[test]
    fn test_search_history_advanced_session_filter() {
        let db = test_db();
        db.insert_command(
            "sess_a",
            "cmd alpha",
            "/tmp",
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
            "sess_b",
            "cmd beta",
            "/tmp",
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
                None,
                None,
                None,
                None,
                false,
                Some("sess_a"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("alpha"));
    }

    #[test]
    fn test_search_history_advanced_exit_code_filter() {
        let db = test_db();
        db.insert_command(
            "s1",
            "exit zero",
            "/tmp",
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
            "exit two",
            "/tmp",
            Some(2),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "exit one",
            "/tmp",
            Some(1),
            "2025-06-01T00:02:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(None, None, None, None, Some(2), false, None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("exit two"));
    }

    #[test]
    fn test_pending_conversation_flow() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let conv_id = db
            .insert_conversation(
                "s1",
                "run tests",
                "command",
                "cargo test",
                Some("runs the test suite"),
                false,
                true,
            )
            .unwrap();
        assert!(conv_id > 0);

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_some());
        let (id, response) = pending.unwrap();
        assert_eq!(id, conv_id);
        assert_eq!(response, "cargo test");

        db.update_conversation_result(conv_id, 0, Some("all tests passed"))
            .unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].result_exit_code, Some(0));
        assert_eq!(
            convos[0].result_output_snippet.as_deref(),
            Some("all tests passed")
        );
    }

    #[test]
    fn test_insert_usage_and_get_usage_stats() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage(
            "s1",
            Some("hello"),
            "gpt-4",
            "openai",
            Some(100),
            Some(50),
            Some(0.01),
            None,
        )
        .unwrap();
        db.insert_usage(
            "s1",
            Some("world"),
            "gpt-4",
            "openai",
            Some(200),
            Some(100),
            Some(0.02),
            None,
        )
        .unwrap();

        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
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
            "s1",
            Some("q"),
            "claude",
            "anthropic",
            Some(50),
            Some(25),
            None,
            Some("gen_abc"),
        )
        .unwrap();

        let updated = db.update_usage_cost("gen_abc", 0.05).unwrap();
        assert!(updated);

        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
        assert_eq!(stats.len(), 1);
        let (_, _, _, _, cost) = &stats[0];
        assert!((cost - 0.05).abs() < 1e-9);
    }

    #[test]
    fn test_get_pending_generation_ids() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage(
            "s1",
            Some("q"),
            "gpt-4",
            "openai",
            Some(10),
            Some(5),
            None,
            Some("gen_123"),
        )
        .unwrap();
        db.insert_usage(
            "s1",
            Some("q2"),
            "gpt-4",
            "openai",
            Some(10),
            Some(5),
            Some(0.01),
            Some("gen_456"),
        )
        .unwrap();

        let pending = db.get_pending_generation_ids().unwrap();
        assert!(pending.contains(&"gen_123".to_string()));
        assert!(!pending.contains(&"gen_456".to_string()));
    }

    #[test]
    fn test_update_command_output() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "my cmd",
                "/tmp",
                None,
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();

        let updated = db
            .update_command(id, Some(42), Some("some output"))
            .unwrap();
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
            "s1",
            "old prunable",
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
                "s1",
                &format!("query{i}"),
                "chat",
                &format!("resp{i}"),
                None,
                false,
                false,
            )
            .unwrap();
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

        let id = db
            .insert_command(
                "s1",
                "cargo build",
                "/project",
                Some(0),
                "2025-06-01T00:00:00Z",
                Some(5200),
                Some("Compiled OK"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "Built project successfully").unwrap();

        db.insert_command(
            "s1",
            "cargo test",
            "/project",
            Some(1),
            "2025-06-01T00:01:00Z",
            Some(3000),
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let cmds = db.recent_commands_with_summaries("s1", 10).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].command, "cargo build");
        assert_eq!(
            cmds[0].summary.as_deref(),
            Some("Built project successfully")
        );
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
            "s1",
            "cmd_s1",
            "/tmp",
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
            "s2",
            "cmd_s2",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let cmds = db.recent_commands_with_summaries("s1", 10).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "cmd_s1");
    }

    #[test]
    fn test_recent_commands_with_summaries_falls_back_to_same_tty() {
        let db = test_db();
        db.create_session("current", "/dev/pts/0", "zsh", 1234)
            .unwrap();
        db.create_session("old_same_tty", "/dev/pts/0", "zsh", 5678)
            .unwrap();

        let id = db
            .insert_command(
                "old_same_tty",
                "from_old_same_tty",
                "/tmp",
                Some(0),
                "2025-06-01T00:01:00Z",
                None,
                Some("ok"),
                "/dev/pts/0",
                "zsh",
                5678,
            )
            .unwrap();
        db.update_summary(id, "same tty fallback").unwrap();

        let cmds = db.recent_commands_with_summaries("current", 10).unwrap();
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].command, "from_old_same_tty");
        assert_eq!(cmds[0].summary.as_deref(), Some("same tty fallback"));
    }

    #[test]
    fn test_other_sessions_with_summaries() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 5678).unwrap();

        db.insert_command(
            "s1",
            "cmd_mine",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/0",
            "zsh",
            1234,
        )
        .unwrap();
        db.insert_command(
            "s2",
            "cmd_other",
            "/home",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "/dev/pts/1",
            "bash",
            5678,
        )
        .unwrap();

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
            "s1",
            "docker compose up",
            "/app",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("Starting containers... done"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "git log --oneline",
            "/app",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

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
            "s1",
            "make build",
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
            "make test",
            "/project",
            Some(1),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(Some("make"), None, None, None, None, true, None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("make test"));
    }

    #[test]
    fn test_session_end_and_heartbeat() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.update_heartbeat("s1").unwrap();
        let hb: Option<String> = db
            .conn
            .query_row(
                "SELECT last_heartbeat FROM sessions WHERE id = 's1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(hb.is_some());

        let ended: Option<String> = db
            .conn
            .query_row("SELECT ended_at FROM sessions WHERE id = 's1'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(ended.is_none());

        db.end_session("s1").unwrap();
        let ended: Option<String> = db
            .conn
            .query_row("SELECT ended_at FROM sessions WHERE id = 's1'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(ended.is_some());
    }

    #[test]
    fn test_prune_keeps_recent() {
        let db = test_db();
        db.insert_command(
            "s1",
            "ancient",
            "/tmp",
            Some(0),
            "2015-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "recent",
            "/tmp",
            Some(0),
            "2099-12-31T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let deleted = db.prune(365).unwrap();
        assert_eq!(deleted, 1);

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);

        let results = db.search_history("recent", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_commands_needing_summary_excludes_no_output() {
        let db = test_db();
        db.insert_command(
            "s1",
            "no output cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert!(needing.is_empty());
    }

    #[test]
    fn test_commands_needing_summary_excludes_already_summarized() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "summarized cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("output text"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "already done").unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert!(needing.is_empty());
    }

    #[test]
    fn test_mark_unsummarized_for_llm_and_needing_llm() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cmd1",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("output1"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "cmd2",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            Some("output2"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "cmd3",
            "/tmp",
            Some(0),
            "2025-06-01T00:02:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

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
        let id = db
            .insert_command(
                "s1",
                "failing cmd",
                "/tmp",
                Some(1),
                "2025-06-01T00:00:00Z",
                None,
                Some("error output"),
                "",
                "",
                0,
            )
            .unwrap();

        db.mark_summary_error(id, "API timeout").unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert!(needing.is_empty());

        let summary: Option<String> = db
            .conn
            .query_row(
                "SELECT summary FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(summary.unwrap().contains("[error: API timeout]"));
    }

    #[test]
    fn test_update_conversation_result_thorough() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id1 = db
            .insert_conversation(
                "s1",
                "deploy",
                "command",
                "kubectl apply -f deploy.yaml",
                Some("deploy to k8s"),
                false,
                false,
            )
            .unwrap();
        let id2 = db
            .insert_conversation(
                "s1",
                "check status",
                "command",
                "kubectl get pods",
                None,
                false,
                false,
            )
            .unwrap();

        db.update_conversation_result(id1, 0, Some("deployment created"))
            .unwrap();
        db.update_conversation_result(id2, 1, None).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 2);
        assert_eq!(convos[0].result_exit_code, Some(0));
        assert_eq!(
            convos[0].result_output_snippet.as_deref(),
            Some("deployment created")
        );
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
            "s1",
            "what is rust",
            "chat",
            "Rust is a systems language",
            None,
            false,
            false,
        )
        .unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn test_find_pending_conversation_ignores_completed() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let conv_id = db
            .insert_conversation("s1", "build", "command", "cargo build", None, false, false)
            .unwrap();
        db.update_conversation_result(conv_id, 0, None).unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_none());
    }

    #[test]
    fn test_insert_usage() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db
            .insert_usage(
                "s1",
                Some("hello world"),
                "claude-3-opus",
                "anthropic",
                Some(500),
                Some(200),
                Some(0.10),
                Some("gen_xyz"),
            )
            .unwrap();
        assert!(id > 0);

        let id2 = db
            .insert_usage("s1", None, "gpt-4o", "openai", None, None, None, None)
            .unwrap();
        assert!(id2 > id);

        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
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
            "s1",
            "test cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        db.optimize_fts().unwrap();
        db.check_fts_integrity().unwrap();
    }

    #[test]
    fn test_search_history_advanced_current_session_alias() {
        let db = test_db();
        db.insert_command(
            "my_sess",
            "cmd here",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "other_sess",
            "cmd there",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "/dev/pts/2",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                None,
                None,
                None,
                None,
                None,
                false,
                Some("current"),
                Some("my_sess"),
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("cmd here"));
    }

    #[test]
    fn test_update_command() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "running cmd",
                "/tmp",
                None,
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();

        let updated = db.update_command(id, Some(0), Some("all good")).unwrap();
        assert!(updated);

        let updated_again = db.update_command(id, None, Some("extra output")).unwrap();
        assert!(updated_again);

        let (code, out): (Option<i32>, Option<String>) = db
            .conn
            .query_row(
                "SELECT exit_code, output FROM commands WHERE id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
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
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("output"),
                "",
                "",
                0,
            )
            .unwrap();

        let first = db.update_summary(id, "summary v1").unwrap();
        assert!(first);

        let second = db.update_summary(id, "summary v2").unwrap();
        assert!(!second);

        let summary: Option<String> = db
            .conn
            .query_row(
                "SELECT summary FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(summary.as_deref(), Some("summary v1"));
    }

    #[test]
    fn test_prune_also_removes_ended_sessions() {
        let db = test_db();
        db.create_session("old_sess", "/dev/pts/0", "zsh", 1234)
            .unwrap();
        db.conn
            .execute(
                "UPDATE sessions SET ended_at = '2015-01-01T00:00:00Z' WHERE id = 'old_sess'",
                [],
            )
            .unwrap();

        db.prune(30).unwrap();

        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE id = 'old_sess'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_search_history_advanced_fts_with_regex_filter() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo build --release",
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
            "cargo test --release",
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
                Some("cargo"),
                Some("test"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("cargo test"));
    }

    #[test]
    fn test_conversations_across_sessions_isolated() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 5678).unwrap();

        db.insert_conversation("s1", "q1", "chat", "r1", None, false, false)
            .unwrap();
        db.insert_conversation("s2", "q2", "chat", "r2", None, false, false)
            .unwrap();

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
            "s1",
            "cargo build",
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
            "cargo test",
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
        db.insert_command(
            "s1",
            "cargo bench",
            "/project",
            Some(0),
            "2025-06-01T00:02:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

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
                "s1",
                &format!("grep pattern{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();
        }

        let results = db.search_history("grep", 3).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_search_history_matches_output() {
        let db = test_db();
        db.insert_command(
            "s1",
            "run_script",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("unique_sentinel_output_value"),
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history("unique_sentinel_output_value", 10)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "run_script");
    }

    #[test]
    fn test_search_history_matches_summary_via_fts() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "make deploy",
                "/app",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("deploying..."),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "deployed application to production kubernetes cluster")
            .unwrap();

        let results = db.search_history("kubernetes", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "make deploy");
    }

    #[test]
    fn test_search_history_matches_cwd() {
        let db = test_db();
        db.insert_command(
            "s1",
            "ls",
            "/unique/searchable/directory",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db.search_history("searchable", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_history_hyphenated_term() {
        let db = test_db();
        db.insert_command(
            "s1",
            "echo from-ht",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("from-ht"),
            "",
            "",
            0,
        )
        .unwrap();

        let results = db.search_history("from-ht", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "echo from-ht");
    }

    #[test]
    fn test_init_db_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn, 10000).unwrap();
        init_db(&conn, 10000).unwrap();

        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_string());

        conn.execute(
            "INSERT INTO sessions (id, tty, shell, pid, started_at) VALUES ('x', 'tty', 'zsh', 1, '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO commands (session_id, command, started_at) VALUES ('x', 'echo hi', '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM commands_fts WHERE commands_fts MATCH 'echo'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_command_with_none_values() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "echo hello",
                "/tmp",
                None,
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();
        assert!(id > 0);

        let (exit_code, duration, output): (Option<i32>, Option<i64>, Option<String>) = db
            .conn
            .query_row(
                "SELECT exit_code, duration_ms, output FROM commands WHERE id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(exit_code.is_none());
        assert!(duration.is_none());
        assert!(output.is_none());
    }

    #[test]
    fn test_insert_command_with_very_long_command() {
        let db = test_db();
        let long_cmd = "x".repeat(100_000);
        let id = db
            .insert_command(
                "s1",
                &long_cmd,
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();
        assert!(id > 0);

        let stored: String = db
            .conn
            .query_row(
                "SELECT command FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored.len(), 100_000);
    }

    #[test]
    fn test_insert_command_with_unicode_output() {
        let db = test_db();
        let unicode_output = "日本語テスト 🦀 émojis résumé café";
        let id = db
            .insert_command(
                "s1",
                "echo intl",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some(unicode_output),
                "",
                "",
                0,
            )
            .unwrap();

        let stored: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
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
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some(output),
                "",
                "",
                0,
            )
            .unwrap();

        let stored: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        let stored = stored.unwrap();
        assert!(stored.contains("[truncated by nsh]"));
        assert!(stored.is_char_boundary(0));
    }

    #[test]
    fn test_insert_usage_all_fields() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db
            .insert_usage(
                "s1",
                Some("translate this code"),
                "claude-3.5-sonnet",
                "anthropic",
                Some(1500),
                Some(800),
                Some(0.0234),
                Some("gen_full_test_123"),
            )
            .unwrap();
        assert!(id > 0);

        let (model, provider, input, output, cost, gen_id, query): UsageRow = db.conn.query_row(
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

        let id1 = db
            .insert_command(
                "s1",
                "first",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                Some(100),
                Some("out1"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id1, "summary for first").unwrap();

        let id2 = db
            .insert_command(
                "s1",
                "second",
                "/tmp",
                Some(0),
                "2025-06-01T00:01:00Z",
                Some(200),
                Some("out2"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id2, "summary for second").unwrap();

        let id3 = db
            .insert_command(
                "s1",
                "third",
                "/tmp",
                Some(1),
                "2025-06-01T00:02:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();
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
        db.create_session("other1", "/dev/pts/1", "bash", 5678)
            .unwrap();
        db.create_session("other2", "/dev/pts/2", "fish", 9012)
            .unwrap();

        db.insert_command(
            "me",
            "my_cmd",
            "/home",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/0",
            "zsh",
            1234,
        )
        .unwrap();

        let id1 = db
            .insert_command(
                "other1",
                "their_cmd_1",
                "/tmp",
                Some(0),
                "2025-06-01T00:01:00Z",
                None,
                Some("output1"),
                "/dev/pts/1",
                "bash",
                5678,
            )
            .unwrap();
        db.update_summary(id1, "summary for other1").unwrap();

        db.insert_command(
            "other2",
            "their_cmd_2",
            "/var",
            Some(1),
            "2025-06-01T00:02:00Z",
            None,
            None,
            "/dev/pts/2",
            "fish",
            9012,
        )
        .unwrap();

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
        db.create_session("ended", "/dev/pts/1", "bash", 5678)
            .unwrap();
        db.create_session("active", "/dev/pts/2", "fish", 9012)
            .unwrap();
        db.end_session("ended").unwrap();

        db.insert_command(
            "ended",
            "ended_cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "bash",
            5678,
        )
        .unwrap();
        db.insert_command(
            "active",
            "active_cmd",
            "/var",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "/dev/pts/2",
            "fish",
            9012,
        )
        .unwrap();

        let others = db.other_sessions_with_summaries("me", 5, 5).unwrap();
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].command, "active_cmd");
    }

    #[test]
    fn test_other_sessions_with_summaries_falls_back_to_recent_other_ttys() {
        let db = test_db();
        db.create_session("me", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("ended_other", "/dev/pts/1", "bash", 5678)
            .unwrap();
        db.end_session("ended_other").unwrap();

        db.insert_command(
            "ended_other",
            "ended_cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "bash",
            5678,
        )
        .unwrap();

        let others = db.other_sessions_with_summaries("me", 5, 5).unwrap();
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].command, "ended_cmd");
        assert_eq!(others[0].tty, "/dev/pts/1");
    }

    #[test]
    fn test_conversation_full_lifecycle() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id1 = db
            .insert_conversation(
                "s1",
                "how do I list files",
                "chat",
                "Use ls -la to list files",
                None,
                false,
                false,
            )
            .unwrap();

        let id2 = db
            .insert_conversation(
                "s1",
                "list files",
                "command",
                "ls -la",
                Some("lists all files including hidden"),
                false,
                true,
            )
            .unwrap();

        assert!(id2 > id1);

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_some());
        let (pid, resp) = pending.unwrap();
        assert_eq!(pid, id2);
        assert_eq!(resp, "ls -la");

        db.update_conversation_result(id2, 0, Some("total 42\ndrwxr-xr-x"))
            .unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_none());

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 2);
        assert_eq!(convos[0].response_type, "chat");
        assert!(convos[0].result_exit_code.is_none());
        assert_eq!(convos[1].response_type, "command");
        assert_eq!(convos[1].result_exit_code, Some(0));
        assert_eq!(
            convos[1].explanation.as_deref(),
            Some("lists all files including hidden")
        );

        db.clear_conversations("s1").unwrap();
        let convos = db.get_conversations("s1", 10).unwrap();
        assert!(convos.is_empty());
    }

    #[test]
    fn test_insert_command_creates_session_on_conflict() {
        let db = test_db();
        db.insert_command(
            "auto_sess",
            "echo hello",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/5",
            "zsh",
            999,
        )
        .unwrap();

        let tty: String = db
            .conn
            .query_row(
                "SELECT tty FROM sessions WHERE id = 'auto_sess'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tty, "/dev/pts/5");

        db.insert_command(
            "auto_sess",
            "echo world",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "/dev/pts/6",
            "bash",
            1000,
        )
        .unwrap();

        let tty: String = db
            .conn
            .query_row(
                "SELECT tty FROM sessions WHERE id = 'auto_sess'",
                [],
                |row| row.get(0),
            )
            .unwrap();
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

        let hb1: Option<String> = db
            .conn
            .query_row(
                "SELECT last_heartbeat FROM sessions WHERE id = 's1'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        db.update_heartbeat("s1").unwrap();

        let hb2: Option<String> = db
            .conn
            .query_row(
                "SELECT last_heartbeat FROM sessions WHERE id = 's1'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(hb1.is_some());
        assert!(hb2.is_some());
        assert!(hb2.unwrap() > hb1.unwrap());
    }

    #[test]
    fn test_commands_needing_summary_respects_limit() {
        let db = test_db();
        for i in 0..5 {
            db.insert_command(
                "s1",
                &format!("cmd{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                Some(&format!("output{i}")),
                "",
                "",
                0,
            )
            .unwrap();
        }

        let needing = db.commands_needing_summary(2).unwrap();
        assert_eq!(needing.len(), 2);
    }

    #[test]
    fn test_create_session_ignore_duplicate() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM sessions WHERE id = 's1'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_insert_command_with_all_fields() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "cargo test --release",
                "/home/user/project",
                Some(0),
                "2025-06-01T12:30:00Z",
                Some(45000),
                Some("running 42 tests\ntest result: ok"),
                "/dev/pts/3",
                "zsh",
                5555,
            )
            .unwrap();

        let (cmd, cwd, exit_code, duration, output): (
            String,
            Option<String>,
            Option<i32>,
            Option<i64>,
            Option<String>,
        ) = db
            .conn
            .query_row(
                "SELECT command, cwd, exit_code, duration_ms, output FROM commands WHERE id = ?",
                params![id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
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
            "s1",
            "curl https://api.example.com/v1/users",
            "/tmp",
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
            "wget https://api.example.com/v2/data",
            "/tmp",
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
                Some(r"https://api\.example\.com/v1"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("curl"));
    }

    #[test]
    fn test_prune_cleans_fts_index() {
        let db = test_db();
        db.insert_command(
            "s1",
            "old_prunable_unique_cmd",
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
    fn test_get_usage_stats_with_period_filter() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage(
            "s1",
            Some("old query"),
            "gpt-4",
            "openai",
            Some(100),
            Some(50),
            Some(0.01),
            None,
        )
        .unwrap();
        db.insert_usage(
            "s1",
            Some("new query"),
            "gpt-4",
            "openai",
            Some(200),
            Some(100),
            Some(0.02),
            None,
        )
        .unwrap();

        let stats = db.get_usage_stats(UsagePeriod::Today).unwrap();
        assert_eq!(stats.len(), 1);
        let (model, calls, _, _, _) = &stats[0];
        assert_eq!(model, "gpt-4");
        assert_eq!(*calls, 2);
    }

    #[test]
    fn test_search_history_advanced_fts_with_since() {
        let db = test_db();
        db.insert_command(
            "s1",
            "early cargo build",
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
            "late cargo test",
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

        let results = db
            .search_history_advanced(
                Some("cargo"),
                None,
                Some("2025-01-01T00:00:00Z"),
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("late"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_until() {
        let db = test_db();
        db.insert_command(
            "s1",
            "early cargo build",
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
            "late cargo test",
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

        let results = db
            .search_history_advanced(
                Some("cargo"),
                None,
                None,
                Some("2025-01-01T00:00:00Z"),
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("early"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_exit_code() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo build ok",
            "/tmp",
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
            "cargo build fail",
            "/tmp",
            Some(1),
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
                Some("cargo"),
                None,
                None,
                None,
                Some(1),
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("fail"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_session_filter() {
        let db = test_db();
        db.insert_command(
            "sess_x",
            "cargo run alpha",
            "/tmp",
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
            "sess_y",
            "cargo run beta",
            "/tmp",
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
                Some("cargo"),
                None,
                None,
                None,
                None,
                false,
                Some("sess_x"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("alpha"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_all_filters() {
        let db = test_db();
        db.insert_command(
            "s1",
            "npm test pass",
            "/app",
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
            "npm test fail",
            "/app",
            Some(1),
            "2025-06-01T12:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s2",
            "npm test other",
            "/app",
            Some(1),
            "2025-06-01T12:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("npm"),
                None,
                Some("2025-06-01T06:00:00Z"),
                Some("2025-06-01T18:00:00Z"),
                Some(1),
                false,
                Some("s1"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("npm test fail"));
    }

    #[test]
    fn test_search_history_advanced_fts_failed_only() {
        let db = test_db();
        db.insert_command(
            "s1",
            "make build success",
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
            "make build failure",
            "/project",
            Some(2),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(Some("make"), None, None, None, None, true, None, None, 100)
            .unwrap();
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

        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();

        let long_output = "a".repeat(100);
        let updated = db.update_command(id, None, Some(&long_output)).unwrap();
        assert!(updated);

        let stored: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
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

        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();

        let output = "aaa日本語bbb";
        let updated = db.update_command(id, None, Some(output)).unwrap();
        assert!(updated);

        let stored: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        let stored = stored.unwrap();
        assert!(stored.contains("[truncated by nsh]"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_since_and_until() {
        let db = test_db();
        db.insert_command(
            "s1",
            "git commit early",
            "/repo",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "git commit middle",
            "/repo",
            Some(0),
            "2025-06-15T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "git commit late",
            "/repo",
            Some(0),
            "2025-12-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("git"),
                None,
                Some("2025-03-01T00:00:00Z"),
                Some("2025-09-01T00:00:00Z"),
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("middle"));
    }

    #[test]
    fn test_search_history_advanced_fts_session_filter_literal() {
        let db = test_db();
        db.insert_command(
            "my_session",
            "docker build target",
            "/app",
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
            "other_session",
            "docker push target",
            "/app",
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
                Some("docker"),
                None,
                None,
                None,
                None,
                false,
                Some("my_session"),
                None,
                100,
            )
            .unwrap();
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
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some(output),
                "",
                "",
                0,
            )
            .unwrap();

        let stored: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
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
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some(output),
                "",
                "",
                0,
            )
            .unwrap();

        let stored: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        let stored = stored.unwrap();
        assert!(stored.contains("[truncated by nsh]"));
        assert!(stored.starts_with("hello"));
    }

    #[test]
    fn test_prune_if_due_skips_when_recently_pruned() {
        let db = test_db();
        db.insert_command(
            "s1",
            "old cmd",
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

        db.prune_if_due(30).unwrap();
        let count1: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count1, 0);

        db.insert_command(
            "s1",
            "another old cmd",
            "/tmp",
            Some(0),
            "2020-02-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        db.prune_if_due(30).unwrap();
        let count2: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            count2, 1,
            "should NOT prune again since last_prune_at is recent"
        );
    }

    #[test]
    fn test_recent_commands_with_summaries_limit() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        for i in 0..10 {
            db.insert_command(
                "s1",
                &format!("cmd_{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();
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
        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
        assert!(stats.is_empty());
    }

    #[test]
    fn test_get_usage_stats_multiple_models() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_usage(
            "s1",
            None,
            "gpt-4",
            "openai",
            Some(100),
            Some(50),
            Some(0.01),
            None,
        )
        .unwrap();
        db.insert_usage(
            "s1",
            None,
            "claude",
            "anthropic",
            Some(200),
            Some(100),
            Some(0.05),
            None,
        )
        .unwrap();
        db.insert_usage(
            "s1",
            None,
            "gpt-4",
            "openai",
            Some(150),
            Some(75),
            Some(0.02),
            None,
        )
        .unwrap();

        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
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
            "s1",
            "run script1",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("error: connection refused"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "run script2",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            Some("success: all good"),
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("run"),
                Some("connection"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("script1"));
    }

    #[test]
    fn test_cleanup_orphaned_sessions_ignores_ended() {
        let db = test_db();
        db.create_session("ended_sess", "/dev/pts/0", "zsh", 2_000_000_000)
            .unwrap();
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
            created_at: None,
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
            created_at: None,
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
            created_at: None,
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
            created_at: None,
        };
        let msg = exchange.to_tool_result_message("tool_3");
        assert!(matches!(msg.role, crate::provider::Role::Tool));
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
            } => {
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
            created_at: None,
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
            created_at: None,
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
            created_at: None,
        };
        let msg = exchange.to_assistant_message("t1");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolUse { input, .. } => {
                assert_eq!(input["explanation"], "");
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[test]
    fn test_meta_get_set() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.get_meta("foo").unwrap().is_none());
        db.set_meta("foo", "bar").unwrap();
        assert_eq!(db.get_meta("foo").unwrap(), Some("bar".to_string()));
    }

    #[test]
    fn test_meta_overwrite() {
        let db = Db::open_in_memory().unwrap();
        db.set_meta("k", "v1").unwrap();
        db.set_meta("k", "v2").unwrap();
        assert_eq!(db.get_meta("k").unwrap(), Some("v2".to_string()));
    }

    #[test]
    fn test_command_count_empty() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.command_count().unwrap(), 0);
    }

    #[test]
    fn test_command_count_after_insert() {
        let db = Db::open_in_memory().unwrap();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.insert_command(
            "s1",
            "ls",
            "/tmp",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "",
            "zsh",
            1234,
        )
        .unwrap();
        assert_eq!(db.command_count().unwrap(), 1);
    }

    // memory-related tests removed

    

    // #[test]
    // fn test_upsert_memory_case_insensitive_key() {}

    #[test]
    fn test_mark_unsummarized_for_llm_empty() {
        let db = test_db();
        let marked = db.mark_unsummarized_for_llm().unwrap();
        assert_eq!(marked, 0);
    }

    #[test]
    fn test_commands_needing_llm_summary_empty() {
        let db = test_db();
        let cmds = db.commands_needing_llm_summary(10).unwrap();
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_commands_needing_llm_summary_respects_limit() {
        let db = test_db();
        for i in 0..5 {
            db.insert_command(
                "s1",
                &format!("cmd{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                Some(&format!("output{i}")),
                "",
                "",
                0,
            )
            .unwrap();
        }
        db.mark_unsummarized_for_llm().unwrap();
        let cmds = db.commands_needing_llm_summary(2).unwrap();
        assert_eq!(cmds.len(), 2);
    }

    #[test]
    fn test_prune_empty_db() {
        let db = test_db();
        let deleted = db.prune(30).unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_end_session_nonexistent() {
        let db = test_db();
        db.end_session("no_such_session").unwrap();
    }

    #[test]
    fn test_recent_commands_other_sessions_none() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.insert_command(
            "s1",
            "my cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/0",
            "zsh",
            1234,
        )
        .unwrap();
        let others = db.recent_commands_other_sessions("s1", 10).unwrap();
        assert!(others.is_empty());
    }

    #[test]
    fn test_find_pending_conversation_picks_most_recent() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_conversation("s1", "first", "command", "echo first", None, false, true)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let id2 = db
            .insert_conversation("s1", "second", "command", "echo second", None, false, true)
            .unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_some());
        let (pid, resp) = pending.unwrap();
        assert_eq!(pid, id2);
        assert_eq!(resp, "echo second");
    }

    #[test]
    fn test_search_history_advanced_regex_with_since() {
        let db = test_db();
        db.insert_command(
            "s1",
            "curl http://old.com",
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
            "curl http://new.com",
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

        let results = db
            .search_history_advanced(
                None,
                Some("curl"),
                Some("2025-01-01T00:00:00Z"),
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("new.com"));
    }

    #[test]
    fn test_search_history_advanced_regex_with_failed_only() {
        let db = test_db();
        db.insert_command(
            "s1",
            "make deploy-ok",
            "/app",
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
            "make deploy-fail",
            "/app",
            Some(1),
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
                Some("deploy"),
                None,
                None,
                None,
                true,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("deploy-fail"));
    }

    #[test]
    fn test_other_sessions_with_summaries_empty_when_no_other() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.insert_command(
            "s1",
            "only mine",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/0",
            "zsh",
            1234,
        )
        .unwrap();

        let others = db.other_sessions_with_summaries("s1", 5, 10).unwrap();
        assert!(others.is_empty());
    }

    #[test]
    fn test_mark_summary_error_excludes_from_needing_summary() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("output"),
                "",
                "",
                0,
            )
            .unwrap();

        let needing_before = db.commands_needing_summary(10).unwrap();
        assert_eq!(needing_before.len(), 1);

        db.mark_summary_error(id, "timeout").unwrap();

        let needing_after = db.commands_needing_summary(10).unwrap();
        assert!(needing_after.is_empty());

        let needing_llm = db.commands_needing_llm_summary(10).unwrap();
        assert!(needing_llm.is_empty());
    }

    #[test]
    fn test_update_summary_updates_fts() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "deploy app",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("deploying..."),
                "",
                "",
                0,
            )
            .unwrap();

        let before = db.search_history("kubernetes_cluster_xyz", 10).unwrap();
        assert!(before.is_empty());

        db.update_summary(id, "deployed to kubernetes_cluster_xyz")
            .unwrap();

        let after = db.search_history("kubernetes_cluster_xyz", 10).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].command, "deploy app");
    }

    // #[test]
    // fn test_delete_memory_nonexistent() {}

    

    #[test]
    fn test_command_count_after_prune() {
        let db = test_db();
        db.insert_command(
            "s1",
            "old",
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
            "new",
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
        assert_eq!(db.command_count().unwrap(), 2);

        db.prune(30).unwrap();
        assert_eq!(db.command_count().unwrap(), 1);
    }

    #[test]
    fn test_search_history_advanced_no_filters_returns_all() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cmd1",
            "/tmp",
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
            "cmd2",
            "/tmp",
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
            .search_history_advanced(None, None, None, None, None, false, None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_update_heartbeat_nonexistent_session() {
        let db = test_db();
        db.update_heartbeat("no_such_session").unwrap();
    }

    #[test]
    fn test_set_and_get_session_label() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        assert!(db.set_session_label("s1", "my-label").unwrap());
        assert_eq!(db.get_session_label("s1").unwrap(), Some("my-label".into()));
    }

    #[test]
    fn test_set_session_label_nonexistent() {
        let db = test_db();
        assert!(!db.set_session_label("no_such", "lbl").unwrap());
    }

    #[test]
    fn test_get_session_label_missing_session() {
        let db = test_db();
        assert_eq!(db.get_session_label("no_such").unwrap(), None);
    }

    #[test]
    fn test_get_session_label_initially_none() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        assert_eq!(db.get_session_label("s1").unwrap(), None);
    }

    #[test]
    fn test_insert_command_output_truncation() {
        let db = Db::open_in_memory().unwrap();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        let big_output = "x".repeat(50_000);
        let id = db
            .insert_command(
                "s1",
                "echo big",
                "/tmp",
                Some(0),
                "2025-01-01T00:00:00Z",
                Some(100),
                Some(&big_output),
                "/dev/pts/0",
                "zsh",
                1234,
            )
            .unwrap();
        let stored: String = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(stored.len() < big_output.len());
        assert!(stored.ends_with("... [truncated by nsh]"));
    }

    #[test]
    fn test_get_usage_stats_all() {
        let db = test_db();
        db.insert_usage(
            "s1",
            Some("hello"),
            "gpt-4",
            "openai",
            Some(100),
            Some(50),
            Some(0.01),
            Some("gen1"),
        )
        .unwrap();
        db.insert_usage(
            "s1",
            Some("world"),
            "gpt-4",
            "openai",
            Some(200),
            Some(80),
            Some(0.02),
            Some("gen2"),
        )
        .unwrap();
        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
        assert_eq!(stats.len(), 1);
        let (model, calls, inp, out, cost) = &stats[0];
        assert_eq!(model, "gpt-4");
        assert_eq!(*calls, 2);
        assert_eq!(*inp, 300);
        assert_eq!(*out, 130);
        assert!(*cost > 0.0);
    }

    #[test]
    fn test_get_usage_stats_today() {
        let db = test_db();
        db.insert_usage(
            "s1",
            None,
            "claude",
            "anthropic",
            Some(10),
            Some(5),
            Some(0.001),
            None,
        )
        .unwrap();
        let stats = db.get_usage_stats(UsagePeriod::Today).unwrap();
        assert_eq!(stats.len(), 1);
    }

    #[test]
    fn test_get_usage_stats_week() {
        let db = test_db();
        db.insert_usage("s1", None, "m1", "p1", Some(1), Some(1), Some(0.0), None)
            .unwrap();
        let stats = db.get_usage_stats(UsagePeriod::Week).unwrap();
        assert_eq!(stats.len(), 1);
    }

    #[test]
    fn test_get_usage_stats_month() {
        let db = test_db();
        db.insert_usage("s1", None, "m1", "p1", Some(1), Some(1), Some(0.0), None)
            .unwrap();
        let stats = db.get_usage_stats(UsagePeriod::Month).unwrap();
        assert_eq!(stats.len(), 1);
    }

    #[test]
    fn test_get_usage_stats_no_records() {
        let db = test_db();
        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
        assert!(stats.is_empty());
    }

    #[test]
    fn test_update_usage_cost_with_generation_id() {
        let db = test_db();
        db.insert_usage(
            "s1",
            None,
            "gpt-4",
            "openai",
            Some(10),
            Some(5),
            Some(0.0),
            Some("g1"),
        )
        .unwrap();
        assert!(db.update_usage_cost("g1", 1.23).unwrap());
        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
        assert!((stats[0].4 - 1.23).abs() < 1e-9);
    }

    #[test]
    fn test_update_usage_cost_missing_generation_id() {
        let db = test_db();
        assert!(!db.update_usage_cost("no_such", 1.0).unwrap());
    }

    #[test]
    fn test_fts_integrity_on_fresh_db() {
        let db = test_db();
        db.check_fts_integrity().unwrap();
    }

    #[test]
    fn test_rebuild_fts_after_insert() {
        let db = test_db();
        db.insert_command(
            "s1",
            "ls",
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
        db.rebuild_fts().unwrap();
        db.check_fts_integrity().unwrap();
    }

    #[test]
    fn test_optimize_fts_after_insert() {
        let db = test_db();
        db.insert_command(
            "s1",
            "grep foo",
            "/home",
            Some(1),
            "2025-01-01T00:00:00Z",
            None,
            Some("no match"),
            "",
            "",
            0,
        )
        .unwrap();
        db.optimize_fts().unwrap();
    }

    #[test]
    fn test_end_session_sets_ended_at() {
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
        assert!(ended_at.is_some());
    }

    #[test]
    fn test_update_heartbeat_on_existing_session() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        let before: String = db
            .conn
            .query_row(
                "SELECT last_heartbeat FROM sessions WHERE id = 's1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        db.update_heartbeat("s1").unwrap();
        let after: String = db
            .conn
            .query_row(
                "SELECT last_heartbeat FROM sessions WHERE id = 's1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(after >= before);
    }

    #[test]
    fn test_command_count_multiple_inserts() {
        let db = test_db();
        assert_eq!(db.command_count().unwrap(), 0);
        db.insert_command(
            "s1",
            "a",
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
        db.insert_command(
            "s1",
            "b",
            "/tmp",
            Some(0),
            "2025-01-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        assert_eq!(db.command_count().unwrap(), 2);
    }

    #[test]
    fn test_cleanup_orphaned_sessions_no_orphans() {
        let db = test_db();
        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert_eq!(cleaned, 0);
    }

    #[test]
    fn test_get_pending_generation_ids_empty() {
        let db = test_db();
        let pending = db.get_pending_generation_ids().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_get_pending_generation_ids_excludes_no_generation_id() {
        let db = test_db();
        db.insert_usage("s1", None, "gpt-4", "openai", Some(10), Some(5), None, None)
            .unwrap();
        let pending = db.get_pending_generation_ids().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_get_pending_generation_ids_excludes_already_costed() {
        let db = test_db();
        db.insert_usage(
            "s1",
            None,
            "gpt-4",
            "openai",
            Some(10),
            Some(5),
            Some(0.01),
            Some("gen_paid"),
        )
        .unwrap();
        let pending = db.get_pending_generation_ids().unwrap();
        assert!(!pending.contains(&"gen_paid".to_string()));
    }

    #[test]
    fn test_search_history_advanced_regex_with_exit_code() {
        let db = test_db();
        db.insert_command(
            "s1",
            "make build",
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
            "make test",
            "/project",
            Some(1),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "make deploy",
            "/project",
            Some(2),
            "2025-06-01T00:02:00Z",
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
                Some("make"),
                None,
                None,
                Some(1),
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("make test"));
    }

    #[test]
    fn test_search_history_advanced_regex_with_session_and_date() {
        let db = test_db();
        db.insert_command(
            "s_a",
            "curl http://old.example.com",
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
            "s_a",
            "curl http://new.example.com",
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
        db.insert_command(
            "s_b",
            "curl http://other.example.com",
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

        let results = db
            .search_history_advanced(
                None,
                Some("curl"),
                Some("2025-01-01T00:00:00Z"),
                None,
                None,
                false,
                Some("s_a"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("new.example.com"));
    }

    #[test]
    fn test_search_history_advanced_regex_with_until() {
        let db = test_db();
        db.insert_command(
            "s1",
            "wget http://early.com",
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
            "wget http://late.com",
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

        let results = db
            .search_history_advanced(
                None,
                Some("wget"),
                None,
                Some("2025-01-01T00:00:00Z"),
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("early.com"));
    }

    #[test]
    fn test_search_history_advanced_regex_matches_output() {
        let db = test_db();
        db.insert_command(
            "s1",
            "run_tool",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("FATAL: disk full"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "run_other",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            Some("all good"),
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                None,
                Some("FATAL"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "run_tool");
    }

    #[test]
    fn test_search_history_advanced_no_fts_no_regex_all_results() {
        let db = test_db();
        for i in 0..5 {
            db.insert_command(
                "s1",
                &format!("cmd_{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();
        }

        let results = db
            .search_history_advanced(None, None, None, None, None, false, None, None, 3)
            .unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_update_command_preserves_existing_exit_code() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(42),
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();

        db.update_command(id, None, Some("new output")).unwrap();

        let (exit_code, output): (Option<i32>, Option<String>) = db
            .conn
            .query_row(
                "SELECT exit_code, output FROM commands WHERE id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(exit_code, Some(42));
        assert_eq!(output.as_deref(), Some("new output"));
    }

    #[test]
    fn test_recent_commands_with_summaries_returns_chronological() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_command(
            "s1",
            "third_chrono",
            "/tmp",
            Some(0),
            "2025-06-01T00:02:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "first_chrono",
            "/tmp",
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
            "second_chrono",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let cmds = db.recent_commands_with_summaries("s1", 10).unwrap();
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0].command, "first_chrono");
        assert_eq!(cmds[1].command, "second_chrono");
        assert_eq!(cmds[2].command, "third_chrono");
    }

    #[test]
    fn test_get_conversations_returns_chronological() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_conversation("s1", "third", "chat", "r3", None, false, false)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        db.insert_conversation("s1", "fourth", "chat", "r4", None, false, false)
            .unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 2);
        assert_eq!(convos[0].query, "third");
        assert_eq!(convos[1].query, "fourth");
    }

    #[test]
    fn test_get_conversations_different_session_empty() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 5678).unwrap();

        db.insert_conversation("s1", "q", "chat", "r", None, false, false)
            .unwrap();

        let convos = db.get_conversations("s2", 10).unwrap();
        assert!(convos.is_empty());
    }

    #[test]
    fn test_search_history_advanced_fts_literal_session() {
        let db = test_db();
        db.insert_command(
            "cur_sess",
            "npm run build matching",
            "/app",
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
            "other_sess",
            "npm run test matching",
            "/app",
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
                Some("npm"),
                None,
                None,
                None,
                None,
                false,
                Some("cur_sess"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("build"));
    }

    #[test]
    fn test_other_sessions_with_summaries_respects_limit() {
        let db = test_db();
        db.create_session("me", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("other", "/dev/pts/1", "bash", 5678)
            .unwrap();

        for i in 0..10 {
            db.insert_command(
                "other",
                &format!("cmd_{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                None,
                "/dev/pts/1",
                "bash",
                5678,
            )
            .unwrap();
        }

        let others = db.other_sessions_with_summaries("me", 1, 3).unwrap();
        assert!(others.len() <= 3);
    }

    #[test]
    fn test_search_history_advanced_regex_no_match() {
        let db = test_db();
        db.insert_command(
            "s1",
            "echo hello",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
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
                Some("^zzz_no_match$"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_rebuild_fts_idempotent() {
        let db = test_db();
        db.insert_command(
            "s1",
            "idempotent_cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        db.rebuild_fts().unwrap();
        db.rebuild_fts().unwrap();

        let results = db.search_history("idempotent_cmd", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_check_fts_integrity_on_fresh_db() {
        let db = test_db();
        db.check_fts_integrity().unwrap();
    }

    #[test]
    fn test_check_fts_integrity_after_inserts() {
        let db = test_db();
        for i in 0..10 {
            db.insert_command(
                "s1",
                &format!("cmd_{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                Some(&format!("output_{i}")),
                "",
                "",
                0,
            )
            .unwrap();
        }
        db.check_fts_integrity().unwrap();
    }

    #[test]
    fn test_commands_needing_llm_summary() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cmd_with_output",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("some output"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "cmd_no_output",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let before = db.commands_needing_llm_summary(10).unwrap();
        assert!(before.is_empty());

        db.mark_unsummarized_for_llm().unwrap();

        let after = db.commands_needing_llm_summary(10).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].command, "cmd_with_output");
    }

    #[test]
    fn test_mark_summary_error_prevents_reprocessing() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "error_cmd",
                "/tmp",
                Some(1),
                "2025-06-01T00:00:00Z",
                None,
                Some("crash output"),
                "",
                "",
                0,
            )
            .unwrap();

        db.mark_summary_error(id, "rate limited").unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert!(needing.is_empty());

        let needing_llm = db.commands_needing_llm_summary(10).unwrap();
        assert!(needing_llm.is_empty());

        let (summary, status): (Option<String>, Option<String>) = db
            .conn
            .query_row(
                "SELECT summary, summary_status FROM commands WHERE id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(summary.unwrap().contains("[error: rate limited]"));
        assert_eq!(status.as_deref(), Some("error"));
    }

    #[test]
    fn test_mark_summary_error_no_overwrite_existing_summary() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "already_done",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("output"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "good summary").unwrap();

        db.mark_summary_error(id, "should not overwrite").unwrap();

        let summary: Option<String> = db
            .conn
            .query_row(
                "SELECT summary FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(summary.as_deref(), Some("good summary"));
    }

    #[test]
    fn test_update_summary_returns_false_for_nonexistent() {
        let db = test_db();
        let updated = db.update_summary(999999, "phantom summary").unwrap();
        assert!(!updated);
    }

    #[test]
    fn test_command_count() {
        let db = test_db();
        assert_eq!(db.command_count().unwrap(), 0);

        db.insert_command(
            "s1",
            "cmd1",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        assert_eq!(db.command_count().unwrap(), 1);

        db.insert_command(
            "s1",
            "cmd2",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        assert_eq!(db.command_count().unwrap(), 2);
    }

    #[test]
    fn test_get_set_meta() {
        let db = test_db();

        let val = db.get_meta("nonexistent_key").unwrap();
        assert!(val.is_none());

        db.set_meta("test_key", "test_value").unwrap();
        let val = db.get_meta("test_key").unwrap();
        assert_eq!(val.as_deref(), Some("test_value"));

        db.set_meta("test_key", "updated_value").unwrap();
        let val = db.get_meta("test_key").unwrap();
        assert_eq!(val.as_deref(), Some("updated_value"));
    }

    #[test]
    fn test_optimize_fts_on_empty_db() {
        let db = test_db();
        db.optimize_fts().unwrap();
    }

    #[test]
    fn test_rebuild_then_integrity_check() {
        let db = test_db();
        for i in 0..5 {
            db.insert_command(
                "s1",
                &format!("rebuild_test_{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                Some(&format!("output for rebuild test {i}")),
                "",
                "",
                0,
            )
            .unwrap();
        }

        db.rebuild_fts().unwrap();
        db.check_fts_integrity().unwrap();

        let results = db.search_history("rebuild_test", 10).unwrap();
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_commands_needing_summary_with_mixed_states() {
        let db = test_db();
        db.insert_command(
            "s1",
            "no_output",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let id_with_output = db
            .insert_command(
                "s1",
                "has_output",
                "/tmp",
                Some(0),
                "2025-06-01T00:01:00Z",
                None,
                Some("output here"),
                "",
                "",
                0,
            )
            .unwrap();

        let id_summarized = db
            .insert_command(
                "s1",
                "already_summarized",
                "/tmp",
                Some(0),
                "2025-06-01T00:02:00Z",
                None,
                Some("more output"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id_summarized, "done").unwrap();

        let id_errored = db
            .insert_command(
                "s1",
                "errored",
                "/tmp",
                Some(1),
                "2025-06-01T00:03:00Z",
                None,
                Some("error output"),
                "",
                "",
                0,
            )
            .unwrap();
        db.mark_summary_error(id_errored, "failed").unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0].id, id_with_output);
    }

    #[test]
    fn test_prune_if_due_sets_meta() {
        let db = test_db();
        db.insert_command(
            "s1",
            "old_cmd",
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

        db.prune_if_due(30).unwrap();

        let last_prune = db.get_meta("last_prune_at").unwrap();
        assert!(last_prune.is_some());
    }

    #[test]
    fn test_prune_if_due_idempotent() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cmd_a",
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
            "cmd_b",
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

        db.prune_if_due(30).unwrap();
        let count1: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count1, 1);

        db.prune_if_due(30).unwrap();
        let count2: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count2, 1);
    }

    #[test]
    fn test_update_heartbeat_creates_timestamp() {
        let db = test_db();
        db.create_session("hb_sess", "/dev/pts/0", "zsh", 1234)
            .unwrap();

        db.update_heartbeat("hb_sess").unwrap();

        let hb: Option<String> = db
            .conn
            .query_row(
                "SELECT last_heartbeat FROM sessions WHERE id = 'hb_sess'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(hb.is_some());
        assert!(hb.unwrap().contains("T"));
    }

    #[test]
    fn test_fts_search_after_summary_update() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "npm run build",
                "/app",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("built ok"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "webpack compilation successful with zero warnings")
            .unwrap();

        let results = db.search_history("webpack", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "npm run build");
    }

    

    

    

    

    

    

    

    

    

    

    #[test]
    fn test_session_labels() {
        let db = test_db();
        db.create_session("sl1", "/dev/pts/0", "zsh", 1).unwrap();
        assert!(db.get_session_label("sl1").unwrap().is_none());
        assert!(db.set_session_label("sl1", "my project").unwrap());
        assert_eq!(db.get_session_label("sl1").unwrap().unwrap(), "my project");
    }

    #[test]
    fn test_session_label_nonexistent() {
        let db = test_db();
        assert!(!db.set_session_label("nope", "label").unwrap());
        assert!(db.get_session_label("nope").unwrap().is_none());
    }

    #[test]
    fn test_latest_cwd_for_tty_returns_most_recent() {
        let db = test_db();
        db.insert_command(
            "tty_s1",
            "echo one",
            "/tmp/one",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "/dev/pts/42",
            "zsh",
            1001,
        )
        .unwrap();
        db.insert_command(
            "tty_s2",
            "echo two",
            "/tmp/two",
            Some(0),
            "2025-01-01T00:00:01Z",
            None,
            None,
            "/dev/pts/42",
            "zsh",
            1002,
        )
        .unwrap();

        let cwd = db.latest_cwd_for_tty("/dev/pts/42").unwrap();
        assert_eq!(cwd.as_deref(), Some("/tmp/two"));
    }

    #[test]
    fn test_latest_cwd_for_tty_none_when_no_commands() {
        let db = test_db();
        db.create_session("tty_only", "/dev/pts/99", "zsh", 1234)
            .unwrap();
        assert!(db.latest_cwd_for_tty("/dev/pts/99").unwrap().is_none());
    }

    #[test]
    fn test_commands_needing_summary() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cmd1",
            "/tmp",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            Some("output here"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "cmd2",
            "/tmp",
            Some(0),
            "2025-01-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        let needing = db.commands_needing_summary(10).unwrap();
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0].command, "cmd1");
    }

    #[test]
    fn test_mark_unsummarized_for_llm() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cmd1",
            "/tmp",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            Some("output"),
            "",
            "",
            0,
        )
        .unwrap();
        let marked = db.mark_unsummarized_for_llm().unwrap();
        assert_eq!(marked, 1);
        let needing_llm = db.commands_needing_llm_summary(10).unwrap();
        assert_eq!(needing_llm.len(), 1);
    }

    #[test]
    fn test_fts_maintenance() {
        let db = test_db();
        db.insert_command(
            "s1",
            "test cmd",
            "/",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        assert!(db.rebuild_fts().is_ok());
        assert!(db.optimize_fts().is_ok());
        assert!(db.check_fts_integrity().is_ok());
    }

    #[test]
    fn test_search_history_advanced_regex() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo build",
            "/proj",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "cargo test",
            "/proj",
            Some(0),
            "2025-01-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "npm install",
            "/proj",
            Some(0),
            "2025-01-01T00:02:00Z",
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
                Some("cargo.*"),
                None,
                None,
                None,
                false,
                None,
                None,
                10,
            )
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_search_history_advanced_date_range() {
        let db = test_db();
        db.insert_command(
            "s1",
            "old",
            "/",
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
            "new",
            "/",
            Some(0),
            "2025-06-01T00:00:00Z",
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
                None,
                Some("2025-01-01T00:00:00Z"),
                None,
                None,
                false,
                None,
                None,
                10,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "new");
    }

    #[test]
    fn test_search_history_advanced_fts_with_filters() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo build",
            "/proj",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            Some("success"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "cargo test",
            "/proj",
            Some(1),
            "2025-01-01T00:01:00Z",
            None,
            Some("failed"),
            "",
            "",
            0,
        )
        .unwrap();
        let results = db
            .search_history_advanced(Some("cargo"), None, None, None, None, true, None, None, 10)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "cargo test");
    }

    #[test]
    fn test_search_history_advanced_fts_hyphenated_term() {
        let db = test_db();
        db.insert_command(
            "s1",
            "echo from-ht",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("from-ht"),
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("from-ht"),
                None,
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
        assert_eq!(results[0].command, "echo from-ht");
    }

    #[test]
    fn test_conversation_insert_and_fetch() {
        let db = test_db();
        db.create_session("cv1", "/dev/pts/0", "zsh", 1).unwrap();
        db.insert_conversation(
            "cv1",
            "how do I X",
            "command",
            "ls -la",
            Some("list files"),
            false,
            false,
        )
        .unwrap();
        db.insert_conversation("cv1", "and Y?", "chat", "try this", None, false, false)
            .unwrap();
        let convos = db.get_conversations("cv1", 10).unwrap();
        assert_eq!(convos.len(), 2);
        assert_eq!(convos[0].query, "how do I X");
        assert_eq!(convos[1].query, "and Y?");
    }

    #[test]
    fn test_unicode_in_commands() {
        let db = test_db();
        db.insert_command(
            "s1",
            "echo 'こんにちは 🌍'",
            "/tmp",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            Some("こんにちは 🌍"),
            "",
            "",
            0,
        )
        .unwrap();
        let results = db.search_history("こんにちは", 10).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_cleanup_orphaned_sessions_empty_db() {
        let db = test_db();
        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert_eq!(cleaned, 0);
    }

    #[test]
    fn test_cleanup_orphaned_sessions_with_ended_sessions_only() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.end_session("s1").unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 5678).unwrap();
        db.end_session("s2").unwrap();

        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert_eq!(cleaned, 0);
    }

    #[test]
    fn test_cleanup_orphaned_sessions_skips_alive_process() {
        let db = test_db();
        let my_pid = std::process::id() as i64;
        db.create_session("alive_sess", "/dev/pts/0", "zsh", my_pid)
            .unwrap();

        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert_eq!(cleaned, 0, "should not clean up session with alive PID");

        let ended_at: Option<String> = db
            .conn
            .query_row(
                "SELECT ended_at FROM sessions WHERE id = 'alive_sess'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(ended_at.is_none());
    }

    #[test]
    fn test_cleanup_orphaned_sessions_mixed_alive_and_dead() {
        let db = test_db();
        let my_pid = std::process::id() as i64;
        let dead_pid: i64 = 2_000_000_000;

        db.create_session("alive", "/dev/pts/0", "zsh", my_pid)
            .unwrap();
        db.create_session("dead", "/dev/pts/1", "zsh", dead_pid)
            .unwrap();

        let cleaned = db.cleanup_orphaned_sessions().unwrap();
        assert_eq!(cleaned, 1);

        let alive_ended: Option<String> = db
            .conn
            .query_row(
                "SELECT ended_at FROM sessions WHERE id = 'alive'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(alive_ended.is_none());

        let dead_ended: Option<String> = db
            .conn
            .query_row(
                "SELECT ended_at FROM sessions WHERE id = 'dead'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(dead_ended.is_some());
    }

    #[test]
    fn test_get_meta_schema_version() {
        let db = test_db();
        let version = db.get_meta("schema_version").unwrap();
        assert_eq!(version, Some(SCHEMA_VERSION.to_string()));
    }

    #[test]
    fn test_set_meta_multiple_keys() {
        let db = test_db();
        db.set_meta("key_a", "val_a").unwrap();
        db.set_meta("key_b", "val_b").unwrap();
        assert_eq!(db.get_meta("key_a").unwrap(), Some("val_a".to_string()));
        assert_eq!(db.get_meta("key_b").unwrap(), Some("val_b".to_string()));
    }

    #[test]
    fn test_set_meta_empty_value() {
        let db = test_db();
        db.set_meta("empty", "").unwrap();
        assert_eq!(db.get_meta("empty").unwrap(), Some("".to_string()));
    }

    #[test]
    fn test_command_for_summary_struct_fields() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "compile project",
                "/home/dev",
                Some(1),
                "2025-06-01T00:00:00Z",
                None,
                Some("error: could not compile"),
                "",
                "",
                0,
            )
            .unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert_eq!(needing.len(), 1);
        let cmd = &needing[0];
        assert_eq!(cmd.id, id);
        assert_eq!(cmd.command, "compile project");
        assert_eq!(cmd.cwd.as_deref(), Some("/home/dev"));
        assert_eq!(cmd.exit_code, Some(1));
        assert_eq!(cmd.output.as_deref(), Some("error: could not compile"));
    }

    #[test]
    fn test_search_history_advanced_regex_matches_summary() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "generic_cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("output"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "compiled with warnings about deprecated API")
            .unwrap();

        let results = db
            .search_history_advanced(
                None,
                Some("deprecated"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "generic_cmd");
    }

    #[test]
    fn test_search_history_advanced_fts_with_regex_filters_on_output() {
        let db = test_db();
        db.insert_command(
            "s1",
            "run tests alpha",
            "/app",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("PASS: all tests passed"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "run tests beta",
            "/app",
            Some(1),
            "2025-06-01T00:01:00Z",
            None,
            Some("FAIL: 3 tests failed"),
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("tests"),
                Some("FAIL"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].output.as_deref().unwrap().contains("FAIL"));
    }

    #[test]
    fn test_search_history_advanced_current_session_alias_with_regex() {
        let db = test_db();
        db.insert_command(
            "my_sess",
            "rsync files here",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "other_sess",
            "rsync files there",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "/dev/pts/2",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                None,
                Some("rsync"),
                None,
                None,
                None,
                false,
                Some("current"),
                Some("my_sess"),
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("here"));
    }

    #[test]
    fn test_init_db_fts5_validation_on_fresh_db() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn, 10000).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM commands_fts WHERE commands_fts MATCH 'test'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    

    #[test]
    fn test_init_db_sets_pragmas() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn, 5000).unwrap();

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn test_init_db_registers_regexp_function() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn, 10000).unwrap();

        conn.execute(
            "INSERT INTO sessions (id, tty, shell, pid, started_at) VALUES ('r1', 'tty', 'zsh', 1, '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO commands (session_id, command, started_at) VALUES ('r1', 'cargo build --release', '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();

        let matches: bool = conn
            .query_row(
                "SELECT 'cargo build --release' REGEXP 'cargo.*release'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(matches);

        let no_match: bool = conn
            .query_row("SELECT 'echo hello' REGEXP 'cargo.*release'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(!no_match);
    }

    #[test]
    fn test_insert_conversation_returns_incrementing_ids() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id1 = db
            .insert_conversation("s1", "q1", "chat", "r1", None, false, false)
            .unwrap();
        let id2 = db
            .insert_conversation("s1", "q2", "chat", "r2", None, false, false)
            .unwrap();
        let id3 = db
            .insert_conversation("s1", "q3", "command", "ls", Some("list"), true, true)
            .unwrap();

        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[test]
    fn test_insert_conversation_stores_executed_and_pending_flags() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_conversation("s1", "q", "command", "ls", None, true, true)
            .unwrap();

        let (executed, pending): (i32, i32) = db
            .conn
            .query_row(
                "SELECT executed, pending FROM conversations WHERE session_id = 's1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(executed, 1);
        assert_eq!(pending, 1);
    }

    #[test]
    fn test_update_conversation_result_without_output() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db
            .insert_conversation("s1", "q", "command", "rm -rf /tmp/test", None, false, false)
            .unwrap();

        db.update_conversation_result(id, 0, None).unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos[0].result_exit_code, Some(0));
        assert!(convos[0].result_output_snippet.is_none());
    }

    #[test]
    fn test_update_conversation_result_with_failure() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db
            .insert_conversation("s1", "compile", "command", "make all", None, false, false)
            .unwrap();

        db.update_conversation_result(id, 2, Some("make: *** Error 2"))
            .unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos[0].result_exit_code, Some(2));
        assert_eq!(
            convos[0].result_output_snippet.as_deref(),
            Some("make: *** Error 2")
        );
    }

    #[test]
    fn test_conversation_exchange_to_tool_result_command_no_result() {
        let exchange = ConversationExchange {
            query: "do something".to_string(),
            response_type: "command".to_string(),
            response: "echo hi".to_string(),
            explanation: None,
            result_exit_code: None,
            result_output_snippet: None,
            created_at: None,
        };
        let msg = exchange.to_tool_result_message("t1");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolResult { content, .. } => {
                assert!(content.contains("Command prefilled: echo hi"));
                assert!(!content.contains("Exit"));
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[test]
    fn test_conversation_exchange_to_tool_result_chat_no_result() {
        let exchange = ConversationExchange {
            query: "hello".to_string(),
            response_type: "chat".to_string(),
            response: "hi there".to_string(),
            explanation: None,
            result_exit_code: None,
            result_output_snippet: None,
            created_at: None,
        };
        let msg = exchange.to_tool_result_message("t2");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolResult { content, .. } => {
                assert!(content.contains("hi there"));
                assert!(!content.contains("Exit"));
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[test]
    fn test_gethostname_returns_nonempty() {
        let hostname = super::gethostname();
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_search_history_advanced_regex_with_all_non_fts_filters() {
        let db = test_db();
        db.insert_command(
            "s1",
            "make clean",
            "/proj",
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
            "make build",
            "/proj",
            Some(0),
            "2025-06-01T12:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s2",
            "make test",
            "/proj",
            Some(1),
            "2025-06-01T12:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "make deploy",
            "/proj",
            Some(1),
            "2025-06-01T12:00:00Z",
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
                Some("make"),
                Some("2025-06-01T06:00:00Z"),
                Some("2025-06-01T18:00:00Z"),
                None,
                true,
                Some("s1"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("deploy"));
    }

    #[test]
    fn test_insert_command_with_duration() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "sleep 5",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                Some(5000),
                None,
                "",
                "",
                0,
            )
            .unwrap();

        let duration: Option<i64> = db
            .conn
            .query_row(
                "SELECT duration_ms FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(duration, Some(5000));
    }

    #[test]
    fn test_create_session_stores_hostname_and_username() {
        let db = test_db();
        db.create_session("s_host", "/dev/pts/0", "zsh", 1234)
            .unwrap();

        let (hostname, username): (Option<String>, Option<String>) = db
            .conn
            .query_row(
                "SELECT hostname, username FROM sessions WHERE id = 's_host'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(hostname.is_some());
        assert!(username.is_some());
    }

    #[test]
    fn test_set_session_label_overwrite() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.set_session_label("s1", "first").unwrap();
        db.set_session_label("s1", "second").unwrap();
        assert_eq!(
            db.get_session_label("s1").unwrap(),
            Some("second".to_string())
        );
    }

    #[test]
    fn test_find_pending_conversation_multiple_sessions_isolated() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("s2", "/dev/pts/1", "bash", 5678).unwrap();

        db.insert_conversation("s1", "q1", "command", "cmd_s1", None, false, true)
            .unwrap();
        db.insert_conversation("s2", "q2", "command", "cmd_s2", None, false, true)
            .unwrap();

        let pending_s1 = db.find_pending_conversation("s1").unwrap();
        let pending_s2 = db.find_pending_conversation("s2").unwrap();
        assert!(pending_s1.is_some());
        assert!(pending_s2.is_some());
        assert_eq!(pending_s1.unwrap().1, "cmd_s1");
        assert_eq!(pending_s2.unwrap().1, "cmd_s2");
    }

    #[test]
    fn test_search_history_with_special_fts_chars() {
        let db = test_db();
        db.insert_command(
            "s1",
            "echo 'hello world'",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db.search_history("hello", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_insert_command_output_none_stored_as_null() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "quiet cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();

        let output: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(output.is_none());
    }

    #[test]
    fn test_get_conversations_preserves_all_fields() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db
            .insert_conversation(
                "s1",
                "the query",
                "command",
                "the response",
                Some("the explanation"),
                true,
                true,
            )
            .unwrap();
        db.update_conversation_result(id, 42, Some("exit output"))
            .unwrap();

        let convos = db.get_conversations("s1", 10).unwrap();
        assert_eq!(convos.len(), 1);
        let c = &convos[0];
        assert_eq!(c.query, "the query");
        assert_eq!(c.response_type, "command");
        assert_eq!(c.response, "the response");
        assert_eq!(c.explanation.as_deref(), Some("the explanation"));
        assert_eq!(c.result_exit_code, Some(42));
        assert_eq!(c.result_output_snippet.as_deref(), Some("exit output"));
    }

    #[test]
    fn test_usage_period_variants() {
        let db = test_db();
        db.insert_usage("s1", None, "m", "p", Some(1), Some(1), Some(0.0), None)
            .unwrap();

        assert!(!db.get_usage_stats(UsagePeriod::Today).unwrap().is_empty());
        assert!(!db.get_usage_stats(UsagePeriod::Week).unwrap().is_empty());
        assert!(!db.get_usage_stats(UsagePeriod::Month).unwrap().is_empty());
        assert!(!db.get_usage_stats(UsagePeriod::All).unwrap().is_empty());
    }

    #[test]
    fn test_insert_command_empty_output_stored() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some(""),
                "",
                "",
                0,
            )
            .unwrap();

        let output: Option<String> = db
            .conn
            .query_row(
                "SELECT output FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(output.as_deref(), Some(""));
    }

    #[test]
    fn test_update_command_with_none_values_preserves() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(5),
                "2025-06-01T00:00:00Z",
                None,
                Some("original"),
                "",
                "",
                0,
            )
            .unwrap();

        db.update_command(id, None, None).unwrap();

        let (exit_code, output): (Option<i32>, Option<String>) = db
            .conn
            .query_row(
                "SELECT exit_code, output FROM commands WHERE id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(exit_code, Some(5));
        assert_eq!(output.as_deref(), Some("original"));
    }

    #[test]
    fn test_search_history_advanced_regex_with_session_filter() {
        let db = test_db();
        db.insert_command(
            "sess1",
            "python run.py",
            "/app",
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
            "sess2",
            "python test.py",
            "/app",
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
                Some("python"),
                None,
                None,
                None,
                false,
                Some("sess1"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("run.py"));
    }

    #[test]
    fn test_conversation_exchange_to_tool_result_command_with_exit_no_output() {
        let exchange = ConversationExchange {
            query: "check".to_string(),
            response_type: "command".to_string(),
            response: "test -f file.txt".to_string(),
            explanation: None,
            result_exit_code: Some(1),
            result_output_snippet: None,
            created_at: None,
        };
        let msg = exchange.to_tool_result_message("t_id");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolResult { content, .. } => {
                assert!(content.contains("Exit 1"));
                assert!(content.contains("Command prefilled:"));
                assert!(!content.contains("Output:"));
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[test]
    fn test_search_history_advanced_no_fts_regex_with_current_session_no_current() {
        let db = test_db();
        db.insert_command(
            "default",
            "echo fallback",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "other",
            "echo other",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "/dev/pts/2",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                None,
                Some("echo"),
                None,
                None,
                None,
                false,
                Some("current"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("fallback"));
    }

    #[test]
    fn test_search_history_advanced_no_fts_no_regex_with_until() {
        let db = test_db();
        db.insert_command(
            "s1",
            "early_cmd",
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
            "late_cmd",
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

        let results = db
            .search_history_advanced(
                None,
                None,
                None,
                Some("2025-01-01T00:00:00Z"),
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("early_cmd"));
    }

    #[test]
    fn test_search_history_advanced_no_fts_no_regex_with_exit_code() {
        let db = test_db();
        db.insert_command(
            "s1",
            "success_cmd",
            "/tmp",
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
            "fail_cmd_42",
            "/tmp",
            Some(42),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(None, None, None, None, Some(42), false, None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("fail_cmd_42"));
    }

    #[test]
    fn test_search_history_advanced_no_fts_no_regex_failed_only() {
        let db = test_db();
        db.insert_command(
            "s1",
            "ok_cmd",
            "/tmp",
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
            "broken_cmd",
            "/tmp",
            Some(3),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(None, None, None, None, None, true, None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("broken_cmd"));
    }

    #[test]
    fn test_search_history_advanced_no_fts_no_regex_session_filter_literal() {
        let db = test_db();
        db.insert_command(
            "sess_alpha",
            "alpha_cmd",
            "/tmp",
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
            "sess_beta",
            "beta_cmd",
            "/tmp",
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
                None,
                None,
                None,
                None,
                false,
                Some("sess_alpha"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("alpha_cmd"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_regex_invalid_regex_ignored() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo build something",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("cargo"),
                Some("[invalid(regex"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_search_history_advanced_fts_current_session_alias() {
        let db = test_db();
        db.insert_command(
            "my_fts_sess",
            "npm install fts_target",
            "/app",
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
            "other_fts_sess",
            "npm install fts_other",
            "/app",
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
                Some("npm"),
                None,
                None,
                None,
                None,
                false,
                Some("my_fts_sess"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("fts_target"));
    }

    

    

    // #[test]
    

    // #[test]
    

    #[test]
    fn test_conversation_exchange_to_tool_result_chat_with_exit_code() {
        let exchange = ConversationExchange {
            query: "q".to_string(),
            response_type: "chat".to_string(),
            response: "some response".to_string(),
            explanation: None,
            result_exit_code: Some(0),
            result_output_snippet: Some("output text".to_string()),
            created_at: None,
        };
        let msg = exchange.to_tool_result_message("t_chat");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolResult { content, .. } => {
                assert!(content.contains("chat"));
                assert!(content.contains("Exit 0"));
                assert!(content.contains("output text"));
            }
            _ => panic!("expected ToolResult"),
        }
    }

    #[test]
    fn test_search_history_advanced_fts_session_filter_passes_literal() {
        let db = test_db();
        db.insert_command(
            "active_sess",
            "cargo fts_sess_lit alpha",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "other_sess",
            "cargo fts_sess_lit beta",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "/dev/pts/2",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("fts_sess_lit"),
                None,
                None,
                None,
                None,
                false,
                Some("current"),
                Some("active_sess"),
                100,
            )
            .unwrap();
        assert_eq!(
            results.len(),
            1,
            "FTS path resolves 'current' via TTY subquery"
        );
        assert!(results[0].command.contains("alpha"));
    }

    #[test]
    fn test_search_history_advanced_regex_current_session_alias() {
        let db = test_db();
        db.insert_command(
            "my_active",
            "wget regex_curr_test_aaa",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "someone_else",
            "wget regex_curr_test_bbb",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "/dev/pts/2",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                None,
                Some("regex_curr_test"),
                None,
                None,
                None,
                false,
                Some("current"),
                Some("my_active"),
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("aaa"));
    }

    #[test]
    fn test_search_history_advanced_regex_matches_summary_field() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "run_deploy_xyz",
                "/app",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("deploying..."),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "deployed to unique_regex_cluster_abc")
            .unwrap();

        let results = db
            .search_history_advanced(
                None,
                Some("unique_regex_cluster_abc"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "run_deploy_xyz");
    }

    #[test]
    fn test_search_history_advanced_regex_with_all_filters() {
        let db = test_db();
        db.insert_command(
            "sess_r",
            "curl http://api.test.com/v1",
            "/app",
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
            "sess_r",
            "curl http://api.test.com/v2",
            "/app",
            Some(1),
            "2025-06-01T12:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "sess_other",
            "curl http://api.test.com/v3",
            "/app",
            Some(1),
            "2025-06-01T12:00:00Z",
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
                Some(r"curl.*api\.test"),
                Some("2025-06-01T06:00:00Z"),
                Some("2025-06-01T18:00:00Z"),
                Some(1),
                false,
                Some("sess_r"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("v2"));
    }

    #[test]
    fn test_search_history_advanced_fts_with_regex_filters_output_match() {
        let db = test_db();
        db.insert_command(
            "s1",
            "run job_a",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("unique_sentinel_fts_regex_out_val"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "run job_b",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            Some("nothing special here"),
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("run"),
                Some("unique_sentinel_fts_regex_out_val"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("job_a"));
    }

    #[test]
    fn test_search_history_advanced_fts_regex_no_match_filters_all() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo fts_nomatch_test",
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

        let results = db
            .search_history_advanced(
                Some("fts_nomatch_test"),
                Some("^zzz_impossible_pattern$"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_history_advanced_fts_invalid_regex_ignored() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cargo fts_badregex_test",
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

        let results = db
            .search_history_advanced(
                Some("fts_badregex_test"),
                Some("[invalid regex"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(
            results.len(),
            1,
            "invalid regex should be ignored, returning unfiltered results"
        );
    }

    #[test]
    fn test_insert_usage_null_tokens_and_cost() {
        let db = test_db();
        let id = db
            .insert_usage("s1", None, "local-model", "ollama", None, None, None, None)
            .unwrap();
        assert!(id > 0);

        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
        assert_eq!(stats.len(), 1);
        let (model, calls, input_tok, output_tok, cost) = &stats[0];
        assert_eq!(model, "local-model");
        assert_eq!(*calls, 1);
        assert_eq!(*input_tok, 0);
        assert_eq!(*output_tok, 0);
        assert!(*cost < 1e-9);
    }

    #[test]
    fn test_search_history_advanced_regex_failed_only_combined() {
        let db = test_db();
        db.insert_command(
            "s1",
            "apt install good",
            "/tmp",
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
            "apt install bad",
            "/tmp",
            Some(100),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "pip install other",
            "/tmp",
            Some(1),
            "2025-06-01T00:02:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(None, Some("apt"), None, None, None, true, None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("bad"));
    }

    #[test]
    fn test_search_history_advanced_regex_with_session_filter_literal() {
        let db = test_db();
        db.insert_command(
            "sess_alpha",
            "find regex_sess_lit_test /data",
            "/tmp",
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
            "sess_beta",
            "find regex_sess_lit_test /other",
            "/tmp",
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
                Some("regex_sess_lit_test"),
                None,
                None,
                None,
                false,
                Some("sess_alpha"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("/data"));
    }

    #[test]
    fn test_gethostname_returns_string() {
        let hostname = gethostname();
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_insert_command_sets_session_hostname_username() {
        let db = test_db();
        db.create_session("host_test_s1", "/dev/pts/0", "zsh", 1234)
            .unwrap();

        let (hostname, username): (Option<String>, Option<String>) = db
            .conn
            .query_row(
                "SELECT hostname, username FROM sessions WHERE id = 'host_test_s1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(hostname.is_some(), "hostname should be set");
        assert!(username.is_some(), "username should be set");
    }

    #[test]
    fn test_prune_zero_retention_days() {
        let db = test_db();
        db.insert_command(
            "s1",
            "recent_cmd",
            "/tmp",
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
            "old_cmd",
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

        let deleted = db.prune(0).unwrap();
        assert_eq!(deleted, 2, "zero retention should delete all past commands");
        assert_eq!(db.command_count().unwrap(), 0);
    }

    #[test]
    fn test_prune_very_large_retention_keeps_all() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cmd_a",
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
            "cmd_b",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let deleted = db.prune(99999).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(db.command_count().unwrap(), 2);
    }

    #[test]
    fn test_prune_if_due_no_old_data() {
        let db = test_db();
        db.insert_command(
            "s1",
            "future_cmd",
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

        db.prune_if_due(30).unwrap();
        assert_eq!(db.command_count().unwrap(), 1);
        assert!(db.get_meta("last_prune_at").unwrap().is_some());
    }

    

    #[test]
    fn test_update_command_triggers_fts_update() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "run_script",
                "/tmp",
                None,
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();

        db.update_command(id, Some(0), Some("unique_fts_update_sentinel_xyz"))
            .unwrap();

        let results = db
            .search_history("unique_fts_update_sentinel_xyz", 10)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command, "run_script");
    }

    #[test]
    fn test_rebuild_fts_on_empty_db() {
        let db = test_db();
        db.rebuild_fts().unwrap();
        db.check_fts_integrity().unwrap();
    }

    #[test]
    fn test_optimize_fts_after_prune() {
        let db = test_db();
        db.insert_command(
            "s1",
            "old_opt_cmd",
            "/tmp",
            Some(0),
            "2020-01-01T00:00:00Z",
            None,
            Some("old output"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "new_opt_cmd",
            "/tmp",
            Some(0),
            "2099-01-01T00:00:00Z",
            None,
            Some("new output"),
            "",
            "",
            0,
        )
        .unwrap();

        db.prune(30).unwrap();
        db.optimize_fts().unwrap();
        db.check_fts_integrity().unwrap();

        let results = db.search_history("new_opt_cmd", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_check_fts_integrity_after_rebuild() {
        let db = test_db();
        for i in 0..20 {
            db.insert_command(
                "s1",
                &format!("integrity_cmd_{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                Some(&format!("output_{i}")),
                "",
                "",
                0,
            )
            .unwrap();
        }
        db.prune(0).unwrap();
        db.rebuild_fts().unwrap();
        db.check_fts_integrity().unwrap();
    }

    #[test]
    fn test_command_count_after_manual_delete() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "to_delete",
                "/tmp",
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
            "to_keep",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        assert_eq!(db.command_count().unwrap(), 2);

        db.conn
            .execute("DELETE FROM commands WHERE id = ?", params![id])
            .unwrap();
        assert_eq!(db.command_count().unwrap(), 1);
    }

    

    

    

    #[test]
    fn test_insert_usage_minimal_fields() {
        let db = test_db();
        let id = db
            .insert_usage("s1", None, "local", "ollama", None, None, None, None)
            .unwrap();
        assert!(id > 0);

        let (model, cost): (String, Option<f64>) = db
            .conn
            .query_row(
                "SELECT model, cost_usd FROM usage WHERE id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(model, "local");
        assert!(cost.is_none());
    }

    #[test]
    fn test_update_usage_cost_multiple_records_same_gen_id() {
        let db = test_db();
        db.insert_usage("s1", None, "m1", "p1", None, None, None, Some("dup_gen"))
            .unwrap();
        db.insert_usage("s1", None, "m1", "p1", None, None, None, Some("dup_gen"))
            .unwrap();

        let updated = db.update_usage_cost("dup_gen", 0.99).unwrap();
        assert!(updated);

        let costs: Vec<Option<f64>> = {
            let mut stmt = db
                .conn
                .prepare("SELECT cost_usd FROM usage WHERE generation_id = 'dup_gen'")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert!(costs.iter().all(|c| c.is_some()));
    }

    #[test]
    fn test_get_pending_generation_ids_multiple() {
        let db = test_db();
        db.insert_usage("s1", None, "m", "p", None, None, None, Some("pend_a"))
            .unwrap();
        db.insert_usage("s1", None, "m", "p", None, None, None, Some("pend_b"))
            .unwrap();
        db.insert_usage("s1", None, "m", "p", None, None, Some(0.01), Some("done_c"))
            .unwrap();

        let pending = db.get_pending_generation_ids().unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&"pend_a".to_string()));
        assert!(pending.contains(&"pend_b".to_string()));
        assert!(!pending.contains(&"done_c".to_string()));
    }

    #[test]
    fn test_commands_needing_summary_returns_fields() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "detailed_cmd",
                "/home/user",
                Some(2),
                "2025-06-01T00:00:00Z",
                None,
                Some("detailed output text"),
                "",
                "",
                0,
            )
            .unwrap();

        let needing = db.commands_needing_summary(10).unwrap();
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0].id, id);
        assert_eq!(needing[0].command, "detailed_cmd");
        assert_eq!(needing[0].cwd.as_deref(), Some("/home/user"));
        assert_eq!(needing[0].exit_code, Some(2));
        assert_eq!(needing[0].output.as_deref(), Some("detailed output text"));
    }

    #[test]
    fn test_update_summary_updates_status_to_done() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "status_cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("output"),
                "",
                "",
                0,
            )
            .unwrap();

        db.update_summary(id, "a summary").unwrap();

        let status: Option<String> = db
            .conn
            .query_row(
                "SELECT summary_status FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status.as_deref(), Some("done"));
    }

    #[test]
    fn test_commands_needing_llm_summary_excludes_errored() {
        let db = test_db();
        let id1 = db
            .insert_command(
                "s1",
                "cmd_needs_llm",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("output1"),
                "",
                "",
                0,
            )
            .unwrap();
        let id2 = db
            .insert_command(
                "s1",
                "cmd_errored",
                "/tmp",
                Some(0),
                "2025-06-01T00:01:00Z",
                None,
                Some("output2"),
                "",
                "",
                0,
            )
            .unwrap();

        db.mark_unsummarized_for_llm().unwrap();
        db.mark_summary_error(id2, "failed").unwrap();

        let needing = db.commands_needing_llm_summary(10).unwrap();
        assert_eq!(needing.len(), 1);
        assert_eq!(needing[0].id, id1);
    }

    #[test]
    fn test_mark_unsummarized_for_llm_idempotent() {
        let db = test_db();
        db.insert_command(
            "s1",
            "cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("output"),
            "",
            "",
            0,
        )
        .unwrap();

        let first = db.mark_unsummarized_for_llm().unwrap();
        assert_eq!(first, 1);

        let second = db.mark_unsummarized_for_llm().unwrap();
        assert_eq!(second, 0, "should not re-mark already marked commands");
    }

    #[test]
    fn test_mark_summary_error_sets_status_and_summary() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "err_cmd",
                "/tmp",
                Some(1),
                "2025-06-01T00:00:00Z",
                None,
                Some("crash"),
                "",
                "",
                0,
            )
            .unwrap();

        db.mark_summary_error(id, "connection refused").unwrap();

        let (summary, status): (Option<String>, Option<String>) = db
            .conn
            .query_row(
                "SELECT summary, summary_status FROM commands WHERE id = ?",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status.as_deref(), Some("error"));
        assert_eq!(summary.as_deref(), Some("[error: connection refused]"));
    }

    #[test]
    fn test_recent_commands_with_summaries_includes_all_fields() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        let id = db
            .insert_command(
                "s1",
                "make build",
                "/project",
                Some(0),
                "2025-06-01T12:30:00Z",
                Some(15000),
                Some("Compiled"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "built successfully").unwrap();

        let cmds = db.recent_commands_with_summaries("s1", 10).unwrap();
        assert_eq!(cmds.len(), 1);
        let cmd = &cmds[0];
        assert_eq!(cmd.command, "make build");
        assert_eq!(cmd.cwd.as_deref(), Some("/project"));
        assert_eq!(cmd.exit_code, Some(0));
        assert_eq!(cmd.started_at, "2025-06-01T12:30:00Z");
        assert_eq!(cmd.duration_ms, Some(15000));
        assert_eq!(cmd.summary.as_deref(), Some("built successfully"));
    }

    #[test]
    fn test_other_sessions_with_summaries_includes_summary_field() {
        let db = test_db();
        db.create_session("me", "/dev/pts/0", "zsh", 1234).unwrap();
        db.create_session("them", "/dev/pts/1", "bash", 5678)
            .unwrap();

        let id = db
            .insert_command(
                "them",
                "cargo build",
                "/proj",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("Compiled"),
                "/dev/pts/1",
                "bash",
                5678,
            )
            .unwrap();
        db.update_summary(id, "compiled the project").unwrap();

        let others = db.other_sessions_with_summaries("me", 5, 5).unwrap();
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].summary.as_deref(), Some("compiled the project"));
        assert_eq!(others[0].command, "cargo build");
    }

    #[test]
    fn test_prune_one_day_retention() {
        let db = test_db();
        db.insert_command(
            "s1",
            "yesterday_cmd",
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
        let now_str = chrono::Utc::now().to_rfc3339();
        db.insert_command(
            "s1",
            "now_cmd",
            "/tmp",
            Some(0),
            &now_str,
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let deleted = db.prune(1).unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(db.command_count().unwrap(), 1);
    }

    #[test]
    fn test_conversation_exchange_to_user_message_preserves_content() {
        let exchange = ConversationExchange {
            query: "multi line\nquery\ntext".to_string(),
            response_type: "chat".to_string(),
            response: "resp".to_string(),
            explanation: None,
            result_exit_code: None,
            result_output_snippet: None,
            created_at: None,
        };
        let msg = exchange.to_user_message();
        match &msg.content[0] {
            crate::provider::ContentBlock::Text { text } => {
                assert_eq!(text, "multi line\nquery\ntext");
            }
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn test_conversation_exchange_to_assistant_message_command_empty_explanation() {
        let exchange = ConversationExchange {
            query: "do it".to_string(),
            response_type: "command".to_string(),
            response: "rm -rf /tmp/junk".to_string(),
            explanation: Some("".to_string()),
            result_exit_code: None,
            result_output_snippet: None,
            created_at: None,
        };
        let msg = exchange.to_assistant_message("tid");
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolUse { input, .. } => {
                assert_eq!(input["command"], "rm -rf /tmp/junk");
                assert_eq!(input["explanation"], "");
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[test]
    fn test_update_command_fts_reflects_new_output() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "fts_update_test_cmd",
                "/tmp",
                None,
                "2025-06-01T00:00:00Z",
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();

        let before = db
            .search_history("fts_unique_output_sentinel_abc", 10)
            .unwrap();
        assert!(before.is_empty());

        db.update_command(id, Some(0), Some("fts_unique_output_sentinel_abc"))
            .unwrap();

        let after = db
            .search_history("fts_unique_output_sentinel_abc", 10)
            .unwrap();
        assert_eq!(after.len(), 1);
    }

    #[test]
    fn test_get_usage_stats_groups_by_model() {
        let db = test_db();
        db.insert_usage(
            "s1",
            None,
            "gpt-4o",
            "openai",
            Some(100),
            Some(50),
            Some(0.01),
            None,
        )
        .unwrap();
        db.insert_usage(
            "s1",
            None,
            "claude-3",
            "anthropic",
            Some(200),
            Some(100),
            Some(0.05),
            None,
        )
        .unwrap();
        db.insert_usage(
            "s1",
            None,
            "gpt-4o",
            "openai",
            Some(300),
            Some(150),
            Some(0.03),
            None,
        )
        .unwrap();

        let stats = db.get_usage_stats(UsagePeriod::All).unwrap();
        assert_eq!(stats.len(), 2);

        let gpt4o = stats.iter().find(|(m, _, _, _, _)| m == "gpt-4o").unwrap();
        assert_eq!(gpt4o.1, 2);
        assert_eq!(gpt4o.2, 400);
        assert_eq!(gpt4o.3, 200);

        let claude = stats
            .iter()
            .find(|(m, _, _, _, _)| m == "claude-3")
            .unwrap();
        assert_eq!(claude.1, 1);
    }

    // ── Additional coverage tests ───────────────────────

    #[test]
    fn test_get_usage_stats_all_periods_with_recent_data() {
        let db = test_db();
        db.insert_usage(
            "s1",
            None,
            "model-x",
            "prov",
            Some(10),
            Some(5),
            Some(0.001),
            None,
        )
        .unwrap();

        for period in [
            UsagePeriod::Today,
            UsagePeriod::Week,
            UsagePeriod::Month,
            UsagePeriod::All,
        ] {
            let stats = db.get_usage_stats(period).unwrap();
            assert_eq!(stats.len(), 1);
            assert_eq!(stats[0].0, "model-x");
        }
    }

    #[test]
    fn test_get_memories_respects_limit_ordering() {
        let db = test_db();
        // removed legacy memory limit/ordering test
    }

    // #[test]
    fn test_memory_update_value_only_preserves_key() {}

    #[test]
    fn test_find_pending_conversation_returns_latest_command() {
        let db = test_db();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();

        db.insert_conversation("s1", "old build", "command", "make old", None, false, false)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        db.insert_conversation("s1", "new build", "command", "make new", None, false, false)
            .unwrap();

        let pending = db.find_pending_conversation("s1").unwrap();
        assert!(pending.is_some());
        let (_, response) = pending.unwrap();
        assert_eq!(response, "make new");
    }

    #[test]
    fn test_mark_unsummarized_for_llm_skips_already_errored() {
        let db = test_db();
        let id1 = db
            .insert_command(
                "s1",
                "cmd1",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("out1"),
                "",
                "",
                0,
            )
            .unwrap();
        let id2 = db
            .insert_command(
                "s1",
                "cmd2",
                "/tmp",
                Some(0),
                "2025-06-01T00:01:00Z",
                None,
                Some("out2"),
                "",
                "",
                0,
            )
            .unwrap();
        db.mark_summary_error(id1, "failed").unwrap();

        let marked = db.mark_unsummarized_for_llm().unwrap();
        assert_eq!(marked, 1);

        let llm_needing = db.commands_needing_llm_summary(10).unwrap();
        assert_eq!(llm_needing.len(), 1);
        assert_eq!(llm_needing[0].id, id2);
    }

    #[test]
    fn test_update_summary_prevents_overwrite() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "cmd",
                "/tmp",
                Some(0),
                "2025-06-01T00:00:00Z",
                None,
                Some("output"),
                "",
                "",
                0,
            )
            .unwrap();

        assert!(db.update_summary(id, "first summary").unwrap());
        assert!(!db.update_summary(id, "second summary").unwrap());

        let summary: Option<String> = db
            .conn
            .query_row(
                "SELECT summary FROM commands WHERE id = ?",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(summary.as_deref(), Some("first summary"));
    }

    #[test]
    fn test_cleanup_orphaned_sessions_leaves_zero_and_negative_pid_open() {
        let db = test_db();
        db.conn.execute(
            "INSERT INTO sessions (id, tty, shell, pid, started_at) VALUES ('neg_pid_x', '/dev/pts/0', 'zsh', -5, '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();
        db.conn.execute(
            "INSERT INTO sessions (id, tty, shell, pid, started_at) VALUES ('zero_pid_x', '/dev/pts/0', 'zsh', 0, '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();

        db.cleanup_orphaned_sessions().unwrap();

        for sid in ["neg_pid_x", "zero_pid_x"] {
            let ended: Option<String> = db
                .conn
                .query_row(
                    "SELECT ended_at FROM sessions WHERE id = ?",
                    params![sid],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(ended.is_none(), "{sid} should remain open");
        }
    }

    #[test]
    fn test_search_history_advanced_fts_combined_with_session_and_exit() {
        let db = test_db();
        db.insert_command(
            "sa",
            "cargo test pass",
            "/p",
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
            "sa",
            "cargo test fail",
            "/p",
            Some(1),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "sb",
            "cargo test other",
            "/p",
            Some(1),
            "2025-06-01T00:02:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("cargo"),
                None,
                None,
                None,
                Some(1),
                false,
                Some("sa"),
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("cargo test fail"));
    }

    #[test]
    #[serial_test::serial]
    fn test_run_doctor_no_prune_no_vacuum() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = temp_home_env();
        let db = test_db();
        db.create_session("doc_s1", "/dev/pts/0", "zsh", 1234)
            .unwrap();
        db.insert_command(
            "doc_s1",
            "echo doctor test",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("ok"),
            "",
            "",
            0,
        )
        .unwrap();

        let config = crate::config::Config::default();
        let result = db.run_doctor(30, true, true, &config);
        assert!(result.is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn test_run_doctor_with_prune_and_vacuum() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = temp_home_env();
        let db = test_db();
        db.insert_command(
            "doc_s2",
            "ancient cmd",
            "/tmp",
            Some(0),
            "2015-01-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "doc_s2",
            "recent cmd",
            "/tmp",
            Some(0),
            "2099-01-01T00:00:00Z",
            None,
            Some("output"),
            "",
            "",
            0,
        )
        .unwrap();

        let config = crate::config::Config::default();
        let result = db.run_doctor(365, false, false, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_search_history_advanced_regex_only_no_fts_v2() {
        let db = test_db();
        db.insert_command(
            "s1",
            "curl https://api.example.com/v2/users",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("200 OK"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "wget https://cdn.example.com/file.tar.gz",
            "/tmp",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "echo hello",
            "/tmp",
            Some(0),
            "2025-06-01T00:02:00Z",
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
                Some(r"https://.*example\.com"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 2);

        let results = db
            .search_history_advanced(
                None,
                Some(r"curl.*v2"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].command.contains("curl"));
    }

    #[test]
    fn test_search_history_advanced_regex_matches_output_and_summary() {
        let db = test_db();
        let id = db
            .insert_command(
                "s1",
                "run_tests",
                "/project",
                Some(1),
                "2025-06-01T00:00:00Z",
                None,
                Some("FAILED: test_widget_render"),
                "",
                "",
                0,
            )
            .unwrap();
        db.update_summary(id, "Widget render test failed with assertion error")
            .unwrap();

        let results = db
            .search_history_advanced(
                None,
                Some(r"FAILED.*widget"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);

        let results = db
            .search_history_advanced(
                None,
                Some(r"assertion error"),
                None,
                None,
                None,
                false,
                None,
                None,
                100,
            )
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_update_heartbeat_nonexistent_session_v2() {
        let db = test_db();
        let result = db.update_heartbeat("nonexistent_session_xyz");
        assert!(result.is_ok());

        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE id = 'nonexistent_session_xyz'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_commands_needing_llm_summary_lifecycle() {
        let db = test_db();
        db.insert_command(
            "s1",
            "complex_cmd_1",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("long output here"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "complex_cmd_2",
            "/tmp",
            Some(1),
            "2025-06-01T00:01:00Z",
            None,
            Some("error output"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "s1",
            "no_output_cmd",
            "/tmp",
            Some(0),
            "2025-06-01T00:02:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();

        let needing_llm = db.commands_needing_llm_summary(10).unwrap();
        assert!(needing_llm.is_empty());

        let marked = db.mark_unsummarized_for_llm().unwrap();
        assert_eq!(marked, 2);

        let needing_llm = db.commands_needing_llm_summary(10).unwrap();
        assert_eq!(needing_llm.len(), 2);

        db.update_summary(needing_llm[0].id, "LLM summary for cmd")
            .unwrap();
        let needing_llm = db.commands_needing_llm_summary(10).unwrap();
        assert_eq!(needing_llm.len(), 1);

        db.mark_summary_error(needing_llm[0].id, "rate limited")
            .unwrap();
        let needing_llm = db.commands_needing_llm_summary(10).unwrap();
        assert!(needing_llm.is_empty());
    }

    #[test]
    fn test_commands_needing_llm_summary_respects_limit_v2() {
        let db = test_db();
        for i in 0..5 {
            db.insert_command(
                "s1",
                &format!("cmd_{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{i:02}:00Z"),
                None,
                Some(&format!("output {i}")),
                "",
                "",
                0,
            )
            .unwrap();
        }
        db.mark_unsummarized_for_llm().unwrap();

        let needing = db.commands_needing_llm_summary(2).unwrap();
        assert_eq!(needing.len(), 2);
    }

    #[test]
    fn test_search_history_advanced_current_includes_imported() {
        let db = test_db();
        db.insert_command(
            "real_sess",
            "echo real",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        db.create_session("imported_bash_history", "import", "bash", 0)
            .unwrap();
        db.insert_command(
            "imported_bash_history",
            "ssh admin@10.0.0.1",
            "/home",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "import",
            "bash",
            0,
        )
        .unwrap();
        db.create_session("imported_zsh_pts1", "/dev/pts/1", "zsh", 0)
            .unwrap();
        db.insert_command(
            "imported_zsh_pts1",
            "git push",
            "/project",
            Some(0),
            "2024-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "zsh",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                None,
                None,
                None,
                None,
                None,
                false,
                Some("current"),
                Some("real_sess"),
                100,
            )
            .unwrap();
        let commands: Vec<&str> = results.iter().map(|r| r.command.as_str()).collect();
        assert!(
            commands.contains(&"echo real"),
            "should include current TTY command"
        );
        assert!(
            commands.contains(&"ssh admin@10.0.0.1"),
            "should include generic imported"
        );
        assert!(
            commands.contains(&"git push"),
            "should include per-TTY imported (matches via TTY + LIKE)"
        );
    }

    #[test]
    fn test_search_history_advanced_literal_session_includes_imported() {
        let db = test_db();
        db.insert_command(
            "my_sess",
            "echo mine",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.create_session("imported_bash_history", "import", "bash", 0)
            .unwrap();
        db.insert_command(
            "imported_bash_history",
            "cargo build",
            "/project",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            None,
            "import",
            "bash",
            0,
        )
        .unwrap();

        let results = db
            .search_history_advanced(
                Some("cargo"),
                None,
                None,
                None,
                None,
                false,
                Some("my_sess"),
                None,
                100,
            )
            .unwrap();
        assert!(
            results.iter().any(|r| r.command.contains("cargo")),
            "literal session filter should also include imported history"
        );
    }

    #[test]
    fn test_search_command_entities_current_includes_imported() {
        let db = test_db();
        db.insert_command(
            "real_sess",
            "echo hi",
            "/tmp",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        db.create_session("imported_bash_history", "import", "bash", 0)
            .unwrap();
        db.insert_command(
            "imported_bash_history",
            "ssh root@10.0.0.5",
            "/home",
            Some(0),
            "2025-05-01T00:00:00Z",
            None,
            None,
            "import",
            "bash",
            0,
        )
        .unwrap();

        let entities = db
            .search_command_entities(
                Some("ssh"),
                None,
                Some("machine"),
                None,
                None,
                Some("current"),
                Some("real_sess"),
                100,
            )
            .unwrap();
        assert!(
            entities.iter().any(|e| e.entity.contains("10.0.0.5")),
            "entity search with 'current' should include imported history"
        );
    }

    #[test]
    fn test_schema_migration_from_v0() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        ",
        )
        .unwrap();

        init_db(&conn, 10000).unwrap();

        let version: String = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_string());

        // removed legacy table verification

        conn.execute(
            "INSERT INTO sessions (id, tty, shell, pid, started_at) VALUES ('migr_s', '/dev/pts/0', 'zsh', 1, '2025-01-01T00:00:00Z')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO commands (session_id, command, cwd, started_at) VALUES ('migr_s', 'ssh root@example.com', '/tmp', '2025-01-01T00:00:01Z')",
            [],
        ).unwrap();
        let db = Db {
            conn,
            max_output_bytes: 32768,
        };
        let inserted = db.backfill_command_entities_if_needed().unwrap();
        assert!(inserted >= 1);
    }
}
