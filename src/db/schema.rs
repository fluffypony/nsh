use rusqlite::{Connection, params};

pub(crate) const SCHEMA_VERSION: i32 = 6;
pub(crate) const COMMAND_ENTITY_BACKFILL_MAX_ID_KEY: &str = "command_entities_backfilled_max_id_v1";
pub const IMPORT_SESSION_PREFIX: &str = "imported_";
// Must stay in sync with IMPORT_SESSION_PREFIX above
pub(crate) const INCLUDE_IMPORTED_SQL: &str = "c.session_id LIKE 'imported_%'";

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
                .truncate(false)
                .open(&lock_path)
                .ok()?;
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                // SAFETY: file is an open File whose fd is valid for the
                // duration of this call. LOCK_EX is a valid flock operation.
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
