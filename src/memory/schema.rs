use rusqlite::Connection;

pub fn create_memory_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        -- Core Memory: exactly 3 rows (human, persona, environment)
        CREATE TABLE IF NOT EXISTS core_memory (
            label       TEXT PRIMARY KEY,
            value       TEXT NOT NULL DEFAULT '',
            char_limit  INTEGER NOT NULL DEFAULT 5000,
            updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        INSERT OR IGNORE INTO core_memory (label, value, char_limit, updated_at)
        VALUES
            ('human', '', 5000, datetime('now')),
            ('persona', '', 5000, datetime('now')),
            ('environment', '', 5000, datetime('now'));

        -- Episodic Memory
        CREATE TABLE IF NOT EXISTS episodic_memory (
            id               TEXT PRIMARY KEY,
            event_type       TEXT NOT NULL,
            actor            TEXT NOT NULL DEFAULT 'user',
            summary          TEXT NOT NULL,
            details          TEXT,
            command          TEXT,
            exit_code        INTEGER,
            working_dir      TEXT,
            project_context  TEXT,
            search_keywords  TEXT NOT NULL DEFAULT '',
            occurred_at      TEXT NOT NULL DEFAULT (datetime('now')),
            is_consolidated  INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_episodic_occurred
            ON episodic_memory(occurred_at DESC);
        CREATE INDEX IF NOT EXISTS idx_episodic_event_type
            ON episodic_memory(event_type);
        CREATE INDEX IF NOT EXISTS idx_episodic_exit_code
            ON episodic_memory(exit_code);
        CREATE INDEX IF NOT EXISTS idx_episodic_working_dir
            ON episodic_memory(working_dir);
        CREATE INDEX IF NOT EXISTS idx_episodic_project
            ON episodic_memory(project_context);
        CREATE INDEX IF NOT EXISTS idx_episodic_consolidated
            ON episodic_memory(is_consolidated);

        -- Semantic Memory
        CREATE TABLE IF NOT EXISTS semantic_memory (
            id               TEXT PRIMARY KEY,
            name             TEXT NOT NULL,
            category         TEXT NOT NULL DEFAULT 'general',
            summary          TEXT NOT NULL,
            details          TEXT,
            search_keywords  TEXT NOT NULL DEFAULT '',
            access_count     INTEGER NOT NULL DEFAULT 0,
            last_accessed    TEXT NOT NULL DEFAULT (datetime('now')),
            created_at       TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_semantic_name
            ON semantic_memory(name);
        CREATE INDEX IF NOT EXISTS idx_semantic_category
            ON semantic_memory(category);

        -- Procedural Memory
        CREATE TABLE IF NOT EXISTS procedural_memory (
            id               TEXT PRIMARY KEY,
            entry_type       TEXT NOT NULL DEFAULT 'workflow',
            trigger_pattern  TEXT NOT NULL DEFAULT '',
            summary          TEXT NOT NULL,
            steps            TEXT NOT NULL DEFAULT '[]',
            search_keywords  TEXT NOT NULL DEFAULT '',
            access_count     INTEGER NOT NULL DEFAULT 0,
            last_accessed    TEXT NOT NULL DEFAULT (datetime('now')),
            created_at       TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
        );

        -- Resource Memory
        CREATE TABLE IF NOT EXISTS resource_memory (
            id               TEXT PRIMARY KEY,
            resource_type    TEXT NOT NULL DEFAULT 'file',
            file_path        TEXT,
            file_hash        TEXT,
            title            TEXT NOT NULL,
            summary          TEXT NOT NULL,
            content          TEXT,
            search_keywords  TEXT NOT NULL DEFAULT '',
            created_at       TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_resource_type
            ON resource_memory(resource_type);
        CREATE INDEX IF NOT EXISTS idx_resource_file_path
            ON resource_memory(file_path);
        CREATE INDEX IF NOT EXISTS idx_resource_file_hash
            ON resource_memory(file_hash);

        -- Knowledge Vault (encrypted secrets)
        CREATE TABLE IF NOT EXISTS knowledge_vault (
            id               TEXT PRIMARY KEY,
            entry_type       TEXT NOT NULL DEFAULT 'credential',
            caption          TEXT NOT NULL,
            secret_value     TEXT NOT NULL,
            sensitivity      TEXT NOT NULL DEFAULT 'medium',
            search_keywords  TEXT NOT NULL DEFAULT '',
            created_at       TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_knowledge_entry_type
            ON knowledge_vault(entry_type);
        CREATE INDEX IF NOT EXISTS idx_knowledge_sensitivity
            ON knowledge_vault(sensitivity);

        -- Memory Config
        CREATE TABLE IF NOT EXISTS memory_config (
            key    TEXT PRIMARY KEY,
            value  TEXT NOT NULL
        );

        INSERT OR IGNORE INTO memory_config (key, value) VALUES
            ('schema_version', '1'),
            ('fade_after_days', '30'),
            ('expire_after_days', '90'),
            ('consolidation_threshold', '50'),
            ('last_decay_at', ''),
            ('last_reflection_at', ''),
            ('last_bootstrap_at', '');
        ",
    )?;

    create_fts_tables(conn)?;

    Ok(())
}

fn create_fts_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        -- Episodic FTS5
        CREATE VIRTUAL TABLE IF NOT EXISTS episodic_memory_fts USING fts5(
            summary,
            details,
            search_keywords,
            content='episodic_memory',
            content_rowid='rowid',
            tokenize='porter unicode61'
        );

        CREATE TRIGGER IF NOT EXISTS episodic_memory_ai AFTER INSERT ON episodic_memory BEGIN
            INSERT INTO episodic_memory_fts(rowid, summary, details, search_keywords)
            VALUES (new.rowid, new.summary, new.details, new.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS episodic_memory_ad AFTER DELETE ON episodic_memory BEGIN
            INSERT INTO episodic_memory_fts(episodic_memory_fts, rowid, summary, details, search_keywords)
            VALUES ('delete', old.rowid, old.summary, old.details, old.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS episodic_memory_au AFTER UPDATE ON episodic_memory BEGIN
            INSERT INTO episodic_memory_fts(episodic_memory_fts, rowid, summary, details, search_keywords)
            VALUES ('delete', old.rowid, old.summary, old.details, old.search_keywords);
            INSERT INTO episodic_memory_fts(rowid, summary, details, search_keywords)
            VALUES (new.rowid, new.summary, new.details, new.search_keywords);
        END;

        -- Semantic FTS5
        CREATE VIRTUAL TABLE IF NOT EXISTS semantic_memory_fts USING fts5(
            name,
            summary,
            details,
            search_keywords,
            content='semantic_memory',
            content_rowid='rowid',
            tokenize='porter unicode61'
        );

        CREATE TRIGGER IF NOT EXISTS semantic_memory_ai AFTER INSERT ON semantic_memory BEGIN
            INSERT INTO semantic_memory_fts(rowid, name, summary, details, search_keywords)
            VALUES (new.rowid, new.name, new.summary, new.details, new.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS semantic_memory_ad AFTER DELETE ON semantic_memory BEGIN
            INSERT INTO semantic_memory_fts(semantic_memory_fts, rowid, name, summary, details, search_keywords)
            VALUES ('delete', old.rowid, old.name, old.summary, old.details, old.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS semantic_memory_au AFTER UPDATE ON semantic_memory BEGIN
            INSERT INTO semantic_memory_fts(semantic_memory_fts, rowid, name, summary, details, search_keywords)
            VALUES ('delete', old.rowid, old.name, old.summary, old.details, old.search_keywords);
            INSERT INTO semantic_memory_fts(rowid, name, summary, details, search_keywords)
            VALUES (new.rowid, new.name, new.summary, new.details, new.search_keywords);
        END;

        -- Procedural FTS5
        CREATE VIRTUAL TABLE IF NOT EXISTS procedural_memory_fts USING fts5(
            summary,
            steps,
            search_keywords,
            content='procedural_memory',
            content_rowid='rowid',
            tokenize='porter unicode61'
        );

        CREATE TRIGGER IF NOT EXISTS procedural_memory_ai AFTER INSERT ON procedural_memory BEGIN
            INSERT INTO procedural_memory_fts(rowid, summary, steps, search_keywords)
            VALUES (new.rowid, new.summary, new.steps, new.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS procedural_memory_ad AFTER DELETE ON procedural_memory BEGIN
            INSERT INTO procedural_memory_fts(procedural_memory_fts, rowid, summary, steps, search_keywords)
            VALUES ('delete', old.rowid, old.summary, old.steps, old.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS procedural_memory_au AFTER UPDATE ON procedural_memory BEGIN
            INSERT INTO procedural_memory_fts(procedural_memory_fts, rowid, summary, steps, search_keywords)
            VALUES ('delete', old.rowid, old.summary, old.steps, old.search_keywords);
            INSERT INTO procedural_memory_fts(rowid, summary, steps, search_keywords)
            VALUES (new.rowid, new.summary, new.steps, new.search_keywords);
        END;

        -- Resource FTS5
        CREATE VIRTUAL TABLE IF NOT EXISTS resource_memory_fts USING fts5(
            title,
            summary,
            content,
            search_keywords,
            content='resource_memory',
            content_rowid='rowid',
            tokenize='porter unicode61'
        );

        CREATE TRIGGER IF NOT EXISTS resource_memory_ai AFTER INSERT ON resource_memory BEGIN
            INSERT INTO resource_memory_fts(rowid, title, summary, content, search_keywords)
            VALUES (new.rowid, new.title, new.summary, new.content, new.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS resource_memory_ad AFTER DELETE ON resource_memory BEGIN
            INSERT INTO resource_memory_fts(resource_memory_fts, rowid, title, summary, content, search_keywords)
            VALUES ('delete', old.rowid, old.title, old.summary, old.content, old.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS resource_memory_au AFTER UPDATE ON resource_memory BEGIN
            INSERT INTO resource_memory_fts(resource_memory_fts, rowid, title, summary, content, search_keywords)
            VALUES ('delete', old.rowid, old.title, old.summary, old.content, old.search_keywords);
            INSERT INTO resource_memory_fts(rowid, title, summary, content, search_keywords)
            VALUES (new.rowid, new.title, new.summary, new.content, new.search_keywords);
        END;

        -- Knowledge Vault FTS5 (NEVER index secret_value)
        CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_vault_fts USING fts5(
            caption,
            search_keywords,
            content='knowledge_vault',
            content_rowid='rowid',
            tokenize='porter unicode61'
        );

        CREATE TRIGGER IF NOT EXISTS knowledge_vault_ai AFTER INSERT ON knowledge_vault BEGIN
            INSERT INTO knowledge_vault_fts(rowid, caption, search_keywords)
            VALUES (new.rowid, new.caption, new.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS knowledge_vault_ad AFTER DELETE ON knowledge_vault BEGIN
            INSERT INTO knowledge_vault_fts(knowledge_vault_fts, rowid, caption, search_keywords)
            VALUES ('delete', old.rowid, old.caption, old.search_keywords);
        END;

        CREATE TRIGGER IF NOT EXISTS knowledge_vault_au AFTER UPDATE ON knowledge_vault BEGIN
            INSERT INTO knowledge_vault_fts(knowledge_vault_fts, rowid, caption, search_keywords)
            VALUES ('delete', old.rowid, old.caption, old.search_keywords);
            INSERT INTO knowledge_vault_fts(rowid, caption, search_keywords)
            VALUES (new.rowid, new.caption, new.search_keywords);
        END;
        ",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_tables_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();
        create_memory_tables(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM core_memory", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn core_memory_seeded() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        let labels: Vec<String> = conn
            .prepare("SELECT label FROM core_memory ORDER BY label")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(labels, vec!["environment", "human", "persona"]);
    }

    #[test]
    fn memory_config_seeded() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        let version: String = conn
            .query_row(
                "SELECT value FROM memory_config WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn fts_tables_exist() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        for table in &[
            "episodic_memory_fts",
            "semantic_memory_fts",
            "procedural_memory_fts",
            "resource_memory_fts",
            "knowledge_vault_fts",
        ] {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(exists, "FTS table {table} should exist");
        }
    }

    #[test]
    fn episodic_fts_trigger_fires() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords)
             VALUES ('ep_TEST', 'command_execution', 'user', 'ran cargo build', 'cargo build rust')",
            [],
        )
        .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM episodic_memory_fts WHERE episodic_memory_fts MATCH 'cargo'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
