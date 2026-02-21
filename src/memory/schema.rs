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

    // Rebuild FTS5 indexes to capture any pre-existing rows that
    // were inserted before triggers existed (e.g., migration path).
    conn.execute_batch(
        "
        INSERT INTO episodic_memory_fts(episodic_memory_fts) VALUES('rebuild');
        INSERT INTO semantic_memory_fts(semantic_memory_fts) VALUES('rebuild');
        INSERT INTO procedural_memory_fts(procedural_memory_fts) VALUES('rebuild');
        INSERT INTO resource_memory_fts(resource_memory_fts) VALUES('rebuild');
        INSERT INTO knowledge_vault_fts(knowledge_vault_fts) VALUES('rebuild');
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

    #[test]
    fn all_data_tables_created() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        let tables = ["core_memory", "episodic_memory", "semantic_memory",
                       "procedural_memory", "resource_memory", "knowledge_vault",
                       "memory_config"];
        for table in &tables {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(exists, "Table {table} should exist");
        }
    }

    #[test]
    fn all_fts_tables_created() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        let fts_tables = [
            "episodic_memory_fts", "semantic_memory_fts",
            "procedural_memory_fts", "resource_memory_fts",
            "knowledge_vault_fts",
        ];
        for table in &fts_tables {
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
    fn all_indexes_created() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        let indexes = [
            "idx_episodic_occurred", "idx_episodic_event_type",
            "idx_episodic_exit_code", "idx_episodic_working_dir",
            "idx_episodic_project", "idx_episodic_consolidated",
            "idx_semantic_name", "idx_semantic_category",
            "idx_resource_type", "idx_resource_file_path", "idx_resource_file_hash",
            "idx_knowledge_entry_type", "idx_knowledge_sensitivity",
        ];
        for idx in &indexes {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='index' AND name=?",
                    [idx],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(exists, "Index {idx} should exist");
        }
    }

    #[test]
    fn all_triggers_created() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        let triggers = [
            "episodic_memory_ai", "episodic_memory_ad", "episodic_memory_au",
            "semantic_memory_ai", "semantic_memory_ad", "semantic_memory_au",
            "procedural_memory_ai", "procedural_memory_ad", "procedural_memory_au",
            "resource_memory_ai", "resource_memory_ad", "resource_memory_au",
            "knowledge_vault_ai", "knowledge_vault_ad", "knowledge_vault_au",
        ];
        for trigger in &triggers {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='trigger' AND name=?",
                    [trigger],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(exists, "Trigger {trigger} should exist");
        }
    }

    #[test]
    fn memory_config_all_keys_seeded() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        let expected_keys = [
            "schema_version", "fade_after_days", "expire_after_days",
            "consolidation_threshold", "last_decay_at",
            "last_reflection_at", "last_bootstrap_at",
        ];
        for key in &expected_keys {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM memory_config WHERE key = ?",
                    [key],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(exists, "Config key '{key}' should be seeded");
        }
    }

    #[test]
    fn semantic_fts_trigger_fires() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO semantic_memory (id, name, category, summary, search_keywords)
             VALUES ('sem_T', 'Docker setup', 'tools', 'Uses docker-compose for local dev', 'docker compose dev')",
            [],
        ).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM semantic_memory_fts WHERE semantic_memory_fts MATCH 'docker'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "semantic FTS should be populated by trigger");
    }

    #[test]
    fn procedural_fts_trigger_fires() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO procedural_memory (id, entry_type, trigger_pattern, summary, steps, search_keywords)
             VALUES ('proc_T', 'workflow', 'deploy', 'Deploy to production', '[\"build\", \"deploy\"]', 'deploy production')",
            [],
        ).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM procedural_memory_fts WHERE procedural_memory_fts MATCH 'deploy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "procedural FTS should be populated by trigger");
    }

    #[test]
    fn resource_fts_trigger_fires() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO resource_memory (id, resource_type, title, summary, search_keywords)
             VALUES ('res_T', 'config', 'Git config', 'Git configuration with aliases', 'git config alias')",
            [],
        ).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM resource_memory_fts WHERE resource_memory_fts MATCH 'alias'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "resource FTS should be populated by trigger");
    }

    #[test]
    fn knowledge_fts_trigger_fires() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO knowledge_vault (id, entry_type, caption, secret_value, sensitivity, search_keywords)
             VALUES ('kv_T', 'credential', 'GitHub access token', 'encrypted_data', 'high', 'github token api')",
            [],
        ).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM knowledge_vault_fts WHERE knowledge_vault_fts MATCH 'github'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "knowledge FTS should be populated by trigger");
    }

    #[test]
    fn episodic_fts_update_trigger() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords)
             VALUES ('ep_UPD', 'command_execution', 'user', 'ran cargo build', 'cargo build')",
            [],
        ).unwrap();

        conn.execute(
            "UPDATE episodic_memory SET summary = 'ran docker build', search_keywords = 'docker build' WHERE id = 'ep_UPD'",
            [],
        ).unwrap();

        // Old term should no longer match
        let old_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM episodic_memory_fts WHERE episodic_memory_fts MATCH 'cargo'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old_count, 0, "old FTS term should be removed after update");

        // New term should match
        let new_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM episodic_memory_fts WHERE episodic_memory_fts MATCH 'docker'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(new_count, 1, "new FTS term should be present after update");
    }

    #[test]
    fn episodic_fts_delete_trigger() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords)
             VALUES ('ep_DEL', 'command_execution', 'user', 'ran npm install', 'npm install')",
            [],
        ).unwrap();

        conn.execute("DELETE FROM episodic_memory WHERE id = 'ep_DEL'", []).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM episodic_memory_fts WHERE episodic_memory_fts MATCH 'npm'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "FTS entry should be removed after delete");
    }

    #[test]
    fn core_memory_default_values() {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();

        let (value, limit): (String, i64) = conn.query_row(
            "SELECT value, char_limit FROM core_memory WHERE label = 'human'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        assert_eq!(value, "");
        assert_eq!(limit, 5000);
    }
}
