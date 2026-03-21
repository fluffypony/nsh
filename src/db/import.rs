use rusqlite::params;

use super::Db;
use super::entities::extract_command_entities;

impl Db {
    pub fn open_readonly() -> anyhow::Result<Self> {
        let dir = crate::config::Config::nsh_dir();
        let config = crate::config::Config::load().unwrap_or_default();
        let db_path = dir.join("nsh.db");
        let conn = rusqlite::Connection::open_with_flags(
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

    #[cfg(test)]
    pub fn conn_execute_batch(&self, sql: &str) -> rusqlite::Result<()> {
        self.conn.execute_batch(sql)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        super::schema::init_db(&conn, 10000)?;
        crate::memory::schema::create_memory_tables(&conn)?;
        let db = Self {
            conn,
            max_output_bytes: 32768,
        };
        Ok(db)
    }
}
