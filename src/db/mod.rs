//! Database layer: SQLite storage for sessions, commands, conversations,
//! usage tracking, memory operations, and entity extraction.
//!
//! Organized by domain:
//! - `schema`: DDL, migrations, init
//! - `sessions`: Session lifecycle
//! - `commands`: Command recording, updates, summaries
//! - `conversations`: Conversation CRUD
//! - `history`: FTS5 search, recent/other session queries
//! - `memory_ops`: Memory tier operations (core, semantic, procedural, etc.)
//! - `entities`: Command entity extraction and search
//! - `usage`: Cost/usage tracking
//! - `maintenance`: Doctor, pruning, FTS maintenance
//! - `import`: History import, readonly open, bulk insert
//! - `types`: All public data types

mod commands;
mod conversations;
pub(crate) mod entities;
mod history;
mod import;
mod maintenance;
mod memory_ops;
pub(crate) mod schema;
mod sessions;
pub mod types;
mod usage;

use rusqlite::Connection;

pub use schema::IMPORT_SESSION_PREFIX;
#[cfg(test)]
pub(crate) use schema::SCHEMA_VERSION;
#[cfg(test)]
pub(crate) use schema::init_db;
pub use types::*;

pub struct Db {
    pub(crate) conn: Connection,
    pub(crate) max_output_bytes: usize,
}

impl Db {
    pub(crate) fn to_fts_literal_query(query: &str) -> String {
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
            match schema::init_db(&conn, config.db.busy_timeout_ms) {
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

    /// Create an in-memory database for testing.
    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        schema::init_db(&conn, 10000)?;
        Ok(Self {
            conn,
            max_output_bytes: 32768,
        })
    }
}

pub(crate) fn gethostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(all(test, not(any())))]
mod tests;
