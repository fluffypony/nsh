use rusqlite::params;

use super::Db;
use super::entities::extract_command_entities;
use super::types::CommandForSummary;

impl Db {
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

    pub fn delete_command_by_id(&self, id: i64) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM commands WHERE id = ?", params![id])?;
        Ok(())
    }

    #[cfg(test)]
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

    pub fn command_count(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM commands", [], |row| {
                row.get::<_, i64>(0).map(|v| v as usize)
            })
    }

    // ── Summary pipeline ──────────────────────────────────────────

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
}
