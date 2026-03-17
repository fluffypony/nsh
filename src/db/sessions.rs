use rusqlite::params;

use super::Db;

impl Db {
    pub fn create_session(
        &self,
        id: &str,
        tty: &str,
        shell: &str,
        pid: i64,
    ) -> rusqlite::Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let hostname = super::gethostname();
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
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map(Option::flatten)
    }

    pub fn session_visible_to_caller(
        &self,
        caller_session: Option<&str>,
        target_session: &str,
    ) -> rusqlite::Result<bool> {
        let Some(caller_session) = caller_session.filter(|value| !value.trim().is_empty()) else {
            // Missing caller context must deny access rather than silently granting it.
            return Ok(false);
        };
        if caller_session == target_session || target_session.starts_with("imported_") {
            return Ok(true);
        }

        let caller_tty: Option<String> = self
            .conn
            .query_row(
                "SELECT tty FROM sessions WHERE id = ?",
                params![caller_session],
                |row| row.get(0),
            )
            .optional()?;
        let Some(caller_tty) = caller_tty else {
            return Ok(false);
        };

        self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM sessions WHERE id = ? AND tty = ?",
            params![target_session, caller_tty],
            |row| row.get(0),
        )
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
            .collect::<Result<_, _>>()?;

        let now = chrono::Utc::now().to_rfc3339();
        let mut cleaned = 0usize;
        for (id, pid) in &orphans {
            if *pid <= 0 {
                continue;
            }
            #[cfg(unix)]
            let process_missing = {
                // SAFETY: libc::kill with signal 0 checks process existence
                // without delivering a signal. The pid is validated > 0 above.
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
}

use rusqlite::OptionalExtension;
