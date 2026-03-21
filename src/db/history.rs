use rusqlite::params;

use super::Db;
use super::schema::INCLUDE_IMPORTED_SQL;
use super::types::{CommandWithSummary, HistoryMatch, OtherSessionSummary};

impl Db {
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
            // Over-fetch when regex filtering will be applied post-query,
            // since the SQL LIMIT runs before regex and may drop valid results.
            let fetch_limit = if regex_pattern.is_some() {
                (limit as i64) * 10
            } else {
                limit as i64
            };
            params_vec.push(Box::new(fetch_limit));

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

            if let Some(pattern) = regex_pattern
                && let Ok(re) = regex::Regex::new(pattern) {
                    results.retain(|r| {
                        re.is_match(&r.command)
                            || r.output.as_deref().is_some_and(|o| re.is_match(o))
                    });
                }

            results.truncate(limit);
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
}
