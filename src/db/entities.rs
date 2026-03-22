use rusqlite::params;

use super::Db;
use super::schema::{COMMAND_ENTITY_BACKFILL_MAX_ID_KEY, INCLUDE_IMPORTED_SQL};
use super::types::CommandEntityMatch;

impl Db {
    #[allow(clippy::too_many_arguments)]
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

        if let Some(exe) = executable_filter.map(normalize_executable_name)
            && !exe.is_empty() {
                sql.push_str(" AND ce.executable = ?");
                params_vec.push(Box::new(exe));
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
}

// ── Entity extraction helpers ─────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct ExtractedCommandEntity {
    pub executable: String,
    pub entity: String,
    pub entity_norm: String,
    pub entity_type: String,
}

pub(crate) fn extract_command_entities(command: &str) -> Vec<ExtractedCommandEntity> {
    let tokens = match shell_words::split(command) {
        Ok(t) => t,
        // Fall back to simple whitespace tokenization if shell_words fails
        // (e.g. unclosed quotes in the command text).
        Err(_) => command.split_whitespace().map(String::from).collect(),
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
    if let Some((h, port)) = host.rsplit_once(':')
        && !h.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            host = h;
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
