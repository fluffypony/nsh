use rusqlite::{Connection, params};

use crate::memory::types::{EpisodicEvent, EpisodicEventCreate, Actor, EventType, generate_id};

fn parse_event_type(s: &str) -> EventType {
    match s {
        "command_execution" => EventType::CommandExecution,
        "command_error" => EventType::CommandError,
        "user_instruction" => EventType::UserInstruction,
        "assistant_action" => EventType::AssistantAction,
        "file_edit" => EventType::FileEdit,
        "session_start" => EventType::SessionStart,
        "session_end" => EventType::SessionEnd,
        "project_switch" => EventType::ProjectSwitch,
        "system_event" => EventType::SystemEvent,
        _ => EventType::SystemEvent,
    }
}

fn parse_actor(s: &str) -> Actor {
    match s {
        "assistant" => Actor::Assistant,
        "system" => Actor::System,
        _ => Actor::User,
    }
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<EpisodicEvent> {
    Ok(EpisodicEvent {
        id: row.get(0)?,
        event_type: parse_event_type(&row.get::<_, String>(1)?),
        actor: parse_actor(&row.get::<_, String>(2)?),
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

pub fn insert(conn: &Connection, event: &EpisodicEventCreate) -> anyhow::Result<String> {
    let id = generate_id("ep");
    conn.execute(
        "INSERT INTO episodic_memory (id, event_type, actor, summary, details, command, exit_code, working_dir, project_context, search_keywords)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            id,
            event.event_type.as_str(),
            event.actor.as_str(),
            event.summary,
            event.details,
            event.command,
            event.exit_code,
            event.working_dir,
            event.project_context,
            event.search_keywords,
        ],
    )?;
    Ok(id)
}

pub fn merge(
    conn: &Connection,
    event_id: &str,
    combined_summary: &str,
    additional_details: Option<&str>,
    search_keywords: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE episodic_memory SET summary = ?, details = ?, search_keywords = ?, occurred_at = datetime('now')
         WHERE id = ?",
        params![combined_summary, additional_details, search_keywords, event_id],
    )?;
    Ok(())
}

pub fn delete(conn: &Connection, ids: &[String]) -> anyhow::Result<usize> {
    let mut count = 0;
    for id in ids {
        count += conn.execute("DELETE FROM episodic_memory WHERE id = ?", params![id])?;
    }
    Ok(count)
}

pub fn list_recent(conn: &Connection, limit: usize, fade_cutoff: Option<&str>) -> anyhow::Result<Vec<EpisodicEvent>> {
    let sql = if let Some(cutoff) = fade_cutoff {
        format!(
            "SELECT id, event_type, actor, summary, details, command, exit_code, working_dir, project_context, search_keywords, occurred_at, is_consolidated
             FROM episodic_memory
             WHERE occurred_at >= '{cutoff}'
             ORDER BY occurred_at DESC
             LIMIT {limit}"
        )
    } else {
        format!(
            "SELECT id, event_type, actor, summary, details, command, exit_code, working_dir, project_context, search_keywords, occurred_at, is_consolidated
             FROM episodic_memory
             ORDER BY occurred_at DESC
             LIMIT {limit}"
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], row_to_event)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn list_unconsolidated(conn: &Connection, limit: usize) -> anyhow::Result<Vec<EpisodicEvent>> {
    let mut stmt = conn.prepare(
        "SELECT id, event_type, actor, summary, details, command, exit_code, working_dir, project_context, search_keywords, occurred_at, is_consolidated
         FROM episodic_memory
         WHERE is_consolidated = 0
         ORDER BY occurred_at ASC
         LIMIT ?",
    )?;
    let rows = stmt.query_map(params![limit as i64], row_to_event)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn search_bm25(conn: &Connection, query: &str, limit: usize, fade_cutoff: Option<&str>) -> anyhow::Result<Vec<EpisodicEvent>> {
    let fts_query = crate::memory::search::fts::build_fts5_query(query);
    if fts_query.is_empty() {
        return Ok(vec![]);
    }

    let cutoff_clause = if let Some(cutoff) = fade_cutoff {
        format!("AND e.occurred_at >= '{cutoff}'")
    } else {
        String::new()
    };

    let sql = format!(
        "SELECT e.id, e.event_type, e.actor, e.summary, e.details, e.command, e.exit_code, e.working_dir, e.project_context, e.search_keywords, e.occurred_at, e.is_consolidated
         FROM episodic_memory e
         JOIN episodic_memory_fts f ON e.rowid = f.rowid
         WHERE episodic_memory_fts MATCH ?
         {cutoff_clause}
         ORDER BY bm25(episodic_memory_fts, 10.0, 1.0, 3.0) ASC
         LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![fts_query], row_to_event)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn mark_consolidated(conn: &Connection, ids: &[String]) -> anyhow::Result<()> {
    for id in ids {
        conn.execute(
            "UPDATE episodic_memory SET is_consolidated = 1 WHERE id = ?",
            params![id],
        )?;
    }
    Ok(())
}

pub fn count(conn: &Connection) -> anyhow::Result<usize> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM episodic_memory", [], |r| r.get(0))?;
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::schema::create_memory_tables;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn insert_and_list_recent() {
        let conn = setup();
        let event = EpisodicEventCreate {
            event_type: EventType::CommandExecution,
            actor: Actor::User,
            summary: "Ran cargo build".into(),
            details: Some("Full build output".into()),
            command: Some("cargo build".into()),
            exit_code: Some(0),
            working_dir: Some("/home/user/project".into()),
            project_context: Some("my-project".into()),
            search_keywords: "cargo build rust compile".into(),
        };
        let id = insert(&conn, &event).unwrap();
        assert!(id.starts_with("ep_"));

        let recent = list_recent(&conn, 10, None).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].summary, "Ran cargo build");
    }

    #[test]
    fn delete_removes_event() {
        let conn = setup();
        let event = EpisodicEventCreate {
            event_type: EventType::SessionStart,
            actor: Actor::System,
            summary: "Session started".into(),
            details: None,
            command: None,
            exit_code: None,
            working_dir: None,
            project_context: None,
            search_keywords: "session start".into(),
        };
        let id = insert(&conn, &event).unwrap();
        assert_eq!(count(&conn).unwrap(), 1);
        delete(&conn, &[id]).unwrap();
        assert_eq!(count(&conn).unwrap(), 0);
    }

    #[test]
    fn mark_consolidated_works() {
        let conn = setup();
        let event = EpisodicEventCreate {
            event_type: EventType::CommandExecution,
            actor: Actor::User,
            summary: "test".into(),
            details: None,
            command: None,
            exit_code: None,
            working_dir: None,
            project_context: None,
            search_keywords: "test".into(),
        };
        let id = insert(&conn, &event).unwrap();
        let uncons = list_unconsolidated(&conn, 10).unwrap();
        assert_eq!(uncons.len(), 1);

        mark_consolidated(&conn, &[id]).unwrap();
        let uncons = list_unconsolidated(&conn, 10).unwrap();
        assert_eq!(uncons.len(), 0);
    }
}
