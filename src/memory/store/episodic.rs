use rusqlite::{Connection, params};

use crate::memory::types::{Actor, EpisodicEvent, EpisodicEventCreate, EventType, generate_id};

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
    // Preserve existing details by appending, not replacing
    let existing_details: Option<String> = conn
        .query_row(
            "SELECT details FROM episodic_memory WHERE id = ?",
            params![event_id],
            |r| r.get(0),
        )
        .ok()
        .flatten();

    let merged_details = match (existing_details, additional_details) {
        (Some(existing), Some(new)) if !new.is_empty() => Some(format!("{existing}\n{new}")),
        (Some(existing), _) => Some(existing),
        (None, Some(new)) if !new.is_empty() => Some(new.to_string()),
        _ => None,
    };

    conn.execute(
        "UPDATE episodic_memory SET summary = ?, details = ?, search_keywords = ?, occurred_at = datetime('now')
         WHERE id = ?",
        params![combined_summary, merged_details, search_keywords, event_id],
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

pub fn list_recent(
    conn: &Connection,
    limit: usize,
    fade_cutoff: Option<&str>,
    since: Option<&str>,
) -> anyhow::Result<Vec<EpisodicEvent>> {
    let mut conditions = Vec::new();
    if let Some(cutoff) = fade_cutoff {
        conditions.push(format!("occurred_at >= '{cutoff}'"));
    }
    if let Some(since_val) = since {
        conditions.push(format!("occurred_at >= '{since_val}'"));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    let sql = format!(
        "SELECT id, event_type, actor, summary, details, command, exit_code, working_dir, project_context, search_keywords, occurred_at, is_consolidated
         FROM episodic_memory
         {where_clause}
         ORDER BY occurred_at DESC
         LIMIT {limit}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], row_to_event)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn list_all(conn: &Connection) -> anyhow::Result<Vec<EpisodicEvent>> {
    let mut stmt = conn.prepare(
        "SELECT id, event_type, actor, summary, details, command, exit_code, working_dir, project_context, search_keywords, occurred_at, is_consolidated
         FROM episodic_memory
         ORDER BY occurred_at DESC",
    )?;
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

pub fn search_bm25(
    conn: &Connection,
    query: &str,
    limit: usize,
    fade_cutoff: Option<&str>,
    since: Option<&str>,
) -> anyhow::Result<Vec<EpisodicEvent>> {
    let fts_query = crate::memory::search::fts::build_fts5_query(query);
    if fts_query.is_empty() {
        return Ok(vec![]);
    }

    let mut extra_clauses = Vec::new();
    if let Some(cutoff) = fade_cutoff {
        extra_clauses.push(format!("AND e.occurred_at >= '{cutoff}'"));
    }
    if let Some(since_val) = since {
        extra_clauses.push(format!("AND e.occurred_at >= '{since_val}'"));
    }
    let extra = extra_clauses.join(" ");

    let sql = format!(
        "SELECT e.id, e.event_type, e.actor, e.summary, e.details, e.command, e.exit_code, e.working_dir, e.project_context, e.search_keywords, e.occurred_at, e.is_consolidated
         FROM episodic_memory e
         JOIN episodic_memory_fts f ON e.rowid = f.rowid
         WHERE episodic_memory_fts MATCH ?
         {extra}
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

        let recent = list_recent(&conn, 10, None, None).unwrap();
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

    #[test]
    fn merge_appends_details() {
        let conn = setup();
        let event = EpisodicEventCreate {
            event_type: EventType::CommandExecution,
            actor: Actor::User,
            summary: "Original summary".into(),
            details: Some("Original details".into()),
            command: Some("cargo build".into()),
            exit_code: Some(0),
            working_dir: None,
            project_context: None,
            search_keywords: "cargo build".into(),
        };
        let id = insert(&conn, &event).unwrap();

        merge(
            &conn,
            &id,
            "Updated summary",
            Some("Additional info"),
            "cargo build updated",
        )
        .unwrap();

        let events = list_recent(&conn, 10, None, None).unwrap();
        assert_eq!(events[0].summary, "Updated summary");
        assert!(
            events[0]
                .details
                .as_ref()
                .unwrap()
                .contains("Original details")
        );
        assert!(
            events[0]
                .details
                .as_ref()
                .unwrap()
                .contains("Additional info")
        );
    }

    #[test]
    fn merge_preserves_existing_details_when_none_added() {
        let conn = setup();
        let event = EpisodicEventCreate {
            event_type: EventType::CommandExecution,
            actor: Actor::User,
            summary: "test".into(),
            details: Some("existing details".into()),
            command: None,
            exit_code: None,
            working_dir: None,
            project_context: None,
            search_keywords: "test".into(),
        };
        let id = insert(&conn, &event).unwrap();

        merge(&conn, &id, "updated", None, "test").unwrap();

        let events = list_recent(&conn, 10, None, None).unwrap();
        assert_eq!(events[0].details.as_ref().unwrap(), "existing details");
    }

    #[test]
    fn search_bm25_finds_by_keywords() {
        let conn = setup();
        let event = EpisodicEventCreate {
            event_type: EventType::CommandExecution,
            actor: Actor::User,
            summary: "Built the project".into(),
            details: None,
            command: Some("cargo build".into()),
            exit_code: Some(0),
            working_dir: None,
            project_context: None,
            search_keywords: "cargo build rust compile".into(),
        };
        insert(&conn, &event).unwrap();

        let results = search_bm25(&conn, "rust compile", 10, None, None).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_bm25_empty_query() {
        let conn = setup();
        insert(
            &conn,
            &EpisodicEventCreate {
                event_type: EventType::CommandExecution,
                actor: Actor::User,
                summary: "test".into(),
                details: None,
                command: None,
                exit_code: None,
                working_dir: None,
                project_context: None,
                search_keywords: "test".into(),
            },
        )
        .unwrap();

        let results = search_bm25(&conn, "", 10, None, None).unwrap();
        assert!(results.is_empty(), "empty query should return no results");
    }

    #[test]
    fn search_bm25_with_fade_cutoff() {
        let conn = setup();
        // Insert old and new events
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_VOLD', 'command_execution', 'user', 'old cargo build', 'cargo build', datetime('now', '-60 days'))",
            [],
        ).unwrap();
        insert(
            &conn,
            &EpisodicEventCreate {
                event_type: EventType::CommandExecution,
                actor: Actor::User,
                summary: "new cargo build".into(),
                details: None,
                command: None,
                exit_code: None,
                working_dir: None,
                project_context: None,
                search_keywords: "cargo build".into(),
            },
        )
        .unwrap();

        let cutoff = crate::memory::decay::get_fade_cutoff(&conn, 30).unwrap();
        let results = search_bm25(&conn, "cargo build", 10, Some(&cutoff), None).unwrap();
        assert_eq!(
            results.len(),
            1,
            "should only find recent event after fade cutoff"
        );
        assert_eq!(results[0].summary, "new cargo build");
    }

    #[test]
    fn list_recent_respects_limit() {
        let conn = setup();
        for i in 0..5 {
            insert(
                &conn,
                &EpisodicEventCreate {
                    event_type: EventType::CommandExecution,
                    actor: Actor::User,
                    summary: format!("event {i}"),
                    details: None,
                    command: None,
                    exit_code: None,
                    working_dir: None,
                    project_context: None,
                    search_keywords: "test".into(),
                },
            )
            .unwrap();
        }

        let recent = list_recent(&conn, 3, None, None).unwrap();
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn list_unconsolidated_only_returns_unconsolidated() {
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
        let id1 = insert(&conn, &event).unwrap();
        let _id2 = insert(&conn, &event).unwrap();

        mark_consolidated(&conn, &[id1]).unwrap();

        let uncons = list_unconsolidated(&conn, 10).unwrap();
        assert_eq!(uncons.len(), 1, "should only return unconsolidated events");
    }

    #[test]
    fn count_tracks_insertions_and_deletions() {
        let conn = setup();
        assert_eq!(count(&conn).unwrap(), 0);

        let id = insert(
            &conn,
            &EpisodicEventCreate {
                event_type: EventType::SessionStart,
                actor: Actor::System,
                summary: "session".into(),
                details: None,
                command: None,
                exit_code: None,
                working_dir: None,
                project_context: None,
                search_keywords: "session".into(),
            },
        )
        .unwrap();
        assert_eq!(count(&conn).unwrap(), 1);

        delete(&conn, &[id]).unwrap();
        assert_eq!(count(&conn).unwrap(), 0);
    }

    #[test]
    fn delete_nonexistent_is_noop() {
        let conn = setup();
        let deleted = delete(&conn, &["ep_NONEXIST".into()]).unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn parse_event_type_all_variants() {
        assert_eq!(
            parse_event_type("command_execution"),
            EventType::CommandExecution
        );
        assert_eq!(parse_event_type("command_error"), EventType::CommandError);
        assert_eq!(
            parse_event_type("user_instruction"),
            EventType::UserInstruction
        );
        assert_eq!(
            parse_event_type("assistant_action"),
            EventType::AssistantAction
        );
        assert_eq!(parse_event_type("file_edit"), EventType::FileEdit);
        assert_eq!(parse_event_type("session_start"), EventType::SessionStart);
        assert_eq!(parse_event_type("session_end"), EventType::SessionEnd);
        assert_eq!(parse_event_type("project_switch"), EventType::ProjectSwitch);
        assert_eq!(parse_event_type("system_event"), EventType::SystemEvent);
        assert_eq!(parse_event_type("unknown_type"), EventType::SystemEvent);
    }

    #[test]
    fn parse_actor_all_variants() {
        assert_eq!(parse_actor("user"), Actor::User);
        assert_eq!(parse_actor("assistant"), Actor::Assistant);
        assert_eq!(parse_actor("system"), Actor::System);
        assert_eq!(parse_actor("unknown"), Actor::User);
    }
}
