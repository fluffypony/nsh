use rusqlite::{Connection, params};

use crate::memory::types::{CoreBlock, CoreLabel};

pub fn get_all(conn: &Connection) -> anyhow::Result<Vec<CoreBlock>> {
    let mut stmt = conn.prepare(
        "SELECT label, value, char_limit, updated_at FROM core_memory ORDER BY label",
    )?;
    let rows = stmt.query_map([], |row| {
        let label_str: String = row.get(0)?;
        Ok(CoreBlock {
            label: CoreLabel::from_str(&label_str).unwrap_or(CoreLabel::Human),
            value: row.get(1)?,
            char_limit: row.get::<_, i64>(2)? as usize,
            updated_at: row.get(3)?,
        })
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn get_block(conn: &Connection, label: CoreLabel) -> anyhow::Result<CoreBlock> {
    let row = conn.query_row(
        "SELECT label, value, char_limit, updated_at FROM core_memory WHERE label = ?",
        params![label.as_str()],
        |row| {
            Ok(CoreBlock {
                label,
                value: row.get(1)?,
                char_limit: row.get::<_, i64>(2)? as usize,
                updated_at: row.get(3)?,
            })
        },
    )?;
    Ok(row)
}

pub fn append(conn: &Connection, label: CoreLabel, content: &str) -> anyhow::Result<()> {
    let block = get_block(conn, label)?;
    let new_value = if block.value.is_empty() {
        content.to_string()
    } else {
        format!("{}\n{}", block.value, content)
    };
    if new_value.len() > block.char_limit {
        tracing::warn!(
            "Core memory block '{}' exceeds char limit ({}/{})",
            label,
            new_value.len(),
            block.char_limit
        );
    }
    conn.execute(
        "UPDATE core_memory SET value = ?, updated_at = datetime('now') WHERE label = ?",
        params![new_value, label.as_str()],
    )?;
    Ok(())
}

pub fn rewrite(conn: &Connection, label: CoreLabel, content: &str) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE core_memory SET value = ?, updated_at = datetime('now') WHERE label = ?",
        params![content, label.as_str()],
    )?;
    Ok(())
}

#[cfg(test)]
pub fn compile_for_prompt(conn: &Connection) -> anyhow::Result<String> {
    let blocks = get_all(conn)?;
    let mut parts = Vec::new();
    for block in &blocks {
        let used = block.value.len();
        let limit = block.char_limit;
        let pct = if limit > 0 {
            (used as f64 / limit as f64 * 100.0) as u32
        } else {
            0
        };
        if !block.value.is_empty() {
            parts.push(format!(
                "<{} characters=\"{}/{}\" ({}% full)>\n{}\n</{}>",
                block.label, used, limit, pct, block.value, block.label
            ));
        } else {
            parts.push(format!(
                "<{} characters=\"0/{}\" (0% full)>\n(empty)\n</{}>",
                block.label, limit, block.label
            ));
        }
    }
    Ok(parts.join("\n\n"))
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
    fn get_all_returns_three_blocks() {
        let conn = setup();
        let blocks = get_all(&conn).unwrap();
        assert_eq!(blocks.len(), 3);
    }

    #[test]
    fn append_and_get() {
        let conn = setup();
        append(&conn, CoreLabel::Human, "Name: Alice").unwrap();
        let block = get_block(&conn, CoreLabel::Human).unwrap();
        assert_eq!(block.value, "Name: Alice");

        append(&conn, CoreLabel::Human, "Role: Developer").unwrap();
        let block = get_block(&conn, CoreLabel::Human).unwrap();
        assert_eq!(block.value, "Name: Alice\nRole: Developer");
    }

    #[test]
    fn rewrite_replaces() {
        let conn = setup();
        append(&conn, CoreLabel::Persona, "Old value").unwrap();
        rewrite(&conn, CoreLabel::Persona, "New value").unwrap();
        let block = get_block(&conn, CoreLabel::Persona).unwrap();
        assert_eq!(block.value, "New value");
    }

    #[test]
    fn compile_for_prompt_format() {
        let conn = setup();
        append(&conn, CoreLabel::Human, "Test user").unwrap();
        let prompt = compile_for_prompt(&conn).unwrap();
        assert!(prompt.contains("<environment"));
        assert!(prompt.contains("<human"));
        assert!(prompt.contains("Test user"));
    }
}
