use rusqlite::{OptionalExtension, params};

use super::Db;
use super::types::{ConversationExchange, ConversationResponseKind};

impl Db {
    #[allow(clippy::too_many_arguments)]
    pub fn insert_conversation(
        &self,
        session_id: &str,
        query: &str,
        response_type: &str,
        response: &str,
        explanation: Option<&str>,
        executed: bool,
        pending: bool,
    ) -> rusqlite::Result<i64> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO conversations \
             (session_id, query, response_type, response, explanation, executed, pending, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                session_id,
                query,
                response_type,
                response,
                explanation,
                executed as i32,
                pending as i32,
                now
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_conversations(
        &self,
        session_id: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<ConversationExchange>> {
        let mut stmt = self.conn.prepare(
            "SELECT query, response_type, response, explanation,
                    result_exit_code, result_output_snippet, created_at
             FROM conversations
             WHERE session_id = ?
             ORDER BY created_at DESC
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![session_id, limit as i64], |row| {
            let rt: String = row.get(1)?;
            Ok(ConversationExchange {
                query: row.get(0)?,
                response_type: ConversationResponseKind::from(rt),
                response: row.get(2)?,
                explanation: row.get(3)?,
                result_exit_code: row.get(4)?,
                result_output_snippet: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;
        let mut results: Vec<ConversationExchange> = rows.collect::<Result<_, _>>()?;
        results.reverse();
        Ok(results)
    }

    pub fn clear_conversations(&self, session_id: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM conversations WHERE session_id = ?",
            params![session_id],
        )?;
        Ok(())
    }

    pub fn find_pending_conversation(
        &self,
        session_id: &str,
    ) -> rusqlite::Result<Option<(i64, String)>> {
        self.conn
            .query_row(
                "SELECT id, response FROM conversations WHERE session_id = ? \
             AND response_type = 'command' AND result_exit_code IS NULL \
             ORDER BY created_at DESC LIMIT 1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
    }

    pub fn conversation_session_id(&self, conv_id: i64) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT session_id FROM conversations WHERE id = ?",
                params![conv_id],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn update_conversation_result(
        &self,
        conv_id: i64,
        exit_code: i32,
        output_snippet: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE conversations SET result_exit_code = ?, result_output_snippet = ? WHERE id = ?",
            params![exit_code, output_snippet, conv_id],
        )?;
        Ok(())
    }
}
