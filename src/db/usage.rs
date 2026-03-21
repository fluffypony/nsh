use rusqlite::params;

use super::Db;
use super::types::UsagePeriod;

impl Db {
    #[allow(clippy::too_many_arguments)]
    pub fn insert_usage(
        &self,
        session_id: &str,
        query_text: Option<&str>,
        model: &str,
        provider: &str,
        input_tokens: Option<u32>,
        output_tokens: Option<u32>,
        cost_usd: Option<f64>,
        generation_id: Option<&str>,
    ) -> rusqlite::Result<i64> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO usage (session_id, query_text, model, provider, \
             input_tokens, output_tokens, cost_usd, generation_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                session_id,
                query_text,
                model,
                provider,
                input_tokens,
                output_tokens,
                cost_usd,
                generation_id,
                now,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn update_usage_cost(&self, generation_id: &str, cost_usd: f64) -> rusqlite::Result<bool> {
        let updated = self.conn.execute(
            "UPDATE usage SET cost_usd = ? WHERE generation_id = ?",
            params![cost_usd, generation_id],
        )?;
        Ok(updated > 0)
    }

    #[allow(clippy::type_complexity)]
    pub fn get_usage_stats(
        &self,
        period: UsagePeriod,
    ) -> rusqlite::Result<Vec<(String, i64, i64, i64, f64)>> {
        let where_clause = match period {
            UsagePeriod::Today => " WHERE created_at >= datetime('now', '-1 day')",
            UsagePeriod::Week => " WHERE created_at >= datetime('now', '-7 days')",
            UsagePeriod::Month => " WHERE created_at >= datetime('now', '-30 days')",
            UsagePeriod::All => "",
        };
        let sql = format!(
            "SELECT model, COUNT(*) as calls, \
             COALESCE(SUM(input_tokens), 0), \
             COALESCE(SUM(output_tokens), 0), \
             COALESCE(SUM(cost_usd), 0.0) \
             FROM usage{where_clause} \
             GROUP BY model ORDER BY calls DESC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, f64>(4)?,
            ))
        })?;
        rows.collect()
    }

    #[cfg(test)]
    pub fn pending_generation_ids(&self) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT generation_id FROM usage \
             WHERE generation_id IS NOT NULL AND cost_usd IS NULL \
             AND created_at > datetime('now', '-1 hour')",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect()
    }
}
