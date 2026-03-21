use rusqlite::params;
use rusqlite::OptionalExtension;

use super::Db;
use super::types::ResourceMemoryWrite;

impl Db {
    // ── Memory operations ──────────────────────────────────────────

    pub fn core_memory(&self) -> rusqlite::Result<Vec<crate::memory::types::CoreBlock>> {
        let mut stmt = self.conn.prepare(
            "SELECT label, value, char_limit, updated_at FROM core_memory ORDER BY label",
        )?;
        let rows = stmt.query_map([], |row| {
            let label_str: String = row.get(0)?;
            let label = crate::memory::types::CoreLabel::from_str(&label_str).map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    0,
                    "label".into(),
                    rusqlite::types::Type::Text,
                )
            })?;
            Ok(crate::memory::types::CoreBlock {
                label,
                value: row.get(1)?,
                char_limit: row.get::<_, i64>(2)? as usize,
                updated_at: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn update_core_block(&self, label: crate::memory::types::CoreLabel, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE core_memory SET value = ?, updated_at = datetime('now') WHERE label = ?",
            params![value, label.as_str()],
        )?;
        Ok(())
    }

    pub fn append_core_block(&self, label: crate::memory::types::CoreLabel, content: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE core_memory SET value = CASE WHEN value = '' THEN ? ELSE value || '\n' || ? END, updated_at = datetime('now') WHERE label = ?",
            params![content, content, label.as_str()],
        )?;
        Ok(())
    }

    pub fn store_semantic_memory(
        &self,
        name: &str,
        category: &str,
        summary: &str,
        details: Option<&str>,
        search_keywords: &str,
    ) -> anyhow::Result<String> {
        crate::memory::store::semantic::store(
            &self.conn,
            &crate::memory::store::semantic::SemanticWrite {
                name,
                category,
                summary,
                details,
                search_keywords,
            },
        )
    }

    pub fn store_procedural_memory(
        &self,
        entry_type: &str,
        trigger_pattern: &str,
        summary: &str,
        steps: &str,
        search_keywords: &str,
    ) -> anyhow::Result<String> {
        crate::memory::store::procedural::store(
            &self.conn,
            &crate::memory::store::procedural::ProceduralWrite {
                entry_type,
                trigger_pattern,
                summary,
                steps,
                search_keywords,
            },
        )
    }

    pub fn store_resource_memory(
        &self,
        resource: &ResourceMemoryWrite<'_>,
    ) -> anyhow::Result<String> {
        let normalized_hash = if resource.file_path.is_some() {
            Some(
                resource
                    .file_hash
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "store_resource_memory requires non-empty file_hash when file_path is set"
                        )
                    })?,
            )
        } else {
            resource.file_hash
        };
        crate::memory::store::resource::store(
            &self.conn,
            &crate::memory::store::resource::ResourceWrite {
                resource_type: resource.resource_type,
                file_path: resource.file_path,
                file_hash: normalized_hash,
                title: resource.title,
                summary: resource.summary,
                content: resource.content,
                search_keywords: resource.search_keywords,
            },
        )
    }

    pub fn store_knowledge_memory(
        &self,
        entry_type: &str,
        caption: &str,
        secret_value: &str,
        sensitivity: crate::memory::types::Sensitivity,
        search_keywords: &str,
    ) -> anyhow::Result<String> {
        crate::memory::store::knowledge::store(
            &self.conn,
            &crate::memory::store::knowledge::KnowledgeWrite {
                entry_type,
                caption,
                secret_value,
                sensitivity,
                search_keywords,
            },
        )
    }

    pub fn search_episodic_fts_since(
        &self,
        query: &str,
        limit: usize,
        fade_cutoff: Option<&str>,
        since: Option<&str>,
    ) -> rusqlite::Result<Vec<crate::memory::types::EpisodicEvent>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut conditions = vec!["episodic_memory_fts MATCH ?1".to_string()];
        if let Some(cutoff) = fade_cutoff {
            conditions.push(format!("e.occurred_at >= '{cutoff}'"));
        }
        if let Some(since_val) = since {
            conditions.push(format!("e.occurred_at >= '{since_val}'"));
        }
        let sql = format!(
            "SELECT e.id, e.event_type, e.actor, e.summary, e.details, e.command, e.exit_code, \
             e.working_dir, e.project_context, e.search_keywords, e.occurred_at, e.is_consolidated \
             FROM episodic_memory e \
             JOIN episodic_memory_fts f ON e.rowid = f.rowid \
             WHERE {} \
             ORDER BY bm25(episodic_memory_fts, 10.0, 5.0, 2.0) \
             LIMIT ?2",
            conditions.join(" AND ")
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Self::row_to_episodic(row)
        })?;
        rows.collect()
    }

    pub fn search_semantic_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::SemanticItem>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut stmt = self.conn.prepare(
            "SELECT s.id, s.name, s.category, s.summary, s.details, s.search_keywords, \
             s.access_count, s.last_accessed, s.created_at, s.updated_at \
             FROM semantic_memory s \
             JOIN semantic_memory_fts f ON s.rowid = f.rowid \
             WHERE semantic_memory_fts MATCH ?1 \
             ORDER BY bm25(semantic_memory_fts, 10.0, 8.0, 5.0, 2.0) \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Ok(crate::memory::types::SemanticItem {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                summary: row.get(3)?,
                details: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_top_accessed_semantic(
        &self,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::SemanticItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, category, summary, details, search_keywords, \
             access_count, last_accessed, created_at, updated_at \
             FROM semantic_memory \
             ORDER BY access_count DESC, last_accessed DESC \
             LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(crate::memory::types::SemanticItem {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                summary: row.get(3)?,
                details: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_all_semantic(&self) -> rusqlite::Result<Vec<crate::memory::types::SemanticItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, category, summary, details, search_keywords, \
             access_count, last_accessed, created_at, updated_at \
             FROM semantic_memory \
             ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(crate::memory::types::SemanticItem {
                id: row.get(0)?,
                name: row.get(1)?,
                category: row.get(2)?,
                summary: row.get(3)?,
                details: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn search_procedural_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::ProceduralItem>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.entry_type, p.trigger_pattern, p.summary, p.steps, p.search_keywords, \
             p.access_count, p.last_accessed, p.created_at, p.updated_at \
             FROM procedural_memory p \
             JOIN procedural_memory_fts f ON p.rowid = f.rowid \
             WHERE procedural_memory_fts MATCH ?1 \
             ORDER BY bm25(procedural_memory_fts, 10.0, 5.0, 2.0) \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Ok(crate::memory::types::ProceduralItem {
                id: row.get(0)?,
                entry_type: row.get(1)?,
                trigger_pattern: row.get(2)?,
                summary: row.get(3)?,
                steps: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn list_all_procedural(
        &self,
    ) -> rusqlite::Result<Vec<crate::memory::types::ProceduralItem>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, entry_type, trigger_pattern, summary, steps, search_keywords, \
             access_count, last_accessed, created_at, updated_at \
             FROM procedural_memory ORDER BY last_accessed DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(crate::memory::types::ProceduralItem {
                id: row.get(0)?,
                entry_type: row.get(1)?,
                trigger_pattern: row.get(2)?,
                summary: row.get(3)?,
                steps: row.get(4)?,
                search_keywords: row.get(5)?,
                access_count: row.get(6)?,
                last_accessed: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;
        rows.collect()
    }

    pub fn search_resource_fts(
        &self,
        query: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<crate::memory::types::ResourceItem>> {
        let fts_query = Self::to_fts_literal_query(query);
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.resource_type, r.file_path, r.file_hash, r.title, r.summary, \
             r.content, r.search_keywords, r.created_at, r.updated_at \
             FROM resource_memory r \
             JOIN resource_memory_fts f ON r.rowid = f.rowid \
             WHERE resource_memory_fts MATCH ?1 \
             ORDER BY bm25(resource_memory_fts, 10.0, 8.0, 5.0, 2.0) \
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |row| {
            Self::row_to_resource(row)
        })?;
        rows.collect()
    }

    pub(crate) fn row_to_resource(
        row: &rusqlite::Row,
    ) -> rusqlite::Result<crate::memory::types::ResourceItem> {
        Ok(crate::memory::types::ResourceItem {
            id: row.get(0)?,
            resource_type: row.get(1)?,
            file_path: row.get(2)?,
            file_hash: row.get(3)?,
            title: row.get(4)?,
            summary: row.get(5)?,
            content: row.get(6)?,
            search_keywords: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
        })
    }

    pub fn search_knowledge_fts(
        &self,
        query: &str,
        limit: usize,
        allowed_sensitivity: &[&str],
    ) -> rusqlite::Result<Vec<crate::memory::types::KnowledgeEntry>> {
        let fts_query = Self::to_fts_literal_query(query);
        let placeholders: Vec<String> = (0..allowed_sensitivity.len())
            .map(|i| format!("?{}", i + 3))
            .collect();
        let sensitivity_clause = if allowed_sensitivity.is_empty() {
            "1=1".to_string()
        } else {
            format!("k.sensitivity IN ({})", placeholders.join(","))
        };
        let sql = format!(
            "SELECT k.id, k.entry_type, k.caption, k.secret_value, k.sensitivity, \
             k.search_keywords, k.created_at, k.updated_at \
             FROM knowledge_vault k \
             JOIN knowledge_vault_fts f ON k.rowid = f.rowid \
             WHERE knowledge_vault_fts MATCH ?1 AND {sensitivity_clause} \
             ORDER BY bm25(knowledge_vault_fts, 10.0, 2.0) \
             LIMIT ?2"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        all_params.push(Box::new(fts_query));
        all_params.push(Box::new(limit as i64));
        for s in allowed_sensitivity {
            all_params.push(Box::new(s.to_string()));
        }
        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            all_params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(params_refs.as_slice(), |row| {
            let sensitivity_str: String = row.get(4)?;
            let sensitivity =
                crate::memory::types::Sensitivity::parse(&sensitivity_str).map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        4,
                        "sensitivity".into(),
                        rusqlite::types::Type::Text,
                    )
                })?;
            Ok(crate::memory::types::KnowledgeEntry {
                id: row.get(0)?,
                entry_type: row.get(1)?,
                caption: row.get(2)?,
                secret_value: row.get(3)?,
                sensitivity,
                search_keywords: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn get_memory_config(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM memory_config WHERE key = ?",
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn set_memory_config(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO memory_config(key, value) VALUES (?, ?)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn memory_stats(&self) -> rusqlite::Result<crate::memory::types::MemoryStats> {
        let core_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM core_memory", [], |row| row.get(0))?;
        let episodic_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM episodic_memory", [], |row| row.get(0))?;
        let semantic_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM semantic_memory", [], |row| row.get(0))?;
        let procedural_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM procedural_memory", [], |row| {
                row.get(0)
            })?;
        let resource_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM resource_memory", [], |row| row.get(0))?;
        let knowledge_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM knowledge_vault", [], |row| row.get(0))?;
        Ok(crate::memory::types::MemoryStats {
            core_count: core_count as usize,
            episodic_count: episodic_count as usize,
            semantic_count: semantic_count as usize,
            procedural_count: procedural_count as usize,
            resource_count: resource_count as usize,
            knowledge_count: knowledge_count as usize,
        })
    }

    pub fn clear_memories_by_type(
        &self,
        memory_type: crate::memory::types::MemoryType,
    ) -> rusqlite::Result<usize> {
        let (table, fts_table) = match memory_type {
            crate::memory::types::MemoryType::Core => {
                self.conn
                    .execute("UPDATE core_memory SET value = ''", [])?;
                return Ok(3);
            }
            crate::memory::types::MemoryType::Episodic => {
                ("episodic_memory", "episodic_memory_fts")
            }
            crate::memory::types::MemoryType::Semantic => {
                ("semantic_memory", "semantic_memory_fts")
            }
            crate::memory::types::MemoryType::Procedural => {
                ("procedural_memory", "procedural_memory_fts")
            }
            crate::memory::types::MemoryType::Resource => {
                ("resource_memory", "resource_memory_fts")
            }
            crate::memory::types::MemoryType::Knowledge => {
                ("knowledge_vault", "knowledge_vault_fts")
            }
        };
        let count = self
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })? as usize;
        self.conn.execute(&format!("DELETE FROM {table}"), [])?;
        self.conn.execute(
            &format!("INSERT INTO {fts_table}({fts_table}) VALUES('rebuild')"),
            [],
        )?;
        Ok(count)
    }

    pub(crate) fn row_to_episodic(
        row: &rusqlite::Row,
    ) -> rusqlite::Result<crate::memory::types::EpisodicEvent> {
        let event_type_str: String = row.get(1)?;
        let actor_str: String = row.get(2)?;
        let event_type =
            crate::memory::types::EventType::parse(&event_type_str).map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    1,
                    "event_type".into(),
                    rusqlite::types::Type::Text,
                )
            })?;
        let actor = crate::memory::types::Actor::parse(&actor_str).map_err(|_| {
            rusqlite::Error::InvalidColumnType(2, "actor".into(), rusqlite::types::Type::Text)
        })?;
        Ok(crate::memory::types::EpisodicEvent {
            id: row.get(0)?,
            event_type,
            actor,
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
}
