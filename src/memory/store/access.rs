use rusqlite::Connection;
use serde_json::Value;

use crate::memory::search;
use crate::memory::types::{
    CoreBlock, CoreLabel, CoreOp, MemoryOp, MemoryStats, MemoryType, SearchResult,
};

use super::{core, episodic, knowledge, procedural, resource, semantic};

pub struct MemoryStoreAccess<'a> {
    conn: &'a Connection,
}

impl<'a> MemoryStoreAccess<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    pub fn core_memory(&self) -> anyhow::Result<Vec<CoreBlock>> {
        core::get_all(self.conn)
    }

    pub fn update_core_block(
        &self,
        label: CoreLabel,
        op: CoreOp,
        content: &str,
    ) -> anyhow::Result<()> {
        match op {
            CoreOp::Append => core::append(self.conn, label, content),
            CoreOp::Rewrite => core::rewrite(self.conn, label, content),
        }
    }

    pub fn search(
        &self,
        query: &str,
        memory_type: Option<MemoryType>,
        limit: usize,
    ) -> anyhow::Result<Vec<SearchResult>> {
        search::search_all(self.conn, query, memory_type, limit)
    }

    pub fn delete_memory(&self, memory_type: MemoryType, id: &str) -> anyhow::Result<()> {
        let ids = vec![id.to_string()];
        match memory_type {
            MemoryType::Core => anyhow::bail!("Cannot delete core memory blocks"),
            MemoryType::Episodic => {
                episodic::delete(self.conn, &ids)?;
            }
            MemoryType::Semantic => {
                semantic::delete(self.conn, &ids)?;
            }
            MemoryType::Procedural => {
                procedural::delete(self.conn, &ids)?;
            }
            MemoryType::Resource => {
                resource::delete(self.conn, &ids)?;
            }
            MemoryType::Knowledge => {
                knowledge::delete(self.conn, &ids)?;
            }
        }
        Ok(())
    }

    pub fn export_all(&self) -> anyhow::Result<Value> {
        let core = core::get_all(self.conn)?;
        let episodic = episodic::list_all(self.conn)?;
        let semantic = semantic::list_all(self.conn)?;
        let procedural = procedural::list_all(self.conn)?;
        let resource = resource::list_all(self.conn)?;
        let knowledge = knowledge::list_all(self.conn)?;

        Ok(serde_json::json!({
            "core": core,
            "episodic": episodic,
            "semantic": semantic,
            "procedural": procedural,
            "resource": resource,
            "knowledge": knowledge,
        }))
    }

    pub fn stats(&self) -> anyhow::Result<MemoryStats> {
        Ok(MemoryStats {
            core_count: 3,
            episodic_count: episodic::count(self.conn)?,
            semantic_count: semantic::count(self.conn)?,
            procedural_count: procedural::count(self.conn)?,
            resource_count: resource::count(self.conn)?,
            knowledge_count: knowledge::count(self.conn)?,
        })
    }

    pub fn clear_all(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "DELETE FROM episodic_memory;
             DELETE FROM semantic_memory;
             DELETE FROM procedural_memory;
             DELETE FROM resource_memory;
             DELETE FROM knowledge_vault;
             UPDATE core_memory SET value = '', updated_at = datetime('now');
             DELETE FROM memory_config WHERE key IN ('last_decay_at', 'last_reflection_at', 'last_bootstrap_at');",
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn set_config(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES (?, ?)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn resource_exists_with_hash(
        &self,
        path: &std::path::Path,
        hash: &str,
    ) -> anyhow::Result<bool> {
        resource::exists_with_hash(self.conn, &path.to_string_lossy(), hash)
    }

    pub fn apply_op(&self, op: &MemoryOp) -> anyhow::Result<()> {
        match op {
            MemoryOp::CoreAppend { label, content } => {
                core::append(self.conn, *label, content)?;
            }
            MemoryOp::CoreRewrite { label, content } => {
                core::rewrite(self.conn, *label, content)?;
            }
            MemoryOp::EpisodicInsert { event } => {
                episodic::insert(self.conn, event)?;
            }
            MemoryOp::EpisodicMerge {
                target_id,
                combined_summary,
                additional_details,
                search_keywords,
            } => {
                episodic::merge(
                    self.conn,
                    target_id,
                    combined_summary,
                    additional_details.as_deref(),
                    search_keywords,
                )?;
            }
            MemoryOp::EpisodicDelete { ids } => {
                episodic::delete(self.conn, ids)?;
            }
            MemoryOp::SemanticInsert {
                name,
                category,
                summary,
                details,
                search_keywords,
            } => {
                semantic::store(
                    self.conn,
                    &semantic::SemanticWrite {
                        name,
                        category,
                        summary,
                        details: details.as_deref(),
                        search_keywords,
                    },
                )?;
            }
            MemoryOp::SemanticUpdate {
                id,
                summary,
                details,
                search_keywords,
            } => {
                semantic::update(
                    self.conn,
                    id,
                    &semantic::SemanticUpdate {
                        summary,
                        details: details.as_deref(),
                        search_keywords,
                    },
                )?;
            }
            MemoryOp::SemanticDelete { ids } => {
                semantic::delete(self.conn, ids)?;
            }
            MemoryOp::ProceduralInsert {
                entry_type,
                trigger_pattern,
                summary,
                steps,
                search_keywords,
            } => {
                procedural::store(
                    self.conn,
                    &procedural::ProceduralWrite {
                        entry_type,
                        trigger_pattern,
                        summary,
                        steps,
                        search_keywords,
                    },
                )?;
            }
            MemoryOp::ProceduralUpdate {
                id,
                summary,
                steps,
                search_keywords,
            } => {
                procedural::update(
                    self.conn,
                    id,
                    &procedural::ProceduralUpdate {
                        summary,
                        steps,
                        search_keywords,
                    },
                )?;
            }
            MemoryOp::ProceduralDelete { ids } => {
                procedural::delete(self.conn, ids)?;
            }
            MemoryOp::ResourceInsert {
                resource_type,
                file_path,
                file_hash,
                title,
                summary,
                content,
                search_keywords,
            } => {
                resource::store(
                    self.conn,
                    &resource::ResourceWrite {
                        resource_type,
                        file_path: file_path.as_deref(),
                        file_hash: file_hash.as_deref(),
                        title,
                        summary,
                        content: content.as_deref(),
                        search_keywords,
                    },
                )?;
            }
            MemoryOp::ResourceDelete { ids } => {
                resource::delete(self.conn, ids)?;
            }
            MemoryOp::KnowledgeInsert {
                entry_type,
                caption,
                secret_value,
                sensitivity,
                search_keywords,
            } => {
                knowledge::store(
                    self.conn,
                    &knowledge::KnowledgeWrite {
                        entry_type,
                        caption,
                        secret_value,
                        sensitivity: *sensitivity,
                        search_keywords,
                    },
                )?;
            }
            MemoryOp::KnowledgeDelete { ids } => {
                knowledge::delete(self.conn, ids)?;
            }
            MemoryOp::NoOp { .. } => {}
        }
        Ok(())
    }
}
