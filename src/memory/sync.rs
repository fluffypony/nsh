//! Multi-device memory synchronization via iroh-docs CRDTs.
//!
//! Architecture:
//! - Each memory type (semantic, procedural, resource, core) maps to an
//!   iroh-docs Document, keyed by a namespace derived from the user's identity.
//! - Entries use the memory ID as the iroh-docs key. Values are JSON.
//! - iroh-docs provides automatic CRDT merge (last-writer-wins per key).
//! - Conflicts are resolved by `updated_at` timestamp.
//! - Deletions use tombstone entries.
//! - The local SQLite DB is treated as a materialized view of the CRDT,
//!   updating its FTS indexes reactively when the doc changes.
//!
//! Key schema: `{memory_type}/{id}` -> JSON-serialized memory entry
//! Episodic memory: append-only semantics (natural CRDT)
//! Semantic/procedural: LWW registers keyed by label
//! Core memory: LWW registers keyed by block label

/// Placeholder sync engine for multi-device memory replication.
///
/// When implemented, this will use iroh-docs to replicate memory
/// entries across devices via CRDTs. For now this is scaffolding
/// that establishes the module structure and public API.
#[cfg(feature = "remote")]
#[allow(dead_code)]
pub struct MemorySyncEngine {
    _placeholder: (),
}

#[cfg(feature = "remote")]
impl MemorySyncEngine {
    /// Initialize the sync engine with the user's secret key.
    pub async fn new(_secret_key: &iroh::SecretKey) -> anyhow::Result<Self> {
        // Future: initialize iroh-docs node, open/create documents per memory type
        Ok(Self { _placeholder: () })
    }

    /// Replicate a local memory write to the CRDT doc.
    pub async fn sync_memory_op(
        &self,
        _memory_type: &str,
        _id: &str,
        _data: &serde_json::Value,
    ) -> anyhow::Result<()> {
        // Future: write to iroh-docs document
        Ok(())
    }
}
