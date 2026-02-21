pub mod fts;

use rusqlite::Connection;
use crate::memory::types::{MemoryType, SearchResult, Sensitivity};

pub fn search_all(
    conn: &Connection,
    query: &str,
    limit_per_type: usize,
) -> anyhow::Result<Vec<SearchResult>> {
    let mut results = Vec::new();

    if let Ok(episodic) = crate::memory::store::episodic::search_bm25(conn, query, limit_per_type, None) {
        for e in episodic {
            results.push(SearchResult {
                memory_type: MemoryType::Episodic,
                id: e.id,
                title: e.summary.clone(),
                summary: e.details.unwrap_or_default(),
                relevance_score: 0.0,
            });
        }
    }

    if let Ok(semantic) = crate::memory::store::semantic::search_bm25(conn, query, limit_per_type) {
        for s in semantic {
            results.push(SearchResult {
                memory_type: MemoryType::Semantic,
                id: s.id,
                title: s.name,
                summary: s.summary,
                relevance_score: 0.0,
            });
        }
    }

    if let Ok(procedural) = crate::memory::store::procedural::search_bm25(conn, query, limit_per_type) {
        for p in procedural {
            results.push(SearchResult {
                memory_type: MemoryType::Procedural,
                id: p.id,
                title: p.summary.clone(),
                summary: p.steps,
                relevance_score: 0.0,
            });
        }
    }

    if let Ok(resource) = crate::memory::store::resource::search_bm25(conn, query, limit_per_type) {
        for r in resource {
            results.push(SearchResult {
                memory_type: MemoryType::Resource,
                id: r.id,
                title: r.title,
                summary: r.summary,
                relevance_score: 0.0,
            });
        }
    }

    if let Ok(knowledge) = crate::memory::store::knowledge::search_bm25(conn, query, limit_per_type, Sensitivity::Medium) {
        for k in knowledge {
            results.push(SearchResult {
                memory_type: MemoryType::Knowledge,
                id: k.id,
                title: k.caption,
                summary: String::new(),
                relevance_score: 0.0,
            });
        }
    }

    Ok(results)
}
