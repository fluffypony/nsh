pub mod fts;

use rusqlite::Connection;
use crate::memory::types::{MemoryType, SearchResult, Sensitivity};

pub fn search_all(
    conn: &Connection,
    query: &str,
    limit_per_type: usize,
) -> anyhow::Result<Vec<SearchResult>> {
    let mut results = Vec::new();

    if let Ok(episodic) = crate::memory::store::episodic::search_bm25(conn, query, limit_per_type, None, None) {
        for e in episodic {
            results.push(SearchResult {
                memory_type: MemoryType::Episodic,
                id: e.id,
                summary: e.details.unwrap_or_else(|| e.summary.clone()),
                score: 0.0,
            });
        }
    }

    if let Ok(semantic) = crate::memory::store::semantic::search_bm25(conn, query, limit_per_type) {
        for s in semantic {
            results.push(SearchResult {
                memory_type: MemoryType::Semantic,
                id: s.id,
                summary: s.summary,
                score: 0.0,
            });
        }
    }

    if let Ok(procedural) = crate::memory::store::procedural::search_bm25(conn, query, limit_per_type) {
        for p in procedural {
            results.push(SearchResult {
                memory_type: MemoryType::Procedural,
                id: p.id,
                summary: p.steps,
                score: 0.0,
            });
        }
    }

    if let Ok(resource) = crate::memory::store::resource::search_bm25(conn, query, limit_per_type) {
        for r in resource {
            results.push(SearchResult {
                memory_type: MemoryType::Resource,
                id: r.id,
                summary: r.summary,
                score: 0.0,
            });
        }
    }

    if let Ok(knowledge) = crate::memory::store::knowledge::search_bm25(conn, query, limit_per_type, Sensitivity::Medium) {
        for k in knowledge {
            results.push(SearchResult {
                memory_type: MemoryType::Knowledge,
                id: k.id,
                summary: String::from("sensitive secret (caption only)"),
                score: 0.0,
            });
        }
    }

    Ok(results)
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
    fn search_all_empty_db() {
        let conn = setup();
        let results = search_all(&conn, "test query", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_all_finds_across_types() {
        let conn = setup();

        // Insert into different memory types
        crate::memory::store::episodic::insert(
            &conn,
            &crate::memory::types::EpisodicEventCreate {
                event_type: crate::memory::types::EventType::CommandExecution,
                actor: crate::memory::types::Actor::User,
                summary: "Ran cargo build for deployment".into(),
                details: None,
                command: Some("cargo build".into()),
                exit_code: Some(0),
                working_dir: None,
                project_context: None,
                search_keywords: "cargo build deployment".into(),
            },
        )
        .unwrap();

        crate::memory::store::semantic::insert_or_update(
            &conn,
            "Rust toolchain",
            "knowledge",
            "Uses cargo for building Rust projects",
            None,
            "cargo rust build toolchain",
        )
        .unwrap();

        let results = search_all(&conn, "cargo build", 10).unwrap();
        assert!(results.len() >= 2, "should find results across episodic and semantic");

        let types: Vec<MemoryType> = results.iter().map(|r| r.memory_type).collect();
        assert!(types.contains(&MemoryType::Episodic));
        assert!(types.contains(&MemoryType::Semantic));
    }

    #[test]
    fn search_all_respects_limit() {
        let conn = setup();

        for i in 0..5 {
            crate::memory::store::semantic::insert_or_update(
                &conn,
                &format!("fact_{i}"),
                "general",
                &format!("A rust programming fact number {i}"),
                None,
                "rust programming",
            )
            .unwrap();
        }

        let results = search_all(&conn, "rust programming", 2).unwrap();
        // limit_per_type=2 means at most 2 per memory type
        let semantic_count = results.iter().filter(|r| r.memory_type == MemoryType::Semantic).count();
        assert!(semantic_count <= 2, "should respect limit per type");
    }

    #[test]
    fn search_all_empty_query_no_crash() {
        let conn = setup();
        let results = search_all(&conn, "", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_all_includes_knowledge() {
        let conn = setup();

        crate::memory::store::knowledge::insert(
            &conn,
            "api_key",
            "GitHub personal access token",
            "ghp_test123",
            Sensitivity::Low,
            "github token api",
        )
        .unwrap();

        let results = search_all(&conn, "github token", 10).unwrap();
        assert!(!results.is_empty());
        let k = results.iter().find(|r| r.memory_type == MemoryType::Knowledge);
        assert!(k.is_some(), "should find knowledge entries");
        // Secret value should NOT be in summary
        assert!(!k.unwrap().summary.contains("ghp_test123"));
    }

    #[test]
    fn search_all_includes_procedural() {
        let conn = setup();

        crate::memory::store::procedural::insert(
            &conn,
            "workflow",
            "deploy",
            "Deploy application to production server",
            r#"["build", "test", "deploy"]"#,
            "deploy production workflow",
        )
        .unwrap();

        let results = search_all(&conn, "deploy production", 10).unwrap();
        let p = results.iter().find(|r| r.memory_type == MemoryType::Procedural);
        assert!(p.is_some(), "should find procedural entries");
    }

    #[test]
    fn search_all_includes_resource() {
        let conn = setup();

        crate::memory::store::resource::insert(
            &conn,
            "config",
            Some("/home/user/.gitconfig"),
            Some("abc"),
            "Git configuration",
            "Git config with aliases",
            None,
            "git config alias",
        )
        .unwrap();

        let results = search_all(&conn, "git config", 10).unwrap();
        let r = results.iter().find(|r| r.memory_type == MemoryType::Resource);
        assert!(r.is_some(), "should find resource entries");
    }
}
