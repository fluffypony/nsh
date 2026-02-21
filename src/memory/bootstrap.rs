use rusqlite::Connection;

use crate::memory::llm_adapter::MemoryLlmClient;
use crate::memory::types::BootstrapReport;

pub async fn bootstrap_scan(
    conn: &Connection,
    llm: &dyn MemoryLlmClient,
) -> anyhow::Result<BootstrapReport> {
    let mut report = BootstrapReport::default();

    let home = dirs::home_dir().unwrap_or_default();

    let config_files = [
        (".zshrc", "Zsh configuration"),
        (".bashrc", "Bash configuration"),
        (".bash_profile", "Bash profile"),
        (".profile", "Shell profile"),
        (".gitconfig", "Git configuration"),
        (".ssh/config", "SSH configuration"),
        (".cargo/config.toml", "Cargo configuration"),
        (".npmrc", "npm configuration"),
        (".docker/config.json", "Docker configuration"),
    ];

    for (filename, description) in &config_files {
        let path = home.join(filename);
        if !path.exists() {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Skip very large files
        if content.len() > 50_000 {
            continue;
        }

        // Redact secrets before sending to LLM
        let (redacted, _) = crate::memory::privacy::redact_secrets_for_memory(&content);

        let prompt = format!(
            "Summarize this config file in 2-3 sentences. What tools, settings, and preferences does it reveal?\n\nFile: {filename} ({description})\n\n```\n{redacted}\n```\n\nAlso provide 5-10 search keywords as a space-separated string.\n\nRespond with JSON: {{\"summary\": \"...\", \"keywords\": \"...\"}}"
        );

        match llm.complete_json(&prompt).await {
            Ok(response) => {
                let (summary, keywords) = parse_bootstrap_response(&response, description);
                let path_str = path.to_string_lossy().to_string();
                let hash = compute_hash(&content);
                crate::memory::store::resource::upsert_by_path(
                    conn,
                    "config",
                    &path_str,
                    &hash,
                    description,
                    &summary,
                    None,
                    &keywords,
                )?;
                report.files_scanned += 1;
            }
            Err(e) => {
                tracing::warn!("Bootstrap scan failed for {filename}: {e}");
            }
        }
    }

    // Detect installed tools for Environment core block
    let tools = detect_installed_tools();
    if !tools.is_empty() {
        let env_text = format!("Installed tools: {}", tools.join(", "));
        crate::memory::store::core::append(
            conn,
            crate::memory::types::CoreLabel::Environment,
            &env_text,
        )?;
    }

    // Record bootstrap completion
    conn.execute(
        "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_bootstrap_at', datetime('now'))",
        [],
    )?;

    Ok(report)
}

fn parse_bootstrap_response(response: &str, default_desc: &str) -> (String, String) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(response.trim()) {
        let summary = v["summary"]
            .as_str()
            .unwrap_or(default_desc)
            .to_string();
        let keywords = v["keywords"].as_str().unwrap_or("").to_string();
        (summary, keywords)
    } else {
        (default_desc.to_string(), String::new())
    }
}

fn detect_installed_tools() -> Vec<String> {
    let tools_to_check = [
        "git", "cargo", "rustc", "node", "npm", "python3", "pip3",
        "docker", "kubectl", "terraform", "go", "java", "ruby",
        "brew", "apt", "dnf", "vim", "nvim", "code", "tmux",
    ];

    tools_to_check
        .iter()
        .filter(|tool| which::which(tool).is_ok())
        .map(|t| t.to_string())
        .collect()
}

fn compute_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn has_bootstrapped(conn: &Connection) -> bool {
    let last: Option<String> = conn
        .query_row(
            "SELECT value FROM memory_config WHERE key = 'last_bootstrap_at'",
            [],
            |r| r.get(0),
        )
        .ok();
    matches!(last, Some(ts) if !ts.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bootstrap_response_valid() {
        let resp = r#"{"summary": "Uses git with aliases", "keywords": "git alias config"}"#;
        let (summary, keywords) = parse_bootstrap_response(resp, "default");
        assert_eq!(summary, "Uses git with aliases");
        assert_eq!(keywords, "git alias config");
    }

    #[test]
    fn parse_bootstrap_response_invalid() {
        let (summary, keywords) = parse_bootstrap_response("not json", "default desc");
        assert_eq!(summary, "default desc");
        assert!(keywords.is_empty());
    }

    #[test]
    fn detect_installed_tools_runs() {
        let tools = detect_installed_tools();
        // At minimum, we should find some common tools
        // This test just verifies it doesn't panic
        assert!(tools.len() >= 0);
    }

    #[test]
    fn compute_hash_deterministic() {
        let h1 = compute_hash("hello");
        let h2 = compute_hash("hello");
        assert_eq!(h1, h2);
        assert_ne!(compute_hash("hello"), compute_hash("world"));
    }

    #[test]
    fn has_bootstrapped_false_initially() {
        let conn = Connection::open_in_memory().unwrap();
        crate::memory::schema::create_memory_tables(&conn).unwrap();
        assert!(!has_bootstrapped(&conn));
    }

    #[test]
    fn has_bootstrapped_true_after_marking() {
        let conn = Connection::open_in_memory().unwrap();
        crate::memory::schema::create_memory_tables(&conn).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_bootstrap_at', datetime('now'))",
            [],
        ).unwrap();

        assert!(has_bootstrapped(&conn));
    }

    #[test]
    fn parse_bootstrap_response_partial() {
        let resp = r#"{"summary": "has aliases"}"#;
        let (summary, keywords) = parse_bootstrap_response(resp, "default");
        assert_eq!(summary, "has aliases");
        assert!(keywords.is_empty());
    }

    #[test]
    fn compute_hash_different_inputs() {
        let h1 = compute_hash("hello world");
        let h2 = compute_hash("hello world!");
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_hash_empty() {
        let h = compute_hash("");
        assert!(!h.is_empty());
        assert_eq!(h.len(), 64); // SHA-256 hex is 64 chars
    }

    #[test]
    fn compute_hash_unicode() {
        let h = compute_hash("こんにちは");
        assert!(!h.is_empty());
        assert_eq!(h.len(), 64);
    }
}
