use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::memory::llm_adapter::MemoryLlmClient;
use crate::memory::store::access::MemoryStoreAccess;
use crate::memory::types::{BootstrapReport, DecayReport, ReflectionReport};

pub struct MemoryMaintenance<'a> {
    db: &'a Arc<Mutex<Connection>>,
    config: &'a crate::config::MemoryConfig,
}

impl<'a> MemoryMaintenance<'a> {
    pub fn new(
        db: &'a Arc<Mutex<Connection>>,
        config: &'a crate::config::MemoryConfig,
    ) -> Self {
        Self { db, config }
    }

    pub fn run_decay(&self) -> anyhow::Result<DecayReport> {
        let conn = self.db.lock().unwrap();
        let report = crate::memory::decay::run_decay(
            &conn,
            self.config.fade_after_days,
            self.config.expire_after_days,
        )?;
        crate::memory::decay::record_decay_run(&conn)?;
        Ok(report)
    }

    pub async fn run_reflection(
        &self,
        llm: &dyn MemoryLlmClient,
    ) -> anyhow::Result<ReflectionReport> {
        let (unconsolidated, core, semantic, procedural) = {
            let conn = self.db.lock().unwrap();
            let unconsolidated = crate::memory::store::episodic::list_unconsolidated(&conn, 100)?;
            if unconsolidated.is_empty() {
                return Ok(ReflectionReport::default());
            }
            let core = crate::memory::store::core::get_all(&conn)?;
            let semantic = crate::memory::store::semantic::list_all(&conn)?;
            let procedural = crate::memory::store::procedural::list_all(&conn)?;
            (unconsolidated, core, semantic, procedural)
        };

        let prompt =
            crate::memory::reflection::build_reflection_prompt(&unconsolidated, &core, &semantic, &procedural);
        let response = llm.complete_json(&prompt).await?;
        let ops = crate::memory::reflection::parse_reflection_response(&response);

        let mut report = ReflectionReport::default();
        let ids: Vec<String> = unconsolidated.iter().map(|event| event.id.clone()).collect();
        let conn = self.db.lock().unwrap();
        let store = MemoryStoreAccess::new(&conn);
        for op in &ops {
            if store.apply_op(op).is_ok() {
                report.ops_applied += 1;
            }
        }
        crate::memory::store::episodic::mark_consolidated(&conn, &ids)?;
        let _ = conn.execute(
            "INSERT INTO memory_config(key, value) VALUES('last_reflection_at', datetime('now')) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![],
        );
        let _ = conn.execute(
            "INSERT INTO memory_config(key, value) VALUES('reflection_runs', '1') \
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
            rusqlite::params![],
        );
        Ok(report)
    }

    pub async fn bootstrap_scan(
        &self,
        llm: &dyn MemoryLlmClient,
    ) -> anyhow::Result<BootstrapReport> {
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

        let mut report = BootstrapReport::default();

        for (filename, description) in &config_files {
            let path = home.join(filename);
            if !path.exists() {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(_) => continue,
            };
            if content.len() > 50_000 {
                continue;
            }
            let (redacted, _) = crate::memory::privacy::redact_secrets_for_memory(&content);
            let prompt = format!(
                "Summarize this config file in 2-3 sentences. What tools, settings, and preferences does it reveal?\n\nFile: {filename} ({description})\n\n```\n{redacted}\n```\n\nAlso provide 5-10 search keywords as a space-separated string.\n\nRespond with JSON: {{\"summary\": \"...\", \"keywords\": \"...\"}}"
            );

            if let Ok(response) = llm.complete_json(&prompt).await {
                let (summary, keywords) =
                    crate::memory::bootstrap::parse_bootstrap_response(&response, description);
                let path_str = path.to_string_lossy().to_string();
                let hash = crate::memory::bootstrap::compute_hash(&content);
                let conn = self.db.lock().unwrap();
                crate::memory::store::resource::store(
                    &conn,
                    &crate::memory::store::resource::ResourceWrite {
                        resource_type: "config",
                        file_path: Some(&path_str),
                        file_hash: Some(&hash),
                        title: description,
                        summary: &summary,
                        content: None,
                        search_keywords: &keywords,
                    },
                )?;
                report.files_scanned += 1;
            }
        }

        let tools = crate::memory::bootstrap::detect_installed_tools();
        if !tools.is_empty() {
            let env_text = format!("Installed tools: {}", tools.join(", "));
            let conn = self.db.lock().unwrap();
            crate::memory::store::core::append(
                &conn,
                crate::memory::types::CoreLabel::Environment,
                &env_text,
            )?;
        }

        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_bootstrap_at', datetime('now'))",
            [],
        )?;

        Ok(report)
    }

    pub fn has_bootstrapped(&self) -> bool {
        let conn = self.db.lock().unwrap();
        crate::memory::bootstrap::has_bootstrapped(&conn)
    }

    pub fn should_run_reflection(&self) -> bool {
        let conn = self.db.lock().unwrap();
        crate::memory::reflection::should_run_reflection(&conn, self.config.consolidation_threshold)
    }

    pub fn should_run_decay(&self) -> bool {
        let conn = self.db.lock().unwrap();
        crate::memory::decay::should_run_decay(&conn)
    }
}
