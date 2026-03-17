use rusqlite::params;

use super::Db;

impl Db {
    /// Prune old data beyond retention period
    pub fn prune(&self, retention_days: u32) -> rusqlite::Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let deleted = self.conn.execute(
            "DELETE FROM commands WHERE started_at < ?",
            params![cutoff_str],
        )?;
        self.conn.execute(
            "DELETE FROM sessions \
             WHERE ended_at IS NOT NULL AND ended_at < ?",
            params![cutoff_str],
        )?;
        self.conn.execute_batch(
            "INSERT INTO commands_fts(commands_fts) VALUES('optimize');
             PRAGMA incremental_vacuum;",
        )?;
        Ok(deleted)
    }

    pub fn rebuild_fts(&self) -> rusqlite::Result<()> {
        self.conn
            .execute_batch("INSERT INTO commands_fts(commands_fts) VALUES('rebuild')")
    }

    pub fn optimize_fts(&self) -> rusqlite::Result<()> {
        self.conn
            .execute_batch("INSERT INTO commands_fts(commands_fts) VALUES('optimize')")
    }

    pub fn check_fts_integrity(&self) -> rusqlite::Result<()> {
        self.conn
            .execute_batch("INSERT INTO commands_fts(commands_fts) VALUES('integrity-check')")
    }

    pub fn prune_if_due(&self, retention_days: u32) -> rusqlite::Result<()> {
        let should_prune: bool = self
            .conn
            .query_row(
                "SELECT COALESCE( \
                   (SELECT value FROM meta WHERE key='last_prune_at'), \
                   '2000-01-01T00:00:00Z' \
                 ) < datetime('now', '-1 day')",
                [],
                |row| row.get(0),
            )
            .unwrap_or(true);

        if should_prune {
            self.prune(retention_days)?;
            let now = chrono::Utc::now().to_rfc3339();
            self.conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('last_prune_at', ?)",
                params![now],
            )?;
        }
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?",
                params![key],
                |row| row.get(0),
            )
            .optional()
    }

    pub fn set_meta(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn run_doctor(
        &self,
        retention_days: u32,
        no_prune: bool,
        no_vacuum: bool,
        config: &crate::config::Config,
    ) -> anyhow::Result<()> {
        eprintln!("nsh doctor: checking system health...\n");

        // 1. Config file validation
        eprint!("  Config file... ");
        let config_path = crate::config::Config::path();
        if config_path.exists() {
            match std::fs::read_to_string(&config_path) {
                Ok(content) => match toml::from_str::<toml::Value>(&content) {
                    Ok(_) => eprintln!("OK ({})", config_path.display()),
                    Err(e) => eprintln!("PARSE ERROR: {e}"),
                },
                Err(e) => eprintln!("READ ERROR: {e}"),
            }
        } else {
            eprintln!("not found (using defaults)");
        }

        // 2. API key reachability
        eprint!("  API key ({})... ", config.provider.default);
        let auth = match config.provider.default.as_str() {
            "openrouter" => config.provider.openrouter.as_ref(),
            "anthropic" => config.provider.anthropic.as_ref(),
            "openai" => config.provider.openai.as_ref(),
            "ollama" => config.provider.ollama.as_ref(),
            "gemini" => config.provider.gemini.as_ref(),
            _ => None,
        };
        match auth {
            Some(a) => match a.resolve_api_key(&config.provider.default) {
                Ok(_) => eprintln!("OK"),
                Err(e) => eprintln!("MISSING: {e}"),
            },
            None => eprintln!("no auth configured"),
        }

        // 3. Shell hook integrity
        eprint!("  Shell hooks... ");
        let shell = std::env::var("SHELL").unwrap_or_default();
        let shell_name = shell.rsplit('/').next().unwrap_or("");
        let rc_path = match shell_name {
            "zsh" => Some(dirs::home_dir().unwrap_or_default().join(".zshrc")),
            "bash" => {
                let bashrc = dirs::home_dir().unwrap_or_default().join(".bashrc");
                let bash_profile = dirs::home_dir().unwrap_or_default().join(".bash_profile");
                if bashrc.exists() {
                    Some(bashrc)
                } else if bash_profile.exists() {
                    Some(bash_profile)
                } else {
                    Some(bashrc)
                }
            }
            "fish" => Some(
                dirs::config_dir()
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".config"))
                    .join("fish/conf.d/nsh.fish"),
            ),
            _ => None,
        };
        if let Some(ref path) = rc_path {
            if path.exists() {
                let content = std::fs::read_to_string(path).unwrap_or_default();
                if content.contains("nsh init") || content.contains("nsh wrap") {
                    eprintln!("OK ({})", path.display());
                } else {
                    eprintln!("MISSING — nsh init not found in {}", path.display());
                }
            } else {
                eprintln!("rc file not found: {}", path.display());
            }
        } else {
            eprintln!("unknown shell: {shell_name}");
        }

        // 4. DB size report
        eprint!("  Database... ");
        let db_path = crate::config::Config::nsh_dir().join("nsh.db");
        let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
        let db_size_str = if db_size > 1_048_576 {
            format!("{:.1} MB", db_size as f64 / 1_048_576.0)
        } else {
            format!("{:.1} KB", db_size as f64 / 1024.0)
        };
        eprintln!("{db_size_str}");

        // 5. FTS5 integrity
        eprint!("  FTS5 integrity... ");
        match self.check_fts_integrity() {
            Ok(()) => eprintln!("OK"),
            Err(e) => {
                eprintln!("FAILED: {e}");
                eprint!("  Rebuilding FTS5 index... ");
                self.rebuild_fts()?;
                eprintln!("done");
            }
        }

        eprint!("  FTS5 optimize... ");
        self.optimize_fts()?;
        eprintln!("OK");

        // 6. Orphaned sessions
        eprint!("  Orphaned sessions... ");
        let cleaned = self.cleanup_orphaned_sessions()?;
        eprintln!("{cleaned} cleaned");

        // 7. Missing summaries count
        eprint!("  Missing summaries... ");
        let missing_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM commands WHERE output IS NOT NULL AND summary IS NULL AND summary_status IS NULL",
            [],
            |row| row.get(0),
        ).unwrap_or(0);
        if missing_count > 0 {
            eprintln!("{missing_count} commands without summaries");
        } else {
            eprintln!("none");
        }

        // Memory system check
        eprint!("  Memory tables... ");
        let memory_count: i64 = self
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM episodic_memory) + \
                    (SELECT COUNT(*) FROM semantic_memory) + \
                    (SELECT COUNT(*) FROM procedural_memory) + \
                    (SELECT COUNT(*) FROM resource_memory) + \
                    (SELECT COUNT(*) FROM knowledge_vault)",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        eprintln!("{memory_count} total memory entries");

        eprint!("  Core memory... ");
        let core_count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM core_memory", [], |row| row.get(0))
            .unwrap_or(0);
        eprintln!("{core_count} blocks");

        eprint!("  Memory FTS5 integrity... ");
        let mut mem_fts_ok = true;
        for table in [
            "episodic_memory_fts",
            "semantic_memory_fts",
            "procedural_memory_fts",
            "resource_memory_fts",
            "knowledge_vault_fts",
        ] {
            if let Err(e) = self.conn.execute(
                &format!("INSERT INTO {table}({table}) VALUES('integrity-check')"),
                [],
            ) {
                eprintln!("FAILED ({table}): {e}");
                let _ = self
                    .conn
                    .execute_batch(&format!("INSERT INTO {table}({table}) VALUES('rebuild')"));
                mem_fts_ok = false;
            }
        }
        if mem_fts_ok {
            eprintln!("OK");
        }

        eprint!("  Core memory usage... ");
        for block in self.core_memory().unwrap_or_default() {
            let pct = if block.char_limit > 0 {
                (block.value.len() as f64 / block.char_limit as f64 * 100.0) as usize
            } else {
                0
            };
            eprint!("{}={}% ", block.label, pct);
        }
        eprintln!();

        // 8. Orphaned socket/PID files
        eprint!("  Orphaned files... ");
        let nsh_dir = crate::config::Config::nsh_dir();
        let mut orphaned_count = 0;
        if let Ok(entries) = std::fs::read_dir(&nsh_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Clean up legacy shared CWD index files
                if name == "tty_last_cwd"
                    || name == "tty_last_cwd.lock"
                    || name == "tty_last_cwd.tmp"
                {
                    let _ = std::fs::remove_file(entry.path());
                    orphaned_count += 1;
                    continue;
                }
                // Clean up orphaned per-TTY CWD files (skip active sessions)
                if name.starts_with("cwd_") && !name.ends_with(".tmp") {
                    // Extract TTY from filename: cwd__dev_ttys011 → /dev/ttys011
                    let tty = name.trim_start_matches("cwd_").replace('_', "/");
                    let tty_active: bool = self
                        .conn
                        .query_row(
                            "SELECT COUNT(*) > 0 FROM sessions WHERE tty = ? AND ended_at IS NULL",
                            params![tty],
                            |row| row.get(0),
                        )
                        .unwrap_or(false);
                    if !tty_active {
                        let _ = std::fs::remove_file(entry.path());
                        orphaned_count += 1;
                    }
                    continue;
                }
                if (name.starts_with("daemon_")
                    && (name.ends_with(".sock") || name.ends_with(".pid")))
                    || name.starts_with("scrollback_") && !name.ends_with(".sock")
                    || name.starts_with("pending_cmd_")
                    || name.starts_with("pending_flag_")
                    || name.starts_with("pending_autorun_")
                {
                    let session_id = name
                        .trim_start_matches("daemon_")
                        .trim_start_matches("scrollback_")
                        .trim_start_matches("pending_cmd_")
                        .trim_start_matches("pending_flag_")
                        .trim_start_matches("pending_autorun_")
                        .trim_end_matches(".sock")
                        .trim_end_matches(".pid")
                        .trim_end_matches(".tmp");
                    let session_active: bool = self
                        .conn
                        .query_row(
                            "SELECT COUNT(*) > 0 FROM sessions WHERE id = ? AND ended_at IS NULL",
                            params![session_id],
                            |row| row.get(0),
                        )
                        .unwrap_or(false);
                    if !session_active {
                        let _ = std::fs::remove_file(entry.path());
                        orphaned_count += 1;
                    }
                }
            }
        }
        eprintln!("{orphaned_count} removed");

        // 9. Pruning
        if !no_prune {
            eprint!("  Pruning old data ({retention_days} days)... ");
            let pruned = self.prune(retention_days)?;
            eprintln!("{pruned} commands removed");
        } else {
            eprintln!("  Pruning... skipped (--no-prune)");
        }

        // 10. Vacuum
        if !no_vacuum {
            eprint!("  Incremental vacuum... ");
            self.conn.execute_batch("PRAGMA incremental_vacuum")?;
            eprintln!("OK");
        } else {
            eprintln!("  Vacuum... skipped (--no-vacuum)");
        }

        // 11. Integrity check
        eprint!("  Integrity check... ");
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        eprintln!("{result}");

        // 12. Memory health section
        let mem_health = self.build_memory_health_section();
        eprint!("{mem_health}");

        eprintln!("\nnsh doctor: done");

        Ok(())
    }

    pub(crate) fn build_memory_health_section(&self) -> String {
        // Fetch counts
        let stats = self.memory_stats().unwrap_or_default();
        let decay_runs: i64 = self
            .get_memory_config("decay_runs")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let last_decay_at = self
            .get_memory_config("last_decay_at")
            .ok()
            .flatten()
            .unwrap_or_else(|| "".into());
        let reflection_runs: i64 = self
            .get_memory_config("reflection_runs")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let last_reflection_at = self
            .get_memory_config("last_reflection_at")
            .ok()
            .flatten()
            .unwrap_or_else(|| "".into());

        // Heuristics
        let mut decay_status = "OK".to_string();
        if let Some(ts) = Self::parse_sqlite_datetime(&last_decay_at)
            && (chrono::Utc::now() - ts).num_hours() > 48 {
                decay_status = "WARN: last decay > 48h ago".into();
            }
        let mut reflection_status = "OK".to_string();
        if reflection_runs == 0 && stats.episodic_count > 100 {
            reflection_status = "WARN: no reflections and episodic>100".into();
        }

        let mut s = String::new();
        s.push_str("\nMemory Health:\n");
        s.push_str(&format!("  Last decay: {last_decay_at} ({decay_status})\n"));
        s.push_str(&format!("  Decay runs: {decay_runs}\n"));
        s.push_str(&format!(
            "  Last reflection: {last_reflection_at} ({reflection_status})\n"
        ));
        s.push_str(&format!("  Reflection runs: {reflection_runs}\n"));
        s.push_str(&format!(
            "  Notes: episodic={}, semantic={}, procedural={}\n",
            stats.episodic_count, stats.semantic_count, stats.procedural_count
        ));
        s
    }

    pub(crate) fn parse_sqlite_datetime(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .or_else(|| {
                chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .map(|dt| dt.and_utc())
            })
    }
}

use rusqlite::OptionalExtension;
