use std::collections::{HashMap, VecDeque};
use std::time::Instant;

pub struct ToolHealthTracker {
    outcomes: HashMap<String, VecDeque<(Instant, bool)>>,
}

impl ToolHealthTracker {
    pub fn new() -> Self {
        Self { outcomes: HashMap::new() }
    }

    pub fn record(&mut self, tool: &str, success: bool) {
        let entries = self.outcomes.entry(tool.to_string()).or_default();
        entries.push_back((Instant::now(), success));
        while entries.len() > 20 {
            entries.pop_front();
        }
    }

    pub fn consecutive_failures(&self, tool: &str) -> usize {
        self.outcomes
            .get(tool)
            .map(|entries| entries.iter().rev().take_while(|(_, ok)| !ok).count())
            .unwrap_or(0)
    }

    pub fn enrich_error(
        &self,
        tool_name: &str,
        input: &serde_json::Value,
        error: &str,
    ) -> String {
        let mut parts = vec![format!("ERROR in tool '{}': {}", tool_name, error)];

        match tool_name {
            "read_file" | "grep_file" | "list_directory" => {
                if let Some(path) = input["path"].as_str() {
                    let p = std::path::Path::new(path);
                    if !p.exists() {
                        parts.push(format!("DIAGNOSTIC: '{}' does not exist.", path));
                        parts.push("SUGGESTION: Check the path with list_directory or glob first.".into());
                    } else if let Ok(meta) = std::fs::symlink_metadata(p) {
                        let ft = meta.file_type();
                        if !ft.is_file() && !ft.is_dir() {
                            parts.push(format!(
                                "DIAGNOSTIC: '{}' is a special file (not regular). Use run_command with 'cat' or 'head' instead.",
                                path
                            ));
                        } else {
                            parts.push(format!("DIAGNOSTIC: exists, type={:?}, size={}", ft, meta.len()));
                        }
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            parts.push(format!("PERMISSIONS: {:o}", meta.permissions().mode()));
                        }
                    }
                }
            }
            "run_command" | "command" => {
                if let Some(cmd) = input["command"].as_str() {
                    let first = cmd.split_whitespace().next().unwrap_or("");
                    if !first.is_empty() {
                        if which::which(first).is_err() {
                            parts.push(format!("DIAGNOSTIC: '{}' not found in PATH.", first));
                            parts.push("SUGGESTION: Install it first, or use a different tool.".into());
                        }
                    }
                }
            }
            "web_search" | "github" => {
                if error.contains("timed out") || error.contains("timeout") {
                    parts.push("DIAGNOSTIC: Network request timed out.".into());
                    parts.push("SUGGESTION: Try local alternatives — search_history, read_file, man_page.".into());
                }
            }
            _ => {}
        }

        let consec = self.consecutive_failures(tool_name);
        if consec >= 3 {
            parts.push(format!(
                "WARNING: Tool '{}' has failed {} consecutive times. Use a COMPLETELY different approach.",
                tool_name, consec
            ));
        }

        match tool_name {
            "read_file" if error.contains("timed out") || error.contains("not a regular file") => {
                parts.push("RECOVERY: Try run_command with `head` or `cat` instead.".into());
            }
            "grep_file" if error.contains("timed out") => {
                parts.push("RECOVERY: Try run_command with `grep` instead.".into());
            }
            "web_search" if error.contains("timed out") => {
                parts.push("RECOVERY: Try the github tool, or work with existing context.".into());
            }
            _ => {}
        }

        parts.push(String::new());
        parts.push("IMPORTANT: Do NOT tell the user you have reported this error — you have NOT.".into());
        parts.push("If this seems like a bug in nsh, ask the user to report at: https://github.com/fluffypony/nsh/issues/new".into());
        parts.push("Try an alternative approach (different tool, CLI command, MCP tool, or skill).".into());

        parts.join("\n")
    }
}
