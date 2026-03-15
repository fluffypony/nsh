use crate::config::SensitiveFileAccess;
use std::path::{Component, PathBuf};

pub fn validate_read_path(raw_path: &str) -> Result<PathBuf, String> {
    validate_read_path_with_access(raw_path, SensitiveFileAccess::Block)
}

pub fn validate_read_path_tool_outcome(
    raw_path: &str,
    sensitive_file_access: SensitiveFileAccess,
) -> Result<PathBuf, super::outcome::ToolInvocationOutcome> {
    validate_read_path_with_access(raw_path, sensitive_file_access)
        .map_err(super::outcome::ToolInvocationOutcome::failure)
}

pub fn validate_read_path_with_access(
    raw_path: &str,
    sensitive_file_access: SensitiveFileAccess,
) -> Result<PathBuf, String> {
    let expanded = if let Some(rest) = raw_path.strip_prefix("~/") {
        dirs::home_dir().unwrap_or_default().join(rest)
    } else if raw_path == "~" {
        dirs::home_dir().unwrap_or_default()
    } else {
        PathBuf::from(raw_path)
    };

    if expanded
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!(
            "Access denied: path '{raw_path}' contains '..' components"
        ));
    }

    let abs = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir().unwrap_or_default().join(expanded)
    };

    let canonical = match std::fs::canonicalize(&abs) {
        Ok(path) => path,
        Err(_) => {
            if abs.exists() {
                return Err(format!("Access denied: cannot resolve '{raw_path}'"));
            }
            abs
        }
    };

    // Note: TOCTOU race between validation and open is acknowledged but
    // impractical to fix without openat-style path resolution, and is
    // also impractical to abuse or attack.
    if sensitive_file_access != SensitiveFileAccess::Allow
        && let Some(home) = dirs::home_dir()
    {
        // Allowlist: reads under ~/.nsh/skills are considered safe so the agent
        // can introspect installed skills (READ-ONLY). This prevents a deadlock
        // where it cannot answer questions about skills it just installed.
        let allowed_read_only = home.join(".nsh").join("skills");
        let allowed_read_only = allowed_read_only
            .canonicalize()
            .unwrap_or(allowed_read_only);
        if canonical.starts_with(&allowed_read_only) {
            return Ok(canonical);
        }

        let sensitive_dirs = crate::security::sensitive_dirs_read(&home);

        for dir in &sensitive_dirs {
            let dir_canonical = dir.canonicalize().unwrap_or_else(|_| dir.clone());
            if canonical.starts_with(&dir_canonical) {
                if sensitive_file_access == SensitiveFileAccess::Ask {
                    let th = crate::tui::theme::current_theme();
                    eprintln!(
                        "{}⚠ '{raw_path}' is in a sensitive directory{}",
                        th.warning, th.reset
                    );
                    eprint!("{}Allow access? [y/N]{} ", th.warning, th.reset);
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                    if super::tty_prompts::read_tty_confirmation() {
                        break;
                    }
                    return Err(format!(
                        "Access denied: '{raw_path}' is in a sensitive directory"
                    ));
                }
                return Err(format!(
                    "Access denied: '{raw_path}' is in a sensitive directory"
                ));
            }
        }
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::{validate_read_path, validate_read_path_tool_outcome, validate_read_path_with_access};
    use crate::config::SensitiveFileAccess;
    use crate::test_support::EnvVarGuard;
    use serial_test::serial;

    fn temp_home_env() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().unwrap();
        let home_guard = EnvVarGuard::set("HOME", home.path());
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        (home, home_guard, xdg_config_guard, xdg_data_guard)
    }

    #[test]
    fn validate_read_path_rejects_parent_segments() {
        let err = validate_read_path("../secret").unwrap_err();
        assert!(err.contains("contains '..'"));
    }

    #[test]
    #[serial]
    fn validate_read_path_with_access_allows_nsh_skills_directory() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();
        let skills_dir = home.path().join(".nsh").join("skills");
        let skill_file = skills_dir.join("demo").join("SKILL.md");
        std::fs::create_dir_all(skill_file.parent().unwrap()).unwrap();
        std::fs::write(&skill_file, "demo").unwrap();

        let resolved =
            validate_read_path_with_access(skill_file.to_str().unwrap(), SensitiveFileAccess::Block)
                .unwrap();

        assert_eq!(resolved, std::fs::canonicalize(skill_file).unwrap());
    }

    #[test]
    fn validate_read_path_tool_outcome_wraps_denials() {
        let outcome =
            validate_read_path_tool_outcome("../secret", SensitiveFileAccess::Block).unwrap_err();

        assert_eq!(
            outcome.into_content(),
            "Access denied: path '../secret' contains '..' components"
        );
    }
}
