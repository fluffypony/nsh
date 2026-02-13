//! Integration tests for nsh.
//!
//! These require a built `nsh` binary. Run with `cargo test`.

#[test]
fn test_init_zsh_generates_session_id() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "init", "zsh"])
        .output()
        .expect("failed to run nsh init zsh");

    let script = String::from_utf8_lossy(&output.stdout);
    // Should NOT contain the placeholder
    assert!(
        !script.contains("__SESSION_ID__"),
        "Session ID placeholder was not replaced"
    );
    // Should contain a UUID-shaped string after NSH_SESSION_ID=
    assert!(
        script.contains("NSH_SESSION_ID="),
        "Missing NSH_SESSION_ID export"
    );
}

#[test]
fn test_init_bash_generates_session_id() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "init", "bash"])
        .output()
        .expect("failed to run nsh init bash");

    let script = String::from_utf8_lossy(&output.stdout);
    assert!(!script.contains("__SESSION_ID__"));
    assert!(script.contains("NSH_SESSION_ID="));
}

#[test]
fn test_init_unsupported_shell() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "init", "tcsh"])
        .output()
        .expect("failed to run nsh init tcsh");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("unsupported"),
        "Expected 'unsupported' in stdout, got: {stdout}"
    );
}

#[test]
fn test_init_fish_generates_session_id() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "init", "fish"])
        .output()
        .expect("failed to run nsh init fish");

    let script = String::from_utf8_lossy(&output.stdout);
    assert!(!script.contains("__SESSION_ID__"));
    assert!(script.contains("NSH_SESSION_ID"));
}

#[test]
fn test_config_path() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "config", "path"])
        .output()
        .expect("failed to run nsh config path");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".nsh/config.toml"),
        "Expected '.nsh/config.toml' in output, got: {stdout}"
    );
}

#[test]
fn test_query_no_words() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "query"])
        .output()
        .expect("failed to run nsh query");

    assert_eq!(output.status.code(), Some(1), "Expected exit code 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage"),
        "Expected 'Usage' in stderr, got: {stderr}"
    );
}

#[test]
fn test_history_search_empty_db() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "history", "search", "nonexistent_query_xyz"])
        .env("HOME", std::env::temp_dir().join("nsh_test_history"))
        .output()
        .expect("failed to run nsh history search");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No results"),
        "Expected 'No results' in stderr, got: {stderr}"
    );
}

#[test]
fn test_reset_without_session() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "reset"])
        .env_remove("NSH_SESSION_ID")
        .env("HOME", std::env::temp_dir().join("nsh_test_reset"))
        .output()
        .expect("failed to run nsh reset");

    assert!(
        output.status.success(),
        "nsh reset should not panic without NSH_SESSION_ID"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("conversation context cleared"),
        "Expected confirmation message, got: {stderr}"
    );
}

#[test]
fn test_version_flag() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "--version"])
        .output()
        .expect("failed to run nsh --version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("nsh"),
        "Expected 'nsh' in version output, got: {stdout}"
    );
}

#[test]
fn test_help_flag() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("failed to run nsh --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage"),
        "Expected 'Usage' in help output, got: {stdout}"
    );
    assert!(
        stdout.contains("Natural Shell"),
        "Expected 'Natural Shell' in help output, got: {stdout}"
    );
}

#[test]
fn test_config_show() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "config", "show"])
        .output()
        .expect("failed to run nsh config show");

    assert!(
        output.status.success(),
        "nsh config show should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cost_subcommand() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "cost", "all"])
        .output()
        .expect("failed to run nsh cost");

    assert!(
        output.status.success(),
        "nsh cost all should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_status_subcommand() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "status"])
        .output()
        .expect("failed to run nsh status");

    assert!(
        output.status.success(),
        "nsh status should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_completions_zsh() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "completions", "zsh"])
        .output()
        .expect("failed to run nsh completions zsh");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Expected non-empty completions output");
}

#[test]
fn test_completions_bash() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "completions", "bash"])
        .output()
        .expect("failed to run nsh completions bash");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Expected non-empty completions output");
}

#[test]
fn test_completions_fish() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "completions", "fish"])
        .output()
        .expect("failed to run nsh completions fish");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Expected non-empty completions output");
}

#[test]
fn test_doctor_succeeds() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "doctor", "--no-prune", "--no-vacuum"])
        .output()
        .expect("failed to run nsh doctor");

    assert!(
        output.status.success(),
        "nsh doctor should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_record_inserts_command() {
    let tmp = std::env::temp_dir().join("nsh_test_record");
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--",
            "record",
            "--session",
            "test-integration-rec",
            "--command",
            "echo hello",
            "--cwd",
            "/tmp",
            "--exit-code",
            "0",
            "--started-at",
            "2025-01-01T00:00:00Z",
            "--duration-ms",
            "10",
            "--tty",
            "/dev/ttys000",
            "--pid",
            "1234",
            "--shell",
            "zsh",
        ])
        .env("HOME", &tmp)
        .output()
        .expect("failed to run nsh record");

    assert!(
        output.status.success(),
        "nsh record should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_session_start_and_end() {
    let tmp = std::env::temp_dir().join("nsh_test_session");
    let session_id = "integration-test-session";

    let start = std::process::Command::new("cargo")
        .args([
            "run",
            "--",
            "session",
            "start",
            "--session",
            session_id,
            "--tty",
            "/dev/ttys000",
            "--shell",
            "zsh",
            "--pid",
            "9999",
        ])
        .env("HOME", &tmp)
        .output()
        .expect("failed to run nsh session start");
    assert!(
        start.status.success(),
        "nsh session start should succeed, stderr: {}",
        String::from_utf8_lossy(&start.stderr)
    );

    let end = std::process::Command::new("cargo")
        .args(["run", "--", "session", "end", "--session", session_id])
        .env("HOME", &tmp)
        .output()
        .expect("failed to run nsh session end");
    assert!(
        end.status.success(),
        "nsh session end should succeed, stderr: {}",
        String::from_utf8_lossy(&end.stderr)
    );
}

#[test]
fn test_heartbeat_succeeds() {
    let tmp = std::env::temp_dir().join("nsh_test_heartbeat");
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "heartbeat", "--session", "hb-test-session"])
        .env("HOME", &tmp)
        .output()
        .expect("failed to run nsh heartbeat");

    assert!(
        output.status.success(),
        "nsh heartbeat should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_redact_next_succeeds() {
    let tmp = std::env::temp_dir().join("nsh_test_redact");
    let _ = std::fs::create_dir_all(tmp.join(".nsh"));
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "redact-next"])
        .env("HOME", &tmp)
        .env("NSH_SESSION_ID", "redact-test")
        .output()
        .expect("failed to run nsh redact-next");

    assert!(
        output.status.success(),
        "nsh redact-next should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("next command output will not be captured"),
        "Expected confirmation message, got: {stderr}"
    );
}

#[test]
fn test_init_zsh_contains_hooks() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "init", "zsh"])
        .output()
        .expect("failed to run nsh init zsh");

    let script = String::from_utf8_lossy(&output.stdout);
    assert!(
        script.contains("precmd") || script.contains("preexec"),
        "zsh init should contain shell hooks, got: {script}"
    );
    assert!(
        script.contains("nsh record")
            || script.contains("nsh session")
            || script.contains("nsh heartbeat"),
        "zsh init should reference nsh subcommands, got: {script}"
    );
}

#[test]
fn test_init_bash_contains_hooks() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "init", "bash"])
        .output()
        .expect("failed to run nsh init bash");

    let script = String::from_utf8_lossy(&output.stdout);
    assert!(
        script.contains("PROMPT_COMMAND") || script.contains("trap") || script.contains("DEBUG"),
        "bash init should contain shell hooks, got: {script}"
    );
    assert!(
        script.contains("nsh record")
            || script.contains("nsh session")
            || script.contains("nsh heartbeat"),
        "bash init should reference nsh subcommands, got: {script}"
    );
}

#[test]
fn test_config_show_raw() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "config", "show", "--raw"])
        .output()
        .expect("failed to run nsh config show --raw");

    assert!(
        output.status.success(),
        "nsh config show --raw should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_config_show_no_config_file() {
    let tmp = std::env::temp_dir().join("nsh_test_config_show_nofile");
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "config", "show"])
        .env("HOME", &tmp)
        .output()
        .expect("failed to run nsh config show");

    assert!(
        output.status.success(),
        "nsh config show should succeed even with no config, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No config file") || stderr.contains("defaults"),
        "Expected missing config message, got: {stderr}"
    );
}

#[test]
fn test_cost_today() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", "cost", "today"])
        .output()
        .expect("failed to run nsh cost today");

    assert!(
        output.status.success(),
        "nsh cost today should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_session_label_missing_session() {
    let tmp = std::env::temp_dir().join("nsh_test_session_label");
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--",
            "session",
            "label",
            "test-label",
            "--session",
            "nonexistent-session-id",
        ])
        .env("HOME", &tmp)
        .output()
        .expect("failed to run nsh session label");

    assert!(
        output.status.success(),
        "nsh session label should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found"),
        "Expected 'not found' for missing session, got: {stderr}"
    );
}
