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

    assert_eq!(
        output.status.code(),
        Some(1),
        "Expected exit code 1"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage"),
        "Expected 'Usage' in stderr, got: {stderr}"
    );
}

#[test]
fn test_history_search_empty_db() {
    let output = std::process::Command::new("cargo")
        .args([
            "run", "--", "history", "search", "nonexistent_query_xyz",
        ])
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
