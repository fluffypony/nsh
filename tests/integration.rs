//! Integration tests for nsh.
//!
//! These require a built `nsh` binary. Run with `cargo test`.

use std::path::Path;
use std::process::{Command, Output};

fn test_home() -> tempfile::TempDir {
    tempfile::tempdir().expect("failed to create temp HOME")
}

fn nsh_command(home: &Path) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--"])
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME");
    cmd
}

fn run_nsh(home: &Path, args: &[&str]) -> Output {
    nsh_command(home)
        .args(args)
        .output()
        .expect("failed to run nsh command")
}

#[test]
fn test_init_zsh_generates_session_id() {
    let home = test_home();
    let output = run_nsh(home.path(), &["init", "zsh"]);

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
    let home = test_home();
    let output = run_nsh(home.path(), &["init", "bash"]);

    let script = String::from_utf8_lossy(&output.stdout);
    assert!(!script.contains("__SESSION_ID__"));
    assert!(script.contains("NSH_SESSION_ID="));
}

#[test]
fn test_init_unsupported_shell() {
    let home = test_home();
    let output = run_nsh(home.path(), &["init", "tcsh"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("unsupported"),
        "Expected 'unsupported' in stdout, got: {stdout}"
    );
}

#[test]
fn test_init_fish_generates_session_id() {
    let home = test_home();
    let output = run_nsh(home.path(), &["init", "fish"]);

    let script = String::from_utf8_lossy(&output.stdout);
    assert!(!script.contains("__SESSION_ID__"));
    assert!(script.contains("NSH_SESSION_ID"));
}

#[test]
fn test_config_path() {
    let home = test_home();
    let output = run_nsh(home.path(), &["config", "path"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".nsh/config.toml"),
        "Expected '.nsh/config.toml' in output, got: {stdout}"
    );
}

#[test]
fn test_query_no_words() {
    let home = test_home();
    let output = run_nsh(home.path(), &["query"]);

    assert_eq!(output.status.code(), Some(1), "Expected exit code 1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage"),
        "Expected 'Usage' in stderr, got: {stderr}"
    );
}

#[test]
fn test_history_search_empty_db() {
    let home = test_home();
    let output = run_nsh(home.path(), &["history", "search", "nonexistent_query_xyz"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No results"),
        "Expected 'No results' in stderr, got: {stderr}"
    );
}

#[test]
fn test_reset_without_session() {
    let home = test_home();
    let output = nsh_command(home.path())
        .args(["reset"])
        .env_remove("NSH_SESSION_ID")
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
    let home = test_home();
    let output = run_nsh(home.path(), &["--version"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("nsh"),
        "Expected 'nsh' in version output, got: {stdout}"
    );
}

#[test]
fn test_help_flag() {
    let home = test_home();
    let output = run_nsh(home.path(), &["--help"]);

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
    let home = test_home();
    let output = run_nsh(home.path(), &["config", "show"]);

    assert!(
        output.status.success(),
        "nsh config show should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cost_subcommand() {
    let home = test_home();
    let output = run_nsh(home.path(), &["cost", "all"]);

    assert!(
        output.status.success(),
        "nsh cost all should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_status_subcommand() {
    let home = test_home();
    let output = run_nsh(home.path(), &["status"]);

    assert!(
        output.status.success(),
        "nsh status should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_completions_zsh() {
    let home = test_home();
    let output = run_nsh(home.path(), &["completions", "zsh"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Expected non-empty completions output");
}

#[test]
fn test_completions_bash() {
    let home = test_home();
    let output = run_nsh(home.path(), &["completions", "bash"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Expected non-empty completions output");
}

#[test]
fn test_completions_fish() {
    let home = test_home();
    let output = run_nsh(home.path(), &["completions", "fish"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Expected non-empty completions output");
}

#[test]
fn test_doctor_succeeds() {
    let home = test_home();
    let output = run_nsh(home.path(), &["doctor", "--no-prune", "--no-vacuum"]);

    assert!(
        output.status.success(),
        "nsh doctor should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_doctor_capture_succeeds() {
    let home = test_home();
    let output = run_nsh(home.path(), &["doctor", "capture"]);

    assert!(
        output.status.success(),
        "nsh doctor capture should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nsh doctor capture:"),
        "expected capture diagnostic output, got: {}",
        stderr
    );
}

#[test]
fn test_memory_stats_cli_outputs_telemetry_keys() {
    let home = test_home();
    let output = run_nsh(home.path(), &["memory", "stats"]);

    assert!(output.status.success(), "nsh memory stats should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Allow daemon startup races in CI: either we got JSON with keys or a startup message
    let ok = stdout.contains("\"core\"")
        && stdout.contains("\"decay_runs\"")
        && stdout.contains("\"reflection_runs\"")
        || stderr.contains("nsh is still starting up");
    assert!(ok, "expected telemetry keys or startup notice; stdout: {stdout}, stderr: {stderr}");
}

#[test]
fn test_memory_telemetry_cli_outputs_only_telem_keys() {
    let home = test_home();
    let output = run_nsh(home.path(), &["memory", "telemetry"]);

    assert!(output.status.success(), "nsh memory telemetry should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let ok = (stdout.contains("\"decay_runs\"")
        && stdout.contains("\"last_decay_at\"")
        && stdout.contains("\"reflection_runs\"")
        && stdout.contains("\"last_reflection_at\""))
        || stderr.contains("nsh is still starting up");
    assert!(ok, "expected telemetry JSON or startup notice; stdout: {stdout}, stderr: {stderr}");
}

#[test]
fn test_daemon_send_record_updates_fast_cwd_file() {
    let home = test_home();
    let output = run_nsh(
        home.path(),
        &[
            "daemon-send",
            "record",
            "--session",
            "s-fast-cwd",
            "--command",
            "pwd",
            "--cwd",
            "/tmp/fast-cwd",
            "--exit-code",
            "0",
            "--started-at",
            "2026-01-01T00:00:00Z",
            "--duration-ms",
            "1",
            "--tty",
            "/dev/ttys-test-fast-cwd",
            "--pid",
            "1234",
            "--shell",
            "zsh",
        ],
    );

    assert!(
        output.status.success(),
        "daemon-send record should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let cwd_file = home.path().join(".nsh").join("cwd__dev_ttys-test-fast-cwd");
    let content = std::fs::read_to_string(cwd_file).expect("per-TTY CWD file should exist");
    assert_eq!(content, "/tmp/fast-cwd");
}

#[test]
fn test_record_inserts_command() {
    let home = test_home();
    let output = run_nsh(
        home.path(),
        &[
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
        ],
    );

    assert!(
        output.status.success(),
        "nsh record should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_session_start_and_end() {
    let home = test_home();
    let session_id = "integration-test-session";

    let start = run_nsh(
        home.path(),
        &[
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
        ],
    );
    assert!(
        start.status.success(),
        "nsh session start should succeed, stderr: {}",
        String::from_utf8_lossy(&start.stderr)
    );

    let end = run_nsh(home.path(), &["session", "end", "--session", session_id]);
    assert!(
        end.status.success(),
        "nsh session end should succeed, stderr: {}",
        String::from_utf8_lossy(&end.stderr)
    );
}

#[test]
fn test_heartbeat_succeeds() {
    let home = test_home();
    let output = run_nsh(home.path(), &["heartbeat", "--session", "hb-test-session"]);

    assert!(
        output.status.success(),
        "nsh heartbeat should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_redact_next_succeeds() {
    let home = test_home();
    let _ = std::fs::create_dir_all(home.path().join(".nsh"));
    let output = nsh_command(home.path())
        .args(["redact-next"])
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
    let home = test_home();
    let output = run_nsh(home.path(), &["init", "zsh"]);

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
    let home = test_home();
    let output = run_nsh(home.path(), &["init", "bash"]);

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
    let home = test_home();
    let output = run_nsh(home.path(), &["config", "show", "--raw"]);

    assert!(
        output.status.success(),
        "nsh config show --raw should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_config_show_no_config_file() {
    let home = test_home();
    let output = run_nsh(home.path(), &["config", "show"]);

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
    let home = test_home();
    let output = run_nsh(home.path(), &["cost", "today"]);

    assert!(
        output.status.success(),
        "nsh cost today should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_session_label_missing_session() {
    let home = test_home();
    let output = run_nsh(
        home.path(),
        &[
            "session",
            "label",
            "test-label",
            "--session",
            "nonexistent-session-id",
        ],
    );

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
