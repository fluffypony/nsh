use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub const DAEMON_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonRequest {
    Record {
        session: String,
        command: String,
        cwd: String,
        exit_code: i32,
        started_at: String,
        #[serde(default)]
        tty: String,
        #[serde(default)]
        pid: i32,
        #[serde(default)]
        shell: String,
        #[serde(default)]
        duration_ms: Option<i64>,
        #[serde(default)]
        output: Option<String>,
    },
    Heartbeat {
        session: String,
    },
    CaptureMark {
        session: String,
    },
    CaptureRead {
        session: String,
        #[serde(default = "default_max_lines")]
        max_lines: usize,
    },
    Scrollback {
        #[serde(default = "default_max_lines")]
        max_lines: usize,
    },
    Context {
        session: String,
    },
    Status,
    McpToolCall {
        tool: String,
        input: serde_json::Value,
    },
    SummarizeCheck {
        session: String,
    },
}

fn default_max_lines() -> usize {
    1000
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DaemonResponse {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    Error {
        message: String,
    },
}

impl DaemonResponse {
    pub fn ok() -> Self {
        Self::Ok { data: None }
    }

    pub fn ok_with_data(data: serde_json::Value) -> Self {
        Self::Ok { data: Some(data) }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error {
            message: msg.into(),
        }
    }
}

pub fn handle_daemon_request(
    request: DaemonRequest,
    capture: &Mutex<crate::pump::CaptureEngine>,
    db_tx: &std::sync::mpsc::Sender<DbCommand>,
    max_output_bytes: usize,
) -> DaemonResponse {
    match request {
        DaemonRequest::Record {
            session,
            command,
            cwd,
            exit_code,
            started_at,
            tty,
            pid,
            shell,
            duration_ms,
            output,
        } => {
            let captured = capture
                .lock()
                .ok()
                .and_then(|mut eng| eng.capture_since_mark(max_output_bytes));
            let final_output = output.or(captured);
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            let cmd = DbCommand::Record {
                session,
                command,
                cwd,
                exit_code,
                started_at,
                tty,
                pid,
                shell,
                duration_ms,
                output: final_output,
                reply: reply_tx,
            };
            if db_tx.send(cmd).is_err() {
                return DaemonResponse::error("DB thread unavailable");
            }
            match reply_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Ok(id)) => DaemonResponse::ok_with_data(serde_json::json!({"id": id})),
                Ok(Err(e)) => DaemonResponse::error(format!("{e}")),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    DaemonResponse::error("DB timeout")
                }
                Err(_) => DaemonResponse::error("DB thread hung up"),
            }
        }

        DaemonRequest::Heartbeat { session } => {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            let cmd = DbCommand::Heartbeat {
                session,
                reply: reply_tx,
            };
            if db_tx.send(cmd).is_err() {
                return DaemonResponse::error("DB thread unavailable");
            }
            let _ = db_tx.send(DbCommand::GenerateSummaries);
            match reply_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Ok(())) => DaemonResponse::ok(),
                Ok(Err(e)) => DaemonResponse::error(format!("{e}")),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    DaemonResponse::error("DB timeout")
                }
                Err(_) => DaemonResponse::error("DB thread hung up"),
            }
        }

        DaemonRequest::Scrollback { max_lines } => match capture.lock() {
            Ok(eng) => {
                let text = eng.get_lines(max_lines);
                DaemonResponse::ok_with_data(serde_json::json!({"scrollback": text}))
            }
            Err(_) => DaemonResponse::error("capture lock poisoned"),
        },

        DaemonRequest::CaptureMark { .. } => match capture.lock() {
            Ok(mut eng) => {
                eng.mark();
                DaemonResponse::ok()
            }
            Err(_) => DaemonResponse::error("capture lock poisoned"),
        },

        DaemonRequest::CaptureRead { max_lines, .. } => match capture.lock() {
            Ok(mut eng) => {
                let text = eng.capture_since_mark(max_output_bytes).unwrap_or_default();
                let lines: Vec<&str> = text.lines().collect();
                let start = lines.len().saturating_sub(max_lines);
                let result = lines[start..].join("\n");
                DaemonResponse::ok_with_data(serde_json::json!({"output": result}))
            }
            Err(_) => DaemonResponse::error("capture lock poisoned"),
        },

        DaemonRequest::Status => DaemonResponse::ok_with_data(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
        })),

        DaemonRequest::SummarizeCheck { .. } => {
            let _ = db_tx.send(DbCommand::GenerateSummaries);
            DaemonResponse::ok()
        }

        DaemonRequest::Context { .. } | DaemonRequest::McpToolCall { .. } => {
            DaemonResponse::error("not yet implemented")
        }
    }
}

pub enum DbCommand {
    Record {
        session: String,
        command: String,
        cwd: String,
        exit_code: i32,
        started_at: String,
        tty: String,
        pid: i32,
        shell: String,
        duration_ms: Option<i64>,
        output: Option<String>,
        reply: std::sync::mpsc::Sender<anyhow::Result<i64>>,
    },
    Heartbeat {
        session: String,
        reply: std::sync::mpsc::Sender<anyhow::Result<()>>,
    },
    #[allow(dead_code)]
    InsertConversation {
        session_id: String,
        query: String,
        response_type: String,
        response: String,
        explanation: Option<String>,
        executed: bool,
        pending: bool,
        reply: std::sync::mpsc::Sender<anyhow::Result<i64>>,
    },
    #[allow(dead_code)]
    SearchHistory {
        query: String,
        limit: usize,
        reply: std::sync::mpsc::Sender<anyhow::Result<Vec<crate::db::HistoryMatch>>>,
    },
    GenerateSummaries,
    Shutdown,
}

pub fn run_db_thread(rx: std::sync::mpsc::Receiver<DbCommand>) {
    let db = match crate::db::Db::open() {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("daemon: failed to open DB: {e}");
            return;
        }
    };

    while let Ok(cmd) = rx.recv() {
        match cmd {
            DbCommand::Record {
                session,
                command,
                cwd,
                exit_code,
                started_at,
                tty,
                pid,
                shell,
                duration_ms,
                output,
                reply,
            } => {
                let cmd_text = command.clone();
                let ec = exit_code;
                let out = output.clone();

                let result = db.insert_command(
                    &session,
                    &command,
                    &cwd,
                    Some(exit_code),
                    &started_at,
                    duration_ms,
                    output.as_deref(),
                    &tty,
                    &shell,
                    pid,
                );
                if let Ok(id) = &result {
                    let output_text = out.as_deref().unwrap_or("");
                    if let Some(trivial) =
                        crate::summary::trivial_summary(&cmd_text, ec, output_text)
                    {
                        let _ = db.update_summary(*id, &trivial);
                    }
                    // Conversation feedback loop: if this command matches
                    // a pending conversation suggestion, record the result
                    if let Ok(Some((conv_id, suggested_cmd))) =
                        db.find_pending_conversation(&session)
                    {
                        if cmd_text.trim() == suggested_cmd.trim() {
                            let snippet = crate::util::truncate(output_text, 500);
                            let snippet_ref = if snippet.is_empty() {
                                None
                            } else {
                                Some(snippet.as_str())
                            };
                            let _ = db.update_conversation_result(conv_id, ec, snippet_ref);
                        }
                    }
                }
                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
            }

            DbCommand::Heartbeat { session, reply } => {
                let result = db.update_heartbeat(&session);
                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
            }

            DbCommand::InsertConversation {
                session_id,
                query,
                response_type,
                response,
                explanation,
                executed,
                pending,
                reply,
            } => {
                let result = db.insert_conversation(
                    &session_id,
                    &query,
                    &response_type,
                    &response,
                    explanation.as_deref(),
                    executed,
                    pending,
                );
                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
            }

            DbCommand::SearchHistory {
                query,
                limit,
                reply,
            } => {
                let result = db.search_history(&query, limit);
                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
            }

            DbCommand::GenerateSummaries => {
                generate_summaries_sync(&db);
            }

            DbCommand::Shutdown => break,
        }
    }
}

fn generate_summaries_sync(db: &crate::db::Db) {
    let commands = match db.commands_needing_summary(5) {
        Ok(cmds) => cmds,
        Err(e) => {
            tracing::debug!("daemon: failed to fetch commands for summary: {e}");
            return;
        }
    };

    for cmd in &commands {
        let output = cmd.output.as_deref().unwrap_or("");
        if let Some(trivial) =
            crate::summary::trivial_summary(&cmd.command, cmd.exit_code.unwrap_or(-1), output)
        {
            let _ = db.update_summary(cmd.id, &trivial);
        }
    }

    let _ = db.mark_unsummarized_for_llm();
}

pub fn daemon_socket_path(session_id: &str) -> std::path::PathBuf {
    crate::config::Config::nsh_dir().join(format!("daemon_{session_id}.sock"))
}

pub fn daemon_pid_path(session_id: &str) -> std::path::PathBuf {
    crate::config::Config::nsh_dir().join(format!("daemon_{session_id}.pid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_protocol_version() {
        assert!(DAEMON_PROTOCOL_VERSION >= 1);
    }

    #[test]
    fn test_default_max_lines() {
        assert_eq!(default_max_lines(), 1000);
    }

    #[test]
    fn test_daemon_request_record_serde() {
        let req = DaemonRequest::Record {
            session: "s1".into(),
            command: "ls".into(),
            cwd: "/tmp".into(),
            exit_code: 0,
            started_at: "2025-01-01T00:00:00Z".into(),
            tty: "/dev/pts/0".into(),
            pid: 1234,
            shell: "zsh".into(),
            duration_ms: Some(100),
            output: Some("output".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::Record {
            session,
            command,
            cwd,
            exit_code,
            started_at,
            tty,
            pid,
            shell,
            duration_ms,
            output,
        } = parsed
        {
            assert_eq!(session, "s1");
            assert_eq!(command, "ls");
            assert_eq!(cwd, "/tmp");
            assert_eq!(exit_code, 0);
            assert_eq!(started_at, "2025-01-01T00:00:00Z");
            assert_eq!(tty, "/dev/pts/0");
            assert_eq!(pid, 1234);
            assert_eq!(shell, "zsh");
            assert_eq!(duration_ms, Some(100));
            assert_eq!(output, Some("output".into()));
        } else {
            panic!("expected Record variant");
        }
    }

    #[test]
    fn test_daemon_request_heartbeat_serde() {
        let req = DaemonRequest::Heartbeat {
            session: "s1".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::Heartbeat { session } = parsed {
            assert_eq!(session, "s1");
        } else {
            panic!("expected Heartbeat variant");
        }
    }

    #[test]
    fn test_daemon_request_capture_mark_serde() {
        let req = DaemonRequest::CaptureMark {
            session: "s1".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::CaptureMark { session } = parsed {
            assert_eq!(session, "s1");
        } else {
            panic!("expected CaptureMark variant");
        }
    }

    #[test]
    fn test_daemon_request_capture_read_serde() {
        let req = DaemonRequest::CaptureRead {
            session: "s1".into(),
            max_lines: 500,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::CaptureRead {
            session,
            max_lines,
        } = parsed
        {
            assert_eq!(session, "s1");
            assert_eq!(max_lines, 500);
        } else {
            panic!("expected CaptureRead variant");
        }
    }

    #[test]
    fn test_daemon_request_scrollback_serde() {
        let req = DaemonRequest::Scrollback { max_lines: 200 };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::Scrollback { max_lines } = parsed {
            assert_eq!(max_lines, 200);
        } else {
            panic!("expected Scrollback variant");
        }
    }

    #[test]
    fn test_daemon_request_context_serde() {
        let req = DaemonRequest::Context {
            session: "s1".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::Context { session } = parsed {
            assert_eq!(session, "s1");
        } else {
            panic!("expected Context variant");
        }
    }

    #[test]
    fn test_daemon_request_status_serde() {
        let req = DaemonRequest::Status;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, DaemonRequest::Status));
    }

    #[test]
    fn test_daemon_request_mcp_tool_call_serde() {
        let req = DaemonRequest::McpToolCall {
            tool: "grep".into(),
            input: serde_json::json!({"pattern": "foo"}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::McpToolCall { tool, input } = parsed {
            assert_eq!(tool, "grep");
            assert_eq!(input, serde_json::json!({"pattern": "foo"}));
        } else {
            panic!("expected McpToolCall variant");
        }
    }

    #[test]
    fn test_daemon_request_summarize_check_serde() {
        let req = DaemonRequest::SummarizeCheck {
            session: "s1".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::SummarizeCheck { session } = parsed {
            assert_eq!(session, "s1");
        } else {
            panic!("expected SummarizeCheck variant");
        }
    }

    #[test]
    fn test_daemon_request_record_defaults() {
        let json = r#"{"type":"record","session":"s1","command":"ls","cwd":"/tmp","exit_code":0,"started_at":"2025-01-01T00:00:00Z"}"#;
        let req: DaemonRequest = serde_json::from_str(json).unwrap();
        if let DaemonRequest::Record {
            tty,
            pid,
            shell,
            duration_ms,
            output,
            ..
        } = req
        {
            assert_eq!(tty, "");
            assert_eq!(pid, 0);
            assert_eq!(shell, "");
            assert!(duration_ms.is_none());
            assert!(output.is_none());
        } else {
            panic!("expected Record variant");
        }
    }

    #[test]
    fn test_daemon_request_capture_read_default_max_lines() {
        let json = r#"{"type":"capture_read","session":"s1"}"#;
        let req: DaemonRequest = serde_json::from_str(json).unwrap();
        if let DaemonRequest::CaptureRead { max_lines, .. } = req {
            assert_eq!(max_lines, 1000);
        } else {
            panic!("expected CaptureRead variant");
        }
    }

    #[test]
    fn test_daemon_request_scrollback_default_max_lines() {
        let json = r#"{"type":"scrollback"}"#;
        let req: DaemonRequest = serde_json::from_str(json).unwrap();
        if let DaemonRequest::Scrollback { max_lines } = req {
            assert_eq!(max_lines, 1000);
        } else {
            panic!("expected Scrollback variant");
        }
    }

    #[test]
    fn test_daemon_response_ok() {
        let resp = DaemonResponse::ok();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(!json.contains("\"data\""));
    }

    #[test]
    fn test_daemon_response_ok_with_data() {
        let resp = DaemonResponse::ok_with_data(serde_json::json!({"key": "value"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"key\":\"value\""));
    }

    #[test]
    fn test_daemon_response_error() {
        let resp = DaemonResponse::error("something failed");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"status\":\"error\""));
        assert!(json.contains("something failed"));
    }

    #[test]
    fn test_daemon_response_ok_roundtrip() {
        let resp = DaemonResponse::ok();
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, DaemonResponse::Ok { data: None }));
    }

    #[test]
    fn test_daemon_response_error_roundtrip() {
        let resp = DaemonResponse::error("bad");
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        if let DaemonResponse::Error { message } = parsed {
            assert_eq!(message, "bad");
        } else {
            panic!("expected Error variant");
        }
    }

    #[test]
    fn test_daemon_socket_path() {
        let path = daemon_socket_path("test-session");
        assert!(path.to_str().unwrap().contains("daemon_test-session.sock"));
    }

    #[test]
    fn test_daemon_pid_path() {
        let path = daemon_pid_path("test-session");
        assert!(path.to_str().unwrap().contains("daemon_test-session.pid"));
    }

    #[test]
    fn test_generate_summaries_sync_empty_db() {
        let db = crate::db::Db::open_in_memory().unwrap();
        generate_summaries_sync(&db);
    }

    #[test]
    fn test_generate_summaries_sync_with_command() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db.insert_command(
            "s1",
            "echo hello",
            "/tmp",
            Some(0),
            "2025-01-01T00:00:00Z",
            None,
            Some("hello"),
            "/dev/pts/0",
            "zsh",
            1234,
        )
        .unwrap();
        generate_summaries_sync(&db);
    }

    #[test]
    fn test_handle_status_request() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(DaemonRequest::Status, &capture, &db_tx, 65536);
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                assert!(d["version"].is_string());
                assert!(d["pid"].is_number());
            }
            _ => panic!("expected Ok with data"),
        }
    }

    #[test]
    fn test_handle_scrollback_request() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        {
            let mut eng = capture.lock().unwrap();
            eng.process(b"hello world\r\n");
        }
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::Scrollback { max_lines: 100 },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                assert!(d["scrollback"].is_string());
            }
            _ => panic!("expected Ok with scrollback data"),
        }
    }

    #[test]
    fn test_handle_capture_mark_request() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::CaptureMark { session: "s1".into() },
            &capture,
            &db_tx,
            65536,
        );
        assert!(matches!(resp, DaemonResponse::Ok { data: None }));
    }

    #[test]
    fn test_handle_capture_read_request() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        {
            let mut eng = capture.lock().unwrap();
            eng.mark();
            eng.process(b"captured output\r\n");
        }
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::CaptureRead { session: "s1".into(), max_lines: 100 },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                assert!(d["output"].is_string());
            }
            _ => panic!("expected Ok with output data"),
        }
    }

    #[test]
    fn test_handle_summarize_check_request() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::SummarizeCheck { session: "s1".into() },
            &capture,
            &db_tx,
            65536,
        );
        assert!(matches!(resp, DaemonResponse::Ok { data: None }));
    }

    #[test]
    fn test_handle_context_not_implemented() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::Context { session: "s1".into() },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("not yet implemented"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_handle_mcp_tool_call_not_implemented() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::McpToolCall { tool: "test".into(), input: serde_json::json!({}) },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("not yet implemented"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_handle_record_db_unavailable() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, db_rx) = std::sync::mpsc::channel::<DbCommand>();
        drop(db_rx);
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "s1".into(),
                command: "ls".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2025-01-01T00:00:00Z".into(),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: None,
            },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("DB thread unavailable"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_handle_heartbeat_db_unavailable() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, db_rx) = std::sync::mpsc::channel::<DbCommand>();
        drop(db_rx);
        let resp = handle_daemon_request(
            DaemonRequest::Heartbeat { session: "s1".into() },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("DB thread unavailable"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_daemon_request_record_roundtrip_minimal() {
        let json_str = r#"{"type":"record","session":"abc","command":"pwd","cwd":"/home","exit_code":1,"started_at":"2025-06-01T12:00:00Z"}"#;
        let req: DaemonRequest = serde_json::from_str(json_str).unwrap();
        let re_json = serde_json::to_string(&req).unwrap();
        let re_parsed: DaemonRequest = serde_json::from_str(&re_json).unwrap();
        if let DaemonRequest::Record { session, command, exit_code, duration_ms, output, .. } = re_parsed {
            assert_eq!(session, "abc");
            assert_eq!(command, "pwd");
            assert_eq!(exit_code, 1);
            assert!(duration_ms.is_none());
            assert!(output.is_none());
        } else {
            panic!("expected Record");
        }
    }

    #[test]
    fn test_daemon_request_mcp_tool_call_complex_input() {
        let req = DaemonRequest::McpToolCall {
            tool: "file_search".into(),
            input: serde_json::json!({"paths": ["/a", "/b"], "recursive": true, "depth": 5}),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::McpToolCall { tool, input } = parsed {
            assert_eq!(tool, "file_search");
            assert_eq!(input["paths"][0], "/a");
            assert_eq!(input["recursive"], true);
            assert_eq!(input["depth"], 5);
        } else {
            panic!("expected McpToolCall");
        }
    }

    #[test]
    fn test_daemon_request_capture_read_custom_max_lines() {
        let json_str = r#"{"type":"capture_read","session":"s2","max_lines":42}"#;
        let req: DaemonRequest = serde_json::from_str(json_str).unwrap();
        if let DaemonRequest::CaptureRead { session, max_lines } = req {
            assert_eq!(session, "s2");
            assert_eq!(max_lines, 42);
        } else {
            panic!("expected CaptureRead");
        }
    }

    #[test]
    fn test_daemon_request_all_variants_tag_values() {
        let variants = vec![
            (r#"{"type":"heartbeat","session":"s"}"#, "heartbeat"),
            (r#"{"type":"capture_mark","session":"s"}"#, "capture_mark"),
            (r#"{"type":"capture_read","session":"s"}"#, "capture_read"),
            (r#"{"type":"scrollback"}"#, "scrollback"),
            (r#"{"type":"context","session":"s"}"#, "context"),
            (r#"{"type":"status"}"#, "status"),
            (r#"{"type":"mcp_tool_call","tool":"t","input":{}}"#, "mcp_tool_call"),
            (r#"{"type":"summarize_check","session":"s"}"#, "summarize_check"),
        ];
        for (json_str, tag) in variants {
            let req: DaemonRequest = serde_json::from_str(json_str).unwrap();
            let serialized = serde_json::to_string(&req).unwrap();
            assert!(serialized.contains(&format!("\"type\":\"{tag}\"")), "tag mismatch for {tag}");
        }
    }

    #[test]
    fn test_daemon_response_ok_with_data_roundtrip() {
        let resp = DaemonResponse::ok_with_data(serde_json::json!({"list": [1, 2, 3], "nested": {"a": true}}));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        if let DaemonResponse::Ok { data: Some(d) } = parsed {
            assert_eq!(d["list"][1], 2);
            assert_eq!(d["nested"]["a"], true);
        } else {
            panic!("expected Ok with data");
        }
    }

    #[test]
    fn test_default_max_lines_value() {
        assert_eq!(default_max_lines(), 1000);
        let json_str = r#"{"type":"scrollback"}"#;
        let req: DaemonRequest = serde_json::from_str(json_str).unwrap();
        if let DaemonRequest::Scrollback { max_lines } = req {
            assert_eq!(max_lines, default_max_lines());
        } else {
            panic!("expected Scrollback");
        }
    }

    #[test]
    fn test_daemon_socket_path_format() {
        let path = daemon_socket_path("abc123");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "daemon_abc123.sock");
    }

    #[test]
    fn test_daemon_pid_path_format() {
        let path = daemon_pid_path("xyz789");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "daemon_xyz789.pid");
    }

    #[test]
    fn test_daemon_request_record_full_roundtrip() {
        let json_str = r#"{
            "type": "record",
            "session": "s1",
            "command": "ls -la",
            "cwd": "/home/user",
            "exit_code": 42,
            "started_at": "2025-06-01T12:00:00Z",
            "tty": "/dev/pts/5",
            "pid": 9999,
            "shell": "fish",
            "duration_ms": 1500,
            "output": "file1\nfile2"
        }"#;
        let req: DaemonRequest = serde_json::from_str(json_str).unwrap();
        let json = serde_json::to_string(&req).unwrap();
        let re: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::Record { session, command, cwd, exit_code, tty, pid, shell, duration_ms, output, .. } = re {
            assert_eq!(session, "s1");
            assert_eq!(command, "ls -la");
            assert_eq!(cwd, "/home/user");
            assert_eq!(exit_code, 42);
            assert_eq!(tty, "/dev/pts/5");
            assert_eq!(pid, 9999);
            assert_eq!(shell, "fish");
            assert_eq!(duration_ms, Some(1500));
            assert_eq!(output.as_deref(), Some("file1\nfile2"));
        } else {
            panic!("expected Record");
        }
    }

    #[test]
    fn test_daemon_request_summarize_check_roundtrip() {
        let req = DaemonRequest::SummarizeCheck { session: "sess42".into() };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::SummarizeCheck { session } = parsed {
            assert_eq!(session, "sess42");
        } else {
            panic!("expected SummarizeCheck");
        }
    }

    #[test]
    fn test_handle_record_with_real_db_thread() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || run_db_thread(rx));

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "test_real_db".into(),
                command: "echo hello".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2025-06-01T00:00:00Z".into(),
                tty: "/dev/pts/0".into(),
                pid: 1234,
                shell: "zsh".into(),
                duration_ms: Some(50),
                output: Some("hello".into()),
            },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                assert!(d["id"].is_number());
            }
            DaemonResponse::Error { message } => {
                panic!("unexpected error: {message}");
            }
            _ => panic!("expected Ok with id"),
        }

        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_handle_heartbeat_with_real_db_thread() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || run_db_thread(rx));

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Heartbeat { session: "test_hb_sess".into() },
            &capture,
            &tx,
            65536,
        );
        assert!(matches!(resp, DaemonResponse::Ok { data: None }));

        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_handle_record_db_error_reply() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            while let Ok(cmd) = rx.recv() {
                match cmd {
                    DbCommand::Record { reply, .. } => {
                        let _ = reply.send(Err(anyhow::anyhow!("simulated error")));
                    }
                    DbCommand::Shutdown => break,
                    _ => {}
                }
            }
        });

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "s1".into(),
                command: "fail".into(),
                cwd: "/tmp".into(),
                exit_code: 1,
                started_at: "2025-01-01T00:00:00Z".into(),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: None,
            },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("simulated error"));
            }
            _ => panic!("expected Error"),
        }
        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_handle_heartbeat_db_error_reply() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            while let Ok(cmd) = rx.recv() {
                match cmd {
                    DbCommand::Heartbeat { reply, .. } => {
                        let _ = reply.send(Err(anyhow::anyhow!("heartbeat fail")));
                    }
                    DbCommand::Shutdown => break,
                    _ => {}
                }
            }
        });

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Heartbeat { session: "s1".into() },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("heartbeat fail"));
            }
            _ => panic!("expected Error"),
        }
        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_handle_record_db_thread_hung_up() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            if let Ok(cmd) = rx.recv() {
                match cmd {
                    DbCommand::Record { reply, .. } => {
                        drop(reply);
                    }
                    _ => {}
                }
            }
        });

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "s1".into(),
                command: "test".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2025-01-01T00:00:00Z".into(),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: None,
            },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("hung up") || message.contains("timeout"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_db_command_generate_summaries_via_real_thread() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || run_db_thread(rx));

        let _ = tx.send(DbCommand::GenerateSummaries);

        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::SearchHistory {
            query: "nonexistent_test_xyz".into(),
            limit: 5,
            reply: reply_tx,
        });
        let result = reply_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_db_command_insert_conversation_via_real_thread() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || run_db_thread(rx));

        let (rec_tx, rec_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::Record {
            session: "conv_test_sess".into(),
            command: "echo setup".into(),
            cwd: "/tmp".into(),
            exit_code: 0,
            started_at: "2025-06-01T00:00:00Z".into(),
            tty: "".into(),
            pid: 0,
            shell: "".into(),
            duration_ms: None,
            output: None,
            reply: rec_tx,
        });
        let _ = rec_rx.recv_timeout(std::time::Duration::from_secs(2));

        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::InsertConversation {
            session_id: "conv_test_sess".into(),
            query: "what is rust".into(),
            response_type: "chat".into(),
            response: "A systems language".into(),
            explanation: None,
            executed: false,
            pending: false,
            reply: reply_tx,
        });
        let result = reply_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());

        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_db_command_shutdown_stops_thread() {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || run_db_thread(rx));

        let _ = tx.send(DbCommand::Shutdown);
        handle.join().expect("db thread should exit cleanly");
    }

    #[test]
    fn test_protocol_version_exact_value() {
        assert_eq!(DAEMON_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn test_daemon_response_error_with_string_owned() {
        let msg = String::from("owned error message");
        let resp = DaemonResponse::error(msg);
        if let DaemonResponse::Error { message } = resp {
            assert_eq!(message, "owned error message");
        } else {
            panic!("expected Error");
        }
    }

    #[test]
    fn test_daemon_response_ok_serialization_omits_data() {
        let resp = DaemonResponse::ok();
        let val: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(val.get("status").unwrap(), "ok");
        assert!(val.get("data").is_none());
    }

    #[test]
    fn test_daemon_response_ok_with_data_serialization_includes_data() {
        let resp = DaemonResponse::ok_with_data(serde_json::json!(42));
        let val: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(val["status"], "ok");
        assert_eq!(val["data"], 42);
    }

    #[test]
    fn test_daemon_response_error_serialization_shape() {
        let resp = DaemonResponse::error("boom");
        let val: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(val["status"], "error");
        assert_eq!(val["message"], "boom");
        assert!(val.get("data").is_none());
    }

    #[test]
    fn test_daemon_response_deserialize_ok_without_data() {
        let json = r#"{"status":"ok"}"#;
        let resp: DaemonResponse = serde_json::from_str(json).unwrap();
        assert!(matches!(resp, DaemonResponse::Ok { data: None }));
    }

    #[test]
    fn test_daemon_response_deserialize_ok_with_data() {
        let json = r#"{"status":"ok","data":{"key":"val"}}"#;
        let resp: DaemonResponse = serde_json::from_str(json).unwrap();
        if let DaemonResponse::Ok { data: Some(d) } = resp {
            assert_eq!(d["key"], "val");
        } else {
            panic!("expected Ok with data");
        }
    }

    #[test]
    fn test_daemon_response_deserialize_error() {
        let json = r#"{"status":"error","message":"something broke"}"#;
        let resp: DaemonResponse = serde_json::from_str(json).unwrap();
        if let DaemonResponse::Error { message } = resp {
            assert_eq!(message, "something broke");
        } else {
            panic!("expected Error");
        }
    }

    #[test]
    fn test_daemon_request_invalid_type_tag() {
        let json = r#"{"type":"nonexistent_variant","session":"s"}"#;
        let result = serde_json::from_str::<DaemonRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_daemon_response_invalid_status_tag() {
        let json = r#"{"status":"unknown","message":"x"}"#;
        let result = serde_json::from_str::<DaemonResponse>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_daemon_request_missing_required_field() {
        let json = r#"{"type":"record","session":"s1"}"#;
        let result = serde_json::from_str::<DaemonRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_daemon_response_ok_with_null_data() {
        let resp = DaemonResponse::ok_with_data(serde_json::Value::Null);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"data\":null"));
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, DaemonResponse::Ok { data: None }));
    }

    #[test]
    fn test_daemon_response_ok_with_empty_object() {
        let resp = DaemonResponse::ok_with_data(serde_json::json!({}));
        let val: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(val["data"], serde_json::json!({}));
    }

    #[test]
    fn test_daemon_response_ok_with_array_data() {
        let resp = DaemonResponse::ok_with_data(serde_json::json!([1, "two", 3]));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        if let DaemonResponse::Ok { data: Some(d) } = parsed {
            assert_eq!(d[0], 1);
            assert_eq!(d[1], "two");
            assert_eq!(d[2], 3);
        } else {
            panic!("expected Ok with array data");
        }
    }

    #[test]
    fn test_daemon_socket_path_special_characters() {
        let path = daemon_socket_path("sess-with.dots_and-dashes");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "daemon_sess-with.dots_and-dashes.sock");
    }

    #[test]
    fn test_daemon_pid_path_special_characters() {
        let path = daemon_pid_path("sess-with.dots_and-dashes");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "daemon_sess-with.dots_and-dashes.pid");
    }

    #[test]
    fn test_daemon_socket_path_empty_session() {
        let path = daemon_socket_path("");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "daemon_.sock");
    }

    #[test]
    fn test_daemon_request_debug_trait() {
        let req = DaemonRequest::Status;
        let dbg = format!("{:?}", req);
        assert!(dbg.contains("Status"));
    }

    #[test]
    fn test_daemon_response_debug_trait() {
        let resp = DaemonResponse::ok();
        let dbg = format!("{:?}", resp);
        assert!(dbg.contains("Ok"));

        let resp_err = DaemonResponse::error("fail");
        let dbg_err = format!("{:?}", resp_err);
        assert!(dbg_err.contains("Error"));
        assert!(dbg_err.contains("fail"));
    }

    #[test]
    fn test_daemon_response_error_empty_message() {
        let resp = DaemonResponse::error("");
        if let DaemonResponse::Error { message } = resp {
            assert_eq!(message, "");
        } else {
            panic!("expected Error");
        }
    }

    #[test]
    fn test_daemon_request_record_negative_exit_code() {
        let req = DaemonRequest::Record {
            session: "s".into(),
            command: "false".into(),
            cwd: "/".into(),
            exit_code: -1,
            started_at: "2025-01-01T00:00:00Z".into(),
            tty: String::new(),
            pid: 0,
            shell: String::new(),
            duration_ms: None,
            output: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::Record { exit_code, .. } = parsed {
            assert_eq!(exit_code, -1);
        } else {
            panic!("expected Record");
        }
    }

    #[test]
    fn test_daemon_request_scrollback_custom_max_lines() {
        let json_str = r#"{"type":"scrollback","max_lines":5}"#;
        let req: DaemonRequest = serde_json::from_str(json_str).unwrap();
        if let DaemonRequest::Scrollback { max_lines } = req {
            assert_eq!(max_lines, 5);
        } else {
            panic!("expected Scrollback");
        }
    }

    #[test]
    fn test_daemon_response_error_with_format_string() {
        let code = 42;
        let resp = DaemonResponse::error(format!("exit code {code}"));
        if let DaemonResponse::Error { message } = resp {
            assert_eq!(message, "exit code 42");
        } else {
            panic!("expected Error");
        }
    }

    #[test]
    fn test_daemon_socket_and_pid_paths_share_parent() {
        let sock = daemon_socket_path("s1");
        let pid = daemon_pid_path("s1");
        assert_eq!(sock.parent(), pid.parent());
    }

    #[test]
    fn test_handle_heartbeat_db_thread_hung_up() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            if let Ok(cmd) = rx.recv() {
                match cmd {
                    DbCommand::Heartbeat { reply, .. } => {
                        drop(reply);
                    }
                    _ => {}
                }
            }
        });

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Heartbeat { session: "s1".into() },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("hung up") || message.contains("timeout"));
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn test_handle_capture_read_truncates_to_max_lines() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 10000, "vt100".into(), "drop".into()));
        {
            let mut eng = capture.lock().unwrap();
            eng.mark();
            for i in 0..20 {
                eng.process(format!("line {i}\r\n").as_bytes());
            }
        }
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::CaptureRead { session: "s1".into(), max_lines: 5 },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                let output = d["output"].as_str().unwrap();
                let line_count = output.lines().count();
                assert!(line_count <= 5, "expected at most 5 lines, got {line_count}");
            }
            _ => panic!("expected Ok with output data"),
        }
    }

    #[test]
    fn test_handle_scrollback_empty_capture() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::Scrollback { max_lines: 10 },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                assert!(d["scrollback"].is_string());
            }
            _ => panic!("expected Ok with scrollback data"),
        }
    }

    #[test]
    fn test_handle_capture_read_no_mark_returns_empty() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::CaptureRead { session: "s1".into(), max_lines: 100 },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                let output = d["output"].as_str().unwrap();
                assert!(output.is_empty());
            }
            _ => panic!("expected Ok with output data"),
        }
    }

    #[test]
    fn test_daemon_response_error_unicode() {
        let resp = DaemonResponse::error("错误: сбой 💥");
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        if let DaemonResponse::Error { message } = parsed {
            assert_eq!(message, "错误: сбой 💥");
        } else {
            panic!("expected Error");
        }
    }

    #[test]
    fn test_daemon_request_mcp_tool_call_empty_tool_name() {
        let req = DaemonRequest::McpToolCall {
            tool: "".into(),
            input: serde_json::json!(null),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::McpToolCall { tool, input } = parsed {
            assert_eq!(tool, "");
            assert!(input.is_null());
        } else {
            panic!("expected McpToolCall");
        }
    }

    #[test]
    fn test_handle_status_contains_version_and_pid() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(DaemonRequest::Status, &capture, &db_tx, 65536);
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                assert_eq!(d["version"].as_str().unwrap(), env!("CARGO_PKG_VERSION"));
                assert_eq!(d["pid"].as_u64().unwrap(), u64::from(std::process::id()));
            }
            _ => panic!("expected Ok with data"),
        }
    }

    #[test]
    fn test_handle_summarize_check_sends_generate_summaries() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::SummarizeCheck { session: "s1".into() },
            &capture,
            &tx,
            65536,
        );
        assert!(matches!(resp, DaemonResponse::Ok { data: None }));
        let cmd = rx.recv_timeout(std::time::Duration::from_millis(100)).unwrap();
        assert!(matches!(cmd, DbCommand::GenerateSummaries));
    }

    #[test]
    fn test_daemon_response_ok_with_deeply_nested_data() {
        let data = serde_json::json!({
            "a": {"b": {"c": {"d": [1, 2, {"e": true}]}}}
        });
        let resp = DaemonResponse::ok_with_data(data.clone());
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        if let DaemonResponse::Ok { data: Some(d) } = parsed {
            assert_eq!(d["a"]["b"]["c"]["d"][2]["e"], true);
        } else {
            panic!("expected Ok with data");
        }
    }

    #[test]
    fn test_daemon_request_record_with_output_provided_takes_priority() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        {
            let mut eng = capture.lock().unwrap();
            eng.mark();
            eng.process(b"captured text\r\n");
        }
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            if let Ok(DbCommand::Record { output, reply, .. }) = rx.recv() {
                assert_eq!(output.as_deref(), Some("explicit output"));
                let _ = reply.send(Ok(1));
            }
        });
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "s1".into(),
                command: "test".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2025-01-01T00:00:00Z".into(),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: Some("explicit output".into()),
            },
            &capture,
            &tx,
            65536,
        );
        assert!(matches!(resp, DaemonResponse::Ok { .. }));
    }

    #[test]
    fn test_daemon_request_record_captures_when_output_none() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 10000, "vt100".into(), "drop".into()));
        {
            let mut eng = capture.lock().unwrap();
            eng.mark();
            eng.process(b"captured line\r\n");
        }
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            if let Ok(DbCommand::Record { output, reply, .. }) = rx.recv() {
                assert!(output.is_some(), "should have captured output from engine");
                let _ = reply.send(Ok(1));
            }
        });
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "s1".into(),
                command: "test".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2025-01-01T00:00:00Z".into(),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: None,
            },
            &capture,
            &tx,
            65536,
        );
        assert!(matches!(resp, DaemonResponse::Ok { .. }));
    }

    #[test]
    fn test_daemon_pid_path_empty_session() {
        let path = daemon_pid_path("");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "daemon_.pid");
    }

    #[test]
    fn test_handle_capture_read_zero_max_lines() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 10000, "vt100".into(), "drop".into()));
        {
            let mut eng = capture.lock().unwrap();
            eng.mark();
            for i in 0..10 {
                eng.process(format!("line {i}\r\n").as_bytes());
            }
        }
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::CaptureRead { session: "s1".into(), max_lines: 0 },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                let output = d["output"].as_str().unwrap();
                assert!(output.is_empty(), "max_lines=0 should yield empty output");
            }
            _ => panic!("expected Ok with output data"),
        }
    }

    #[test]
    fn test_handle_scrollback_with_data() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 10000, "vt100".into(), "drop".into()));
        {
            let mut eng = capture.lock().unwrap();
            eng.process(b"scroll content\r\n");
        }
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp = handle_daemon_request(
            DaemonRequest::Scrollback { max_lines: 1 },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                let text = d["scrollback"].as_str().unwrap();
                assert!(text.contains("scroll content"));
            }
            _ => panic!("expected Ok with scrollback data"),
        }
    }

    #[test]
    fn test_daemon_request_record_with_large_output() {
        let big_output = "x".repeat(100_000);
        let req = DaemonRequest::Record {
            session: "s".into(),
            command: "gen".into(),
            cwd: "/".into(),
            exit_code: 0,
            started_at: "2025-01-01T00:00:00Z".into(),
            tty: String::new(),
            pid: 0,
            shell: String::new(),
            duration_ms: None,
            output: Some(big_output.clone()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DaemonRequest = serde_json::from_str(&json).unwrap();
        if let DaemonRequest::Record { output: Some(o), .. } = parsed {
            assert_eq!(o.len(), 100_000);
        } else {
            panic!("expected Record with output");
        }
    }

    #[test]
    fn test_run_db_thread_insert_conversation_with_explanation() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || run_db_thread(rx));

        let (rec_tx, rec_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::Record {
            session: "conv_explain_sess".into(),
            command: "echo setup".into(),
            cwd: "/tmp".into(),
            exit_code: 0,
            started_at: "2025-06-01T00:00:00Z".into(),
            tty: "".into(),
            pid: 0,
            shell: "".into(),
            duration_ms: None,
            output: None,
            reply: rec_tx,
        });
        let _ = rec_rx.recv_timeout(std::time::Duration::from_secs(2));

        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::InsertConversation {
            session_id: "conv_explain_sess".into(),
            query: "how to list files".into(),
            response_type: "command".into(),
            response: "ls -la".into(),
            explanation: Some("Lists all files with details".into()),
            executed: true,
            pending: false,
            reply: reply_tx,
        });
        let result = reply_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());

        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_run_db_thread_insert_conversation_pending() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || run_db_thread(rx));

        let (rec_tx, rec_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::Record {
            session: "conv_pending_sess".into(),
            command: "echo setup".into(),
            cwd: "/tmp".into(),
            exit_code: 0,
            started_at: "2025-06-01T00:00:00Z".into(),
            tty: "".into(),
            pid: 0,
            shell: "".into(),
            duration_ms: None,
            output: None,
            reply: rec_tx,
        });
        let _ = rec_rx.recv_timeout(std::time::Duration::from_secs(2));

        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::InsertConversation {
            session_id: "conv_pending_sess".into(),
            query: "deploy to prod".into(),
            response_type: "command".into(),
            response: "kubectl apply -f deploy.yaml".into(),
            explanation: None,
            executed: false,
            pending: true,
            reply: reply_tx,
        });
        let result = reply_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());

        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_run_db_thread_search_history_with_results() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || run_db_thread(rx));

        let (rec_tx, rec_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::Record {
            session: "search_hist_sess".into(),
            command: "cargo test --all".into(),
            cwd: "/tmp".into(),
            exit_code: 0,
            started_at: "2025-06-01T00:00:00Z".into(),
            tty: "".into(),
            pid: 0,
            shell: "".into(),
            duration_ms: Some(500),
            output: Some("test result: ok".into()),
            reply: rec_tx,
        });
        let _ = rec_rx.recv_timeout(std::time::Duration::from_secs(2));

        let (search_tx, search_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::SearchHistory {
            query: "cargo test".into(),
            limit: 10,
            reply: search_tx,
        });
        let result = search_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());

        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_run_db_thread_generate_summaries_with_commands() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || run_db_thread(rx));

        for i in 0..3 {
            let (rec_tx, rec_rx) = std::sync::mpsc::channel();
            let _ = tx.send(DbCommand::Record {
                session: "summary_gen_sess".into(),
                command: format!("echo line_{i}"),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: format!("2025-06-01T00:{i:02}:00Z"),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: Some(10),
                output: Some(format!("line_{i}")),
                reply: rec_tx,
            });
            let _ = rec_rx.recv_timeout(std::time::Duration::from_secs(2));
        }

        let _ = tx.send(DbCommand::GenerateSummaries);

        let (search_tx, search_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::SearchHistory {
            query: "echo".into(),
            limit: 10,
            reply: search_tx,
        });
        let _ = search_rx.recv_timeout(std::time::Duration::from_secs(2));

        let _ = tx.send(DbCommand::Shutdown);
    }

    #[test]
    fn test_run_db_thread_multiple_commands_sequence() {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || run_db_thread(rx));

        let (rec_tx, rec_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::Record {
            session: "seq_sess".into(),
            command: "pwd".into(),
            cwd: "/home".into(),
            exit_code: 0,
            started_at: "2025-06-01T00:00:00Z".into(),
            tty: "/dev/pts/0".into(),
            pid: 42,
            shell: "zsh".into(),
            duration_ms: Some(5),
            output: Some("/home".into()),
            reply: rec_tx,
        });
        let result = rec_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());
        let id = result.unwrap();
        assert!(id > 0);

        let (hb_tx, hb_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::Heartbeat {
            session: "seq_sess".into(),
            reply: hb_tx,
        });
        let hb_result = hb_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(hb_result.is_ok());

        let _ = tx.send(DbCommand::GenerateSummaries);

        let _ = tx.send(DbCommand::Shutdown);
        handle.join().expect("db thread should exit cleanly");
    }

    #[test]
    fn test_handle_record_timeout_when_db_sleeps() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            if let Ok(DbCommand::Record { reply, .. }) = rx.recv() {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let _ = reply.send(Ok(1));
            }
        });

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "s1".into(),
                command: "slow".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2025-01-01T00:00:00Z".into(),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: None,
            },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("timeout") || message.contains("DB"));
            }
            _ => panic!("expected Error due to timeout"),
        }
    }

    #[test]
    fn test_handle_heartbeat_timeout_when_db_sleeps() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            if let Ok(DbCommand::Heartbeat { reply, .. }) = rx.recv() {
                std::thread::sleep(std::time::Duration::from_secs(2));
                let _ = reply.send(Ok(()));
            }
        });

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Heartbeat { session: "s1".into() },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("timeout") || message.contains("DB"));
            }
            _ => panic!("expected Error due to timeout"),
        }
    }

    #[test]
    fn test_run_db_thread_shutdown_after_heavy_use() {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || run_db_thread(rx));

        for i in 0..10 {
            let (rec_tx, rec_rx) = std::sync::mpsc::channel();
            let _ = tx.send(DbCommand::Record {
                session: "heavy_sess".into(),
                command: format!("cmd_{i}"),
                cwd: "/tmp".into(),
                exit_code: i % 3,
                started_at: format!("2025-06-01T00:{i:02}:00Z"),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: None,
                reply: rec_tx,
            });
            let _ = rec_rx.recv_timeout(std::time::Duration::from_secs(2));
        }

        let _ = tx.send(DbCommand::GenerateSummaries);
        let _ = tx.send(DbCommand::GenerateSummaries);

        let _ = tx.send(DbCommand::Shutdown);
        handle.join().expect("db thread should exit after heavy use");
    }

    #[test]
    fn test_generate_summaries_sync_with_trivial_command() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.create_session("sum_sess", "/dev/pts/0", "zsh", 1).unwrap();
        db.insert_command(
            "sum_sess", "cd /tmp", "/home", Some(0),
            "2025-01-01T00:00:00Z", Some(5), None,
            "/dev/pts/0", "zsh", 1,
        ).unwrap();
        db.insert_command(
            "sum_sess", "ls", "/tmp", Some(0),
            "2025-01-01T00:01:00Z", Some(10), Some("file1\nfile2"),
            "/dev/pts/0", "zsh", 1,
        ).unwrap();
        generate_summaries_sync(&db);
    }

    #[test]
    fn test_generate_summaries_sync_with_failing_command() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.create_session("fail_sess", "/dev/pts/0", "bash", 1).unwrap();
        db.insert_command(
            "fail_sess", "nonexistent_command", "/tmp", Some(127),
            "2025-01-01T00:00:00Z", Some(10), Some("command not found"),
            "/dev/pts/0", "bash", 1,
        ).unwrap();
        generate_summaries_sync(&db);
    }

    #[test]
    fn test_daemon_request_all_variants_roundtrip() {
        let variants = vec![
            r#"{"type":"heartbeat","session":"s1"}"#,
            r#"{"type":"status"}"#,
            r#"{"type":"capture_mark","session":"s1"}"#,
            r#"{"type":"capture_read","session":"s1"}"#,
            r#"{"type":"scrollback"}"#,
            r#"{"type":"context","session":"s1"}"#,
            r#"{"type":"summarize_check","session":"s1"}"#,
            r#"{"type":"mcp_tool_call","tool":"test","input":{}}"#,
        ];
        for json_str in &variants {
            let parsed: DaemonRequest = serde_json::from_str(json_str).unwrap();
            let reserialized = serde_json::to_string(&parsed).unwrap();
            let _reparsed: DaemonRequest = serde_json::from_str(&reserialized).unwrap();
        }
    }

    #[test]
    fn test_daemon_response_ok_skips_null_data() {
        let resp = DaemonResponse::ok();
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("data"), "Ok without data should skip data field: {json}");
    }

    #[test]
    fn test_daemon_response_ok_with_data_includes_data() {
        let resp = DaemonResponse::ok_with_data(serde_json::json!({"key": "value"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"key\""));
        assert!(json.contains("\"value\""));
    }

    #[test]
    fn test_daemon_response_error_roundtrip_serde() {
        let resp = DaemonResponse::error("something went wrong");
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: DaemonResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            DaemonResponse::Error { message } => {
                assert_eq!(message, "something went wrong");
            }
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn test_daemon_request_record_defaults_for_optional_fields() {
        let json_str = r#"{"type":"record","session":"s1","command":"ls","cwd":"/","exit_code":0,"started_at":"2025-01-01T00:00:00Z"}"#;
        let parsed: DaemonRequest = serde_json::from_str(json_str).unwrap();
        match parsed {
            DaemonRequest::Record { tty, pid, shell, duration_ms, output, .. } => {
                assert_eq!(tty, "");
                assert_eq!(pid, 0);
                assert_eq!(shell, "");
                assert!(duration_ms.is_none());
                assert!(output.is_none());
            }
            _ => panic!("expected Record"),
        }
    }

    #[test]
    fn test_handle_context_and_mcp_not_implemented() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, _db_rx) = std::sync::mpsc::channel();
        let resp1 = handle_daemon_request(
            DaemonRequest::Context { session: "s1".into() },
            &capture,
            &db_tx,
            65536,
        );
        match resp1 {
            DaemonResponse::Error { message } => assert!(message.contains("not yet")),
            _ => panic!("expected Error for Context"),
        }
        let resp2 = handle_daemon_request(
            DaemonRequest::McpToolCall { tool: "test".into(), input: serde_json::json!({}) },
            &capture,
            &db_tx,
            65536,
        );
        match resp2 {
            DaemonResponse::Error { message } => assert!(message.contains("not yet")),
            _ => panic!("expected Error for McpToolCall"),
        }
    }

    #[test]
    fn test_handle_summarize_check() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, db_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            while let Ok(cmd) = db_rx.recv() {
                match cmd {
                    DbCommand::GenerateSummaries => break,
                    _ => {}
                }
            }
        });
        let resp = handle_daemon_request(
            DaemonRequest::SummarizeCheck { session: "s1".into() },
            &capture,
            &db_tx,
            65536,
        );
        assert!(matches!(resp, DaemonResponse::Ok { data: None }));
    }

    #[test]
    fn test_handle_record_db_tx_dropped() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, db_rx) = std::sync::mpsc::channel::<DbCommand>();
        drop(db_rx);
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "s1".into(),
                command: "ls".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2025-01-01T00:00:00Z".into(),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: None,
            },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("unavailable"), "got: {message}");
            }
            _ => panic!("expected Error when db_tx receiver is dropped"),
        }
    }

    #[test]
    fn test_handle_heartbeat_db_tx_dropped() {
        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let (db_tx, db_rx) = std::sync::mpsc::channel::<DbCommand>();
        drop(db_rx);
        let resp = handle_daemon_request(
            DaemonRequest::Heartbeat { session: "s1".into() },
            &capture,
            &db_tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("unavailable"), "got: {message}");
            }
            _ => panic!("expected Error when db_tx receiver is dropped"),
        }
    }

    #[test]
    fn test_run_db_thread_record_with_conversation_feedback() {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || run_db_thread(rx));

        let (conv_tx, conv_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::InsertConversation {
            session_id: "feedback_sess".into(),
            query: "run tests".into(),
            response_type: "command".into(),
            response: "cargo test".into(),
            explanation: Some("run the test suite".into()),
            executed: false,
            pending: true,
            reply: conv_tx,
        });
        let _ = conv_rx.recv_timeout(std::time::Duration::from_secs(2));

        let (rec_tx, rec_rx) = std::sync::mpsc::channel();
        let _ = tx.send(DbCommand::Record {
            session: "feedback_sess".into(),
            command: "cargo test".into(),
            cwd: "/project".into(),
            exit_code: 0,
            started_at: "2025-06-01T00:00:00Z".into(),
            tty: "/dev/pts/0".into(),
            pid: 42,
            shell: "zsh".into(),
            duration_ms: Some(1500),
            output: Some("test result: ok. 10 passed".into()),
            reply: rec_tx,
        });
        let result = rec_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(result.is_ok());

        let _ = tx.send(DbCommand::Shutdown);
        handle.join().expect("db thread should exit cleanly");
    }

    #[test]
    fn test_handle_record_db_error_response() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            if let Ok(DbCommand::Record { reply, .. }) = rx.recv() {
                let _ = reply.send(Err(anyhow::anyhow!("simulated DB error")));
            }
        });

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Record {
                session: "s1".into(),
                command: "test".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2025-01-01T00:00:00Z".into(),
                tty: "".into(),
                pid: 0,
                shell: "".into(),
                duration_ms: None,
                output: None,
            },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("simulated DB error"));
            }
            _ => panic!("expected Error response for DB error"),
        }
    }

    #[test]
    fn test_handle_heartbeat_db_error_response() {
        let (tx, rx) = std::sync::mpsc::channel::<DbCommand>();
        std::thread::spawn(move || {
            if let Ok(DbCommand::Heartbeat { reply, .. }) = rx.recv() {
                let _ = reply.send(Err(anyhow::anyhow!("heartbeat DB error")));
            }
        });

        let capture = Mutex::new(crate::pump::CaptureEngine::new(24, 80, 0, 2, 1000, "vt100".into(), "drop".into()));
        let resp = handle_daemon_request(
            DaemonRequest::Heartbeat { session: "s1".into() },
            &capture,
            &tx,
            65536,
        );
        match resp {
            DaemonResponse::Error { message } => {
                assert!(message.contains("heartbeat DB error"));
            }
            _ => panic!("expected Error response for heartbeat DB error"),
        }
    }
}
