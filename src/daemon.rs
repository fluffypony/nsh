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
}
