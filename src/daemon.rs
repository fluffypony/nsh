use serde::{Deserialize, Serialize};
use std::sync::Mutex;

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

fn default_max_lines() -> usize { 1000 }

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
        Self::Error { message: msg.into() }
    }
}

pub fn handle_daemon_request(
    request: DaemonRequest,
    capture: &Mutex<crate::pump::CaptureEngine>,
    db_tx: &std::sync::mpsc::Sender<DbCommand>,
) -> DaemonResponse {
    match request {
        DaemonRequest::Record {
            session, command, cwd, exit_code, started_at,
            tty, pid, shell, duration_ms, output,
        } => {
            let final_output = if output.is_some() {
                output
            } else {
                capture.lock().ok().and_then(|mut eng| eng.capture_since_mark(65536))
            };
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            let cmd = DbCommand::Record {
                session, command, cwd, exit_code, started_at,
                tty, pid, shell, duration_ms, output: final_output,
                reply: reply_tx,
            };
            if db_tx.send(cmd).is_err() {
                return DaemonResponse::error("DB thread unavailable");
            }
            match reply_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Ok(id)) => DaemonResponse::ok_with_data(serde_json::json!({"id": id})),
                Ok(Err(e)) => DaemonResponse::error(format!("{e}")),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => DaemonResponse::error("DB timeout"),
                Err(_) => DaemonResponse::error("DB thread hung up"),
            }
        }

        DaemonRequest::Heartbeat { session } => {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            let cmd = DbCommand::Heartbeat { session, reply: reply_tx };
            if db_tx.send(cmd).is_err() {
                return DaemonResponse::error("DB thread unavailable");
            }
            match reply_rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Ok(())) => DaemonResponse::ok(),
                Ok(Err(e)) => DaemonResponse::error(format!("{e}")),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => DaemonResponse::error("DB timeout"),
                Err(_) => DaemonResponse::error("DB thread hung up"),
            }
        }

        DaemonRequest::Scrollback { max_lines } => {
            match capture.lock() {
                Ok(eng) => {
                    let text = eng.get_lines(max_lines);
                    DaemonResponse::ok_with_data(serde_json::json!({"scrollback": text}))
                }
                Err(_) => DaemonResponse::error("capture lock poisoned"),
            }
        }

        DaemonRequest::CaptureMark { .. } => {
            match capture.lock() {
                Ok(mut eng) => {
                    eng.mark();
                    DaemonResponse::ok()
                }
                Err(_) => DaemonResponse::error("capture lock poisoned"),
            }
        }

        DaemonRequest::CaptureRead { max_lines, .. } => {
            match capture.lock() {
                Ok(mut eng) => {
                    let text = eng.capture_since_mark(65536)
                        .unwrap_or_default();
                    let lines: Vec<&str> = text.lines().collect();
                    let start = lines.len().saturating_sub(max_lines);
                    let result = lines[start..].join("\n");
                    DaemonResponse::ok_with_data(serde_json::json!({"output": result}))
                }
                Err(_) => DaemonResponse::error("capture lock poisoned"),
            }
        }

        DaemonRequest::Status => {
            DaemonResponse::ok_with_data(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "pid": std::process::id(),
            }))
        }

        DaemonRequest::Context { .. }
        | DaemonRequest::McpToolCall { .. }
        | DaemonRequest::SummarizeCheck { .. } => {
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
    SearchHistory {
        query: String,
        limit: usize,
        reply: std::sync::mpsc::Sender<anyhow::Result<Vec<crate::db::HistoryMatch>>>,
    },
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
                session, command, cwd, exit_code, started_at,
                tty, pid, shell, duration_ms, output, reply,
            } => {
                let result = db.insert_command(
                    &session, &command, &cwd, Some(exit_code),
                    &started_at, duration_ms, output.as_deref(),
                    &tty, &shell, pid,
                );
                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
            }

            DbCommand::Heartbeat { session, reply } => {
                let result = db.update_heartbeat(&session);
                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
            }

            DbCommand::InsertConversation {
                session_id, query, response_type, response,
                explanation, executed, pending, reply,
            } => {
                let result = db.insert_conversation(
                    &session_id, &query, &response_type, &response,
                    explanation.as_deref(), executed, pending,
                );
                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
            }

            DbCommand::SearchHistory { query, limit, reply } => {
                let result = db.search_history(&query, limit);
                let _ = reply.send(result.map_err(|e| anyhow::anyhow!("{e}")));
            }

            DbCommand::Shutdown => break,
        }
    }
}

pub fn daemon_socket_path(session_id: &str) -> std::path::PathBuf {
    crate::config::Config::nsh_dir()
        .join(format!("daemon_{session_id}.sock"))
}

pub fn daemon_pid_path(session_id: &str) -> std::path::PathBuf {
    crate::config::Config::nsh_dir()
        .join(format!("daemon_{session_id}.pid"))
}
