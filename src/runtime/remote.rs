//! Iroh-based remote access endpoint for the nsh global daemon.
//!
//! The iroh endpoint runs in the global daemon as the control plane
//! (auth, pairing, session listing). Live PTY I/O (data plane) stays
//! in the shim. The iroh handler bridges between QUIC streams and
//! per-session Unix sockets via the StreamAttach protocol.

use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use nsh_proto::{ALPN, RemoteRequest, RemoteResponse, RemoteSessionInfo};

static CONNECTED_PEERS: std::sync::LazyLock<Arc<AtomicU32>> =
    std::sync::LazyLock::new(|| Arc::new(AtomicU32::new(0)));
static ATTACHED_SESSIONS: std::sync::LazyLock<Arc<AtomicU32>> =
    std::sync::LazyLock::new(|| Arc::new(AtomicU32::new(0)));
static ACTIVE_CONNECTIONS: std::sync::LazyLock<
    Arc<std::sync::Mutex<Vec<iroh::endpoint::Connection>>>,
> = std::sync::LazyLock::new(|| Arc::new(std::sync::Mutex::new(Vec::new())));
/// Cached relay URL from the iroh endpoint, populated at startup.
static HOME_RELAY_URL: std::sync::LazyLock<std::sync::Mutex<Option<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

/// Send a best-effort state push to all connected peers via unreliable datagrams.
pub fn broadcast_datagram(payload: &[u8]) {
    if let Ok(mut conns) = ACTIVE_CONNECTIONS.lock() {
        conns.retain(|c| c.send_datagram(payload.to_vec().into()).is_ok());
    }
}

pub fn live_peer_counts() -> (u32, u32) {
    (
        CONNECTED_PEERS.load(Ordering::Relaxed),
        ATTACHED_SESSIONS.load(Ordering::Relaxed),
    )
}

/// Return the cached home relay URL, populated when the iroh endpoint starts.
pub fn home_relay_url() -> Option<String> {
    HOME_RELAY_URL.lock().ok().and_then(|g| g.clone())
}

/// Start the iroh remote endpoint in a background thread.
pub fn spawn_iroh_endpoint(
    _config: &crate::config::Config,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let secret_key = crate::runtime::remote_key::load_or_create_secret_key()?;

    let handle = std::thread::Builder::new()
        .name("nshd-iroh".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .expect("iroh tokio runtime");

            rt.block_on(async move {
                if let Err(e) = run_iroh_endpoint(secret_key).await {
                    crate::runtime::global_daemon::log_daemon("iroh.error", &e.to_string());
                }
            });
        })?;

    Ok(handle)
}

/// QUIC-layer auth hook: reject connections from unknown peers before
/// protocol handling, as defense-in-depth alongside the per-connection
/// auth check in NshRemoteHandler::accept.
#[derive(Debug)]
struct NshAuthHook;

#[allow(clippy::manual_async_fn)]
impl iroh::endpoint::EndpointHooks for NshAuthHook {
    fn after_handshake<'a>(
        &'a self,
        info: &'a iroh::endpoint::ConnectionInfo,
    ) -> impl std::future::Future<Output = iroh::endpoint::AfterHandshakeOutcome> + Send + 'a {
        async move {
            let remote_id = info.remote_id();
            let allowed_keys = crate::config::Config::load()
                .map(|c| c.remote.allowed_keys)
                .unwrap_or_default();
            if crate::runtime::remote_key::is_key_allowed(&remote_id, &allowed_keys) {
                iroh::endpoint::AfterHandshakeOutcome::accept()
            } else {
                crate::runtime::global_daemon::log_daemon(
                    "iroh.rejected_hook",
                    &remote_id.to_string(),
                );
                iroh::endpoint::AfterHandshakeOutcome::Reject {
                    error_code: 1u32.into(),
                    reason: b"unauthorized".to_vec(),
                }
            }
        }
    }
}

async fn run_iroh_endpoint(secret_key: iroh::SecretKey) -> anyhow::Result<()> {
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .hooks(NshAuthHook)
        .bind()
        .await?;

    let node_id = endpoint.id();
    // Cache the home relay URL for status reporting
    if let Some(relay) = endpoint.addr().relay_urls().next() {
        if let Ok(mut cached) = HOME_RELAY_URL.lock() {
            *cached = Some(relay.to_string());
        }
    }
    crate::runtime::global_daemon::log_daemon("iroh.started", &format!("EndpointId: {node_id}"));

    let handler = NshRemoteHandler;

    let router = iroh::protocol::Router::builder(endpoint)
        .accept(ALPN.to_vec(), handler)
        .spawn();

    // Periodic state push via unreliable datagrams (best-effort)
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            if let Ok(sessions) = list_active_sessions() {
                for session in &sessions {
                    let update = nsh_proto::StatePush::SessionActivity {
                        session_id: session.session_id.clone(),
                        last_cwd: session.last_cwd.clone(),
                        git_branch: session.git_branch.clone(),
                        running_command: session.running_command.clone(),
                    };
                    if let Ok(bytes) = serde_json::to_vec(&update)
                        && bytes.len() < 1200
                    {
                        broadcast_datagram(&bytes);
                    }
                }
            }
        }
    });

    // Keep router alive until shutdown signal
    // The router runs its accept loop in the background; we block here.
    // In practice, the global daemon thread will keep this alive until process exit.
    tokio::signal::ctrl_c().await.ok();
    router.shutdown().await?;
    Ok(())
}

struct NshRemoteHandler;

impl fmt::Debug for NshRemoteHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NshRemoteHandler").finish()
    }
}

impl iroh::protocol::ProtocolHandler for NshRemoteHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let remote_id = connection.remote_id();
        let remote_id_str = remote_id.to_string();

        // Defense-in-depth: the QUIC-layer NshAuthHook should have already
        // rejected unauthorized peers. This check catches edge cases where
        // config was updated between hook check and protocol handling.
        let allowed_keys = crate::config::Config::load()
            .map(|c| c.remote.allowed_keys)
            .unwrap_or_default();
        if !crate::runtime::remote_key::is_key_allowed(&remote_id, &allowed_keys) {
            crate::runtime::global_daemon::log_daemon(
                "iroh.rejected.defense_in_depth",
                &remote_id_str,
            );
            connection.close(1u32.into(), b"unauthorized");
            return Ok(());
        }

        crate::runtime::global_daemon::log_daemon("iroh.accepted", &remote_id_str);

        CONNECTED_PEERS.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut conns) = ACTIVE_CONNECTIONS.lock() {
            conns.push(connection.clone());
        }

        // Accept bidirectional streams in a loop
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(_) => break,
            };

            let remote_id_str = remote_id_str.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_remote_stream(send, recv, &remote_id_str).await {
                    tracing::debug!("iroh stream error for {remote_id_str}: {e}");
                }
            });
        }

        CONNECTED_PEERS.fetch_sub(1, Ordering::Relaxed);

        Ok(())
    }
}

async fn handle_remote_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    peer_id: &str,
) -> anyhow::Result<()> {
    tracing::debug!("handling remote stream from peer {peer_id}");
    let request: RemoteRequest = nsh_proto::framing::read_message(&mut recv)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Validate session_id in requests that use it (prevent path traversal)
    let validate_session_id = |id: &str| -> bool {
        id.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };

    match request {
        RemoteRequest::ListSessions => {
            let sessions = list_active_sessions()?;
            let response = RemoteResponse::SessionList { sessions };
            nsh_proto::framing::write_message(&mut send, &response)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }

        RemoteRequest::Attach { ref session_id } if !validate_session_id(session_id) => {
            let err = RemoteResponse::Error {
                message: "invalid session_id format".into(),
            };
            nsh_proto::framing::write_message(&mut send, &err)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }

        RemoteRequest::Attach { session_id } => {
            bridge_to_session(
                send,
                recv,
                &session_id,
                peer_id,
                "stream_attach",
                None,
            )
            .await?;
        }

        RemoteRequest::Resume {
            ref session_id, ..
        } if !validate_session_id(session_id) => {
            let err = RemoteResponse::Error {
                message: "invalid session_id format".into(),
            };
            nsh_proto::framing::write_message(&mut send, &err)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }

        RemoteRequest::Resume {
            session_id,
            last_seq,
        } => {
            bridge_to_session(
                send,
                recv,
                &session_id,
                peer_id,
                "stream_resume",
                Some(last_seq),
            )
            .await?;
        }

        RemoteRequest::Query {
            session_id,
            query,
            ..
        } => {
            // Validate session_id format (prevent path traversal)
            if !session_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                let err = RemoteResponse::QueryError {
                    message: "invalid session_id".into(),
                };
                nsh_proto::framing::write_message(&mut send, &err)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                return Ok(());
            }

            // Forward the query to the daemon for execution
            let request = crate::daemon::DaemonRequest::SearchHistory {
                query: query.clone(),
                limit: 5,
            };
            let result = crate::daemon_client::send_to_global(&request);
            let response = match result {
                Ok(resp) => RemoteResponse::QueryComplete {
                    response: serde_json::to_string(&resp).unwrap_or_default(),
                },
                Err(e) => RemoteResponse::QueryError {
                    message: e.to_string(),
                },
            };
            nsh_proto::framing::write_message(&mut send, &response)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }

        _ => {
            let err = RemoteResponse::Error {
                message: "unexpected request on new stream".into(),
            };
            nsh_proto::framing::write_message(&mut send, &err)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
    }

    Ok(())
}

/// Bridge a QUIC stream to a per-session Unix socket for attach or resume.
/// Reads binary-framed output `[8-byte seq BE][4-byte len BE][payload]`
/// from the shim and forwards as `RemoteResponse::TerminalData` over QUIC.
async fn bridge_to_session(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    session_id: &str,
    peer_id: &str,
    request_type: &str,
    last_seq: Option<u64>,
) -> anyhow::Result<()> {
    let socket_path = crate::daemon::daemon_socket_path(session_id);
    let unix_stream = tokio::net::UnixStream::connect(&socket_path).await?;
    let (unix_read, mut unix_write) = unix_stream.into_split();

    // Send handshake (length-prefixed frame)
    let mut handshake_req = serde_json::json!({
        "v": crate::daemon::DAEMON_PROTOCOL_VERSION,
        "type": request_type,
        "session": session_id,
        "peer_id": peer_id,
    });
    if let Some(seq) = last_seq {
        handshake_req["last_seq"] = serde_json::json!(seq);
    }
    let req_bytes = serde_json::to_vec(&handshake_req)?;
    nsh_proto::framing::write_frame(&mut unix_write, &req_bytes).await?;

    // Read handshake response (length-prefixed frame)
    let mut unix_read = unix_read;
    let handshake_resp_bytes = nsh_proto::framing::read_frame(&mut unix_read).await?;
    let handshake_resp: serde_json::Value = serde_json::from_slice(&handshake_resp_bytes)?;

    // Extract snapshot (attach) or resumed flag and send to mobile
    let snapshot = handshake_resp["data"]["snapshot"]
        .as_str()
        .and_then(|s| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(s).ok()
        })
        .unwrap_or_default();

    let attach_ok = RemoteResponse::AttachOk {
        initial_screen: snapshot,
    };
    nsh_proto::framing::write_message(&mut send, &attach_ok)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // === Bridge: Unix socket <-> QUIC stream ===

    ATTACHED_SESSIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _session_guard = scopeguard::guard((), |_| {
        ATTACHED_SESSIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    });

    // Task 1: Unix socket (binary-framed PTY output) -> QUIC (TerminalData)
    let mut output_task = tokio::spawn(async move {
        loop {
            // Read binary frame header: [8-byte seq][4-byte len]
            let mut header = [0u8; 12];
            if tokio::io::AsyncReadExt::read_exact(&mut unix_read, &mut header)
                .await
                .is_err()
            {
                break;
            }
            let seq = u64::from_be_bytes(header[0..8].try_into().unwrap());
            let len = u32::from_be_bytes(header[8..12].try_into().unwrap()) as usize;
            if len > 10 * 1024 * 1024 {
                break;
            }
            let mut payload = vec![0u8; len];
            if tokio::io::AsyncReadExt::read_exact(&mut unix_read, &mut payload)
                .await
                .is_err()
            {
                break;
            }
            let msg = RemoteResponse::TerminalData {
                seq,
                bytes: payload,
            };
            if nsh_proto::framing::write_message(&mut send, &msg)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Task 2: QUIC (RemoteRequest) -> Unix socket (length-prefixed commands)
    let mut input_task = tokio::spawn(async move {
        loop {
            match nsh_proto::framing::read_message::<RemoteRequest, _>(&mut recv).await {
                Ok(RemoteRequest::Input { bytes }) => {
                    let cmd = serde_json::json!({
                        "type": "stream_input",
                        "bytes": bytes,
                    });
                    let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
                    let len = (cmd_bytes.len() as u32).to_be_bytes();
                    if tokio::io::AsyncWriteExt::write_all(&mut unix_write, &len)
                        .await
                        .is_err()
                    {
                        break;
                    }
                    if tokio::io::AsyncWriteExt::write_all(&mut unix_write, &cmd_bytes)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(RemoteRequest::Resize { cols, rows }) => {
                    let cmd = serde_json::json!({
                        "type": "stream_resize",
                        "cols": cols,
                        "rows": rows,
                    });
                    let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
                    let len = (cmd_bytes.len() as u32).to_be_bytes();
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut unix_write, &len).await;
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut unix_write, &cmd_bytes).await;
                }
                Ok(RemoteRequest::Detach) | Err(_) => {
                    let cmd = serde_json::json!({ "type": "stream_detach" });
                    let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
                    let len = (cmd_bytes.len() as u32).to_be_bytes();
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut unix_write, &len).await;
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut unix_write, &cmd_bytes).await;
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait for either side to finish, then abort the other
    tokio::select! {
        _ = &mut output_task => { input_task.abort(); }
        _ = &mut input_task => { output_task.abort(); }
    }

    // _session_guard drop handles ATTACHED_SESSIONS decrement
    Ok(())
}

/// Detect the foreground command running in the shell with the given PID.
fn detect_running_command(shell_pid: i64) -> Option<String> {
    if shell_pid <= 0 {
        return None;
    }

    #[cfg(target_os = "linux")]
    {
        // Read /proc/{pid}/stat to get tpgid (terminal foreground process group)
        let stat_path = format!("/proc/{shell_pid}/stat");
        if let Ok(stat) = std::fs::read_to_string(&stat_path) {
            // comm field (field 2) can contain spaces and parens; split after last ')'
            if let Some(after_comm) = stat.rsplit(')').next() {
                let fields: Vec<&str> = after_comm.split_whitespace().collect();
                // fields[0]=state, [1]=ppid, [2]=pgrp, [3]=session, [4]=tty_nr, [5]=tpgid
                if let Some(tpgid_str) = fields.get(5) {
                    if let Ok(tpgid) = tpgid_str.parse::<i64>() {
                        if tpgid > 0 && tpgid != shell_pid {
                            let fg_cmdline = format!("/proc/{tpgid}/cmdline");
                            if let Ok(bytes) = std::fs::read(&fg_cmdline) {
                                let cmd: String = bytes
                                    .split(|&b| b == 0)
                                    .filter(|s| !s.is_empty())
                                    .filter_map(|s| std::str::from_utf8(s).ok())
                                    .collect::<Vec<_>>()
                                    .join(" ");
                                if !cmd.is_empty() {
                                    return Some(cmd);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fallback: read /proc/{pid}/task/{pid}/children
        let children_path = format!("/proc/{shell_pid}/task/{shell_pid}/children");
        if let Ok(children) = std::fs::read_to_string(&children_path) {
            if let Some(child_pid) = children.split_whitespace().last() {
                let child_cmdline = format!("/proc/{child_pid}/cmdline");
                if let Ok(bytes) = std::fs::read(&child_cmdline) {
                    let args: Vec<&str> = bytes
                        .split(|&b| b == 0)
                        .filter(|s| !s.is_empty())
                        .filter_map(|s| std::str::from_utf8(s).ok())
                        .collect();
                    if !args.is_empty() {
                        let base = args[0].rsplit('/').next().unwrap_or(args[0]);
                        if !matches!(base, "bash" | "zsh" | "fish" | "sh" | "dash") {
                            return Some(args.join(" "));
                        }
                    }
                }
            }
        }

        None
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "pid=,command=", "-p"])
            .arg(format!("{shell_pid}"))
            .output()
        {
            // ps on macOS: find children via separate call
            if let Ok(children_output) = std::process::Command::new("pgrep")
                .args(["-P", &shell_pid.to_string()])
                .output()
            {
                if children_output.status.success() {
                    let text = String::from_utf8_lossy(&children_output.stdout);
                    for child_pid in text.lines() {
                        let child_pid = child_pid.trim();
                        if child_pid.is_empty() {
                            continue;
                        }
                        if let Ok(cmd_output) = std::process::Command::new("ps")
                            .args(["-o", "command=", "-p", child_pid])
                            .output()
                        {
                            if cmd_output.status.success() {
                                let cmd = String::from_utf8_lossy(&cmd_output.stdout)
                                    .trim()
                                    .to_string();
                                let base = cmd
                                    .split_whitespace()
                                    .next()
                                    .unwrap_or("")
                                    .rsplit('/')
                                    .next()
                                    .unwrap_or("");
                                if !cmd.is_empty()
                                    && !matches!(
                                        base,
                                        "bash" | "zsh" | "fish" | "sh" | "dash" | "-bash"
                                            | "-zsh" | "-fish"
                                    )
                                {
                                    return Some(cmd);
                                }
                            }
                        }
                    }
                }
            }
            let _ = output; // suppress unused warning
        }
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

fn list_active_sessions() -> anyhow::Result<Vec<RemoteSessionInfo>> {
    let db = crate::db::Db::open()?;
    let nsh_dir = crate::config::Config::nsh_dir();
    let mut stmt = db.conn.prepare(
        "SELECT s.id, s.tty, s.shell, s.pid, s.label,
                (SELECT c.cwd FROM commands c WHERE c.session_id = s.id ORDER BY c.started_at DESC LIMIT 1),
                (SELECT c.command FROM commands c WHERE c.session_id = s.id ORDER BY c.started_at DESC LIMIT 1)
         FROM sessions s WHERE s.ended_at IS NULL",
    )?;
    let sessions = stmt
        .query_map([], |row| {
            let tty: String = row.get(1)?;
            let db_cwd: Option<String> = row.get(5)?;
            // Also try filesystem CWD (more current than DB)
            let tty_safe = tty.replace('/', "_");
            let fs_cwd = std::fs::read_to_string(nsh_dir.join(format!("cwd_{tty_safe}")))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let effective_cwd = fs_cwd.or(db_cwd);

            // Detect git branch from CWD (walk up to find .git)
            let git_branch = effective_cwd.as_deref().and_then(|cwd| {
                let mut dir = std::path::Path::new(cwd);
                loop {
                    let head = dir.join(".git/HEAD");
                    if let Ok(content) = std::fs::read_to_string(&head) {
                        return content
                            .trim()
                            .strip_prefix("ref: refs/heads/")
                            .map(|b| b.trim().to_string())
                            .or_else(|| Some(content.trim().chars().take(8).collect()));
                    }
                    dir = dir.parent()?;
                }
            });

            let pid: i64 = row.get(3)?;
            let running_command = detect_running_command(pid);
            Ok(RemoteSessionInfo {
                session_id: row.get(0)?,
                tty,
                shell: row.get(2)?,
                pid,
                label: row.get(4)?,
                last_cwd: effective_cwd,
                last_command: row.get(6)?,
                git_branch,
                running_command,
            })
        })?
        .filter_map(|r| r.ok())
        .filter(|s| {
            // Filter out zombie sessions where the shell PID is no longer alive
            #[cfg(unix)]
            {
                if s.pid > 0
                    // SAFETY: kill(pid, 0) checks process existence without signaling.
                    && unsafe { libc::kill(s.pid as libc::pid_t, 0) } != 0
                {
                    return false;
                }
            }
            true
        })
        .collect();
    Ok(sessions)
}

/// Remote status info returned to callers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RemoteStatusPayload {
    pub enabled: bool,
    pub node_id: Option<String>,
    pub relay_url: Option<String>,
    pub connected_peers: u32,
    pub attached_sessions: u32,
}
