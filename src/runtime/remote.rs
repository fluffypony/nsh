//! Iroh-based remote access endpoint for the nsh global daemon.
//!
//! The iroh endpoint runs in the global daemon as the control plane
//! (auth, pairing, session listing). Live PTY I/O (data plane) stays
//! in the shim. The iroh handler bridges between QUIC streams and
//! per-session Unix sockets via the StreamAttach protocol.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use nsh_proto::{ALPN, RemoteRequest, RemoteResponse, RemoteSessionInfo};

/// Start the iroh remote endpoint in a background thread.
pub fn spawn_iroh_endpoint(
    config: &crate::config::Config,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let secret_key = crate::runtime::remote_key::load_or_create_secret_key()?;
    let allowed_keys: HashSet<String> = config.remote.allowed_keys.iter().cloned().collect();

    let handle = std::thread::Builder::new()
        .name("nshd-iroh".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .expect("iroh tokio runtime");

            rt.block_on(async move {
                if let Err(e) = run_iroh_endpoint(secret_key, allowed_keys).await {
                    crate::runtime::global_daemon::log_daemon("iroh.error", &e.to_string());
                }
            });
        })?;

    Ok(handle)
}

async fn run_iroh_endpoint(
    secret_key: iroh::SecretKey,
    allowed_keys: HashSet<String>,
) -> anyhow::Result<()> {
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    let node_id = endpoint.id();
    crate::runtime::global_daemon::log_daemon("iroh.started", &format!("EndpointId: {node_id}"));

    let handler = NshRemoteHandler {
        allowed_keys: Arc::new(allowed_keys),
    };

    let router = iroh::protocol::Router::builder(endpoint)
        .accept(ALPN.to_vec(), handler)
        .spawn();

    // Keep router alive until shutdown signal
    // The router runs its accept loop in the background; we block here.
    // In practice, the global daemon thread will keep this alive until process exit.
    tokio::signal::ctrl_c().await.ok();
    router.shutdown().await?;
    Ok(())
}

struct NshRemoteHandler {
    allowed_keys: Arc<HashSet<String>>,
}

impl fmt::Debug for NshRemoteHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NshRemoteHandler")
            .field("allowed_keys_count", &self.allowed_keys.len())
            .finish()
    }
}

impl iroh::protocol::ProtocolHandler for NshRemoteHandler {
    async fn accept(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let remote_id = connection.remote_id();
        let remote_id_str = remote_id.to_string();

        // Auth check
        if !crate::runtime::remote_key::is_key_allowed(
            &remote_id,
            &self.allowed_keys.iter().cloned().collect::<Vec<_>>(),
        ) {
            crate::runtime::global_daemon::log_daemon("iroh.rejected", &remote_id_str);
            connection.close(1u32.into(), b"unauthorized");
            return Ok(());
        }

        crate::runtime::global_daemon::log_daemon("iroh.accepted", &remote_id_str);

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

        Ok(())
    }
}

async fn handle_remote_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    _peer_id: &str,
) -> anyhow::Result<()> {
    let request: RemoteRequest = nsh_proto::framing::read_message(&mut recv)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    match request {
        RemoteRequest::ListSessions => {
            let sessions = list_active_sessions()?;
            let response = RemoteResponse::SessionList { sessions };
            nsh_proto::framing::write_message(&mut send, &response)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }

        RemoteRequest::Attach { session_id } => {
            // Connect to the per-session daemon socket
            let socket_path = crate::daemon::daemon_socket_path(&session_id);
            let unix_stream = tokio::net::UnixStream::connect(&socket_path).await?;
            let (unix_read, mut unix_write) = unix_stream.into_split();

            // Send StreamAttach handshake (newline-delimited JSON)
            let attach_req = serde_json::json!({
                "v": crate::daemon::DAEMON_PROTOCOL_VERSION,
                "type": "stream_attach",
                "session": session_id,
            });
            let mut req_bytes = serde_json::to_vec(&attach_req)?;
            req_bytes.push(b'\n');
            tokio::io::AsyncWriteExt::write_all(&mut unix_write, &req_bytes).await?;

            // Read handshake response (newline-delimited JSON)
            let mut reader = tokio::io::BufReader::new(unix_read);
            let mut response_line = String::new();
            tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut response_line).await?;
            let handshake_resp: serde_json::Value = serde_json::from_str(&response_line)?;

            // Extract snapshot and send AttachOk to phone
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

            let mut unix_read = reader.into_inner();

            // Task 1: Unix socket (raw PTY output) -> QUIC (TerminalData)
            let output_task = tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let mut seq: u64 = 0;
                loop {
                    match tokio::io::AsyncReadExt::read(&mut unix_read, &mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let msg = RemoteResponse::TerminalData {
                                seq,
                                bytes: buf[..n].to_vec(),
                            };
                            seq += 1;
                            if nsh_proto::framing::write_message(&mut send, &msg)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            // Task 2: QUIC (RemoteRequest) -> Unix socket (length-prefixed commands)
            let input_task = tokio::spawn(async move {
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
                            let _ =
                                tokio::io::AsyncWriteExt::write_all(&mut unix_write, &len).await;
                            let _ =
                                tokio::io::AsyncWriteExt::write_all(&mut unix_write, &cmd_bytes)
                                    .await;
                        }
                        Ok(RemoteRequest::Detach) | Err(_) => {
                            let cmd = serde_json::json!({ "type": "stream_detach" });
                            let cmd_bytes = serde_json::to_vec(&cmd).unwrap();
                            let len = (cmd_bytes.len() as u32).to_be_bytes();
                            let _ =
                                tokio::io::AsyncWriteExt::write_all(&mut unix_write, &len).await;
                            let _ =
                                tokio::io::AsyncWriteExt::write_all(&mut unix_write, &cmd_bytes)
                                    .await;
                            break;
                        }
                        _ => {}
                    }
                }
            });

            tokio::select! {
                _ = output_task => {}
                _ = input_task => {}
            }
        }

        RemoteRequest::Resume {
            session_id: _,
            last_seq: _,
        } => {
            let err = RemoteResponse::Error {
                message: "resume not yet implemented; use attach".into(),
            };
            nsh_proto::framing::write_message(&mut send, &err)
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

fn list_active_sessions() -> anyhow::Result<Vec<RemoteSessionInfo>> {
    let db = crate::db::Db::open()?;
    let mut stmt = db.conn.prepare(
        "SELECT id, tty, shell, pid, label FROM sessions WHERE ended_at IS NULL",
    )?;
    let sessions = stmt
        .query_map([], |row| {
            Ok(RemoteSessionInfo {
                session_id: row.get(0)?,
                tty: row.get(1)?,
                shell: row.get(2)?,
                pid: row.get(3)?,
                label: row.get(4)?,
                last_cwd: None,
                last_command: None,
            })
        })?
        .filter_map(|r| r.ok())
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
