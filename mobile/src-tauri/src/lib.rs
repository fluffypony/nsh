use std::collections::HashMap;
use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;

struct AppState {
    endpoint: Arc<Mutex<Option<iroh::Endpoint>>>,
    secret_key: iroh::SecretKey,
    connected_node: Arc<Mutex<Option<iroh::EndpointId>>>,
    active_connection: Arc<Mutex<Option<iroh::endpoint::Connection>>>,
    /// Active QUIC send stream for the attached session (for input/resize/detach).
    active_send: Arc<Mutex<Option<iroh::endpoint::SendStream>>>,
    /// Currently attached session ID.
    active_session_id: Arc<Mutex<Option<String>>>,
    /// Per-session last-seen sequence numbers for resume support.
    last_seq_map: Arc<Mutex<HashMap<String, u64>>>,
    /// Background reader task handle — aborted before spawning a new one.
    reader_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Background datagram receiver task — aborted on disconnect.
    datagram_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_biometric::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let key = load_or_generate_mobile_key(app)?;
            let state = AppState {
                endpoint: Arc::new(Mutex::new(None)),
                secret_key: key,
                connected_node: Arc::new(Mutex::new(None)),
                active_connection: Arc::new(Mutex::new(None)),
                active_send: Arc::new(Mutex::new(None)),
                active_session_id: Arc::new(Mutex::new(None)),
                last_seq_map: Arc::new(Mutex::new(HashMap::new())),
                reader_task: Arc::new(Mutex::new(None)),
                datagram_task: Arc::new(Mutex::new(None)),
            };
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect_to_daemon,
            disconnect_from_daemon,
            list_sessions,
            attach_session,
            resume_session,
            send_input,
            resize_terminal,
            detach_session,
            send_query,
            get_session_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
async fn connect_to_daemon(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    node_id: String,
    relay_url: Option<String>,
) -> Result<(), String> {
    let mut ep_lock = state.endpoint.lock().await;
    if ep_lock.is_none() {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(state.secret_key.clone())
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        *ep_lock = Some(endpoint);
    }

    let endpoint = ep_lock.as_ref().unwrap();
    let node_id: iroh::EndpointId = node_id.parse().map_err(|e: iroh::KeyParsingError| e.to_string())?;

    // Default to the iroh relay when no relay URL is provided, so that
    // connections behind NAT still work via relay-assisted hole-punching.
    let default_relay: url::Url = "https://relay.iroh.network"
        .parse()
        .expect("valid default relay URL");
    let connection = {
        let relay_parsed = if let Some(ref relay) = relay_url {
            relay.parse::<url::Url>().map_err(|e: url::ParseError| e.to_string())?
        } else {
            default_relay
        };
        let addr = iroh::endpoint::NodeAddr::new(node_id).with_relay_url(relay_parsed);
        endpoint.connect(addr, nsh_proto::ALPN).await
    }
    .map_err(|e| e.to_string())?;

    // Abort previous datagram task if reconnecting
    if let Some(handle) = state.datagram_task.lock().await.take() {
        handle.abort();
    }

    // Spawn datagram receiver for real-time state pushes
    let conn_for_datagrams = connection.clone();
    let app_dg = app.clone();
    let dg_handle = tokio::spawn(async move {
        loop {
            match conn_for_datagrams.read_datagram().await {
                Ok(bytes) => {
                    if let Ok(update) =
                        rmp_serde::from_slice::<nsh_proto::StatePush>(&bytes)
                    {
                        let _ = app_dg.emit("state-push", &update);
                    }
                }
                Err(_) => break,
            }
        }
    });
    *state.datagram_task.lock().await = Some(dg_handle);

    *state.connected_node.lock().await = Some(node_id);
    *state.active_connection.lock().await = Some(connection);

    Ok(())
}

#[tauri::command]
async fn disconnect_from_daemon(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Abort background tasks before dropping connection
    if let Some(handle) = state.reader_task.lock().await.take() {
        handle.abort();
    }
    if let Some(handle) = state.datagram_task.lock().await.take() {
        handle.abort();
    }
    *state.active_send.lock().await = None;
    *state.active_session_id.lock().await = None;
    if let Some(conn) = state.active_connection.lock().await.take() {
        conn.close(0u32.into(), b"disconnect");
    }
    *state.connected_node.lock().await = None;
    Ok(())
}

#[tauri::command]
async fn list_sessions(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<nsh_proto::RemoteSessionInfo>, String> {
    let conn = state.active_connection.lock().await;
    let conn = conn.as_ref().ok_or("not connected")?;

    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;

    let req = nsh_proto::RemoteRequest::ListSessions;
    nsh_proto::framing::write_message(&mut send, &req)
        .await
        .map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;

    let resp: nsh_proto::RemoteResponse = nsh_proto::framing::read_message(&mut recv)
        .await
        .map_err(|e| e.to_string())?;

    match resp {
        nsh_proto::RemoteResponse::SessionList { sessions } => Ok(sessions),
        nsh_proto::RemoteResponse::Error { message } => Err(message),
        _ => Err("unexpected response".into()),
    }
}

#[tauri::command]
async fn attach_session(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    session_id: String,
) -> Result<Vec<u8>, String> {
    let conn = state.active_connection.lock().await;
    let conn = conn.as_ref().ok_or("not connected")?;

    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;

    let req = nsh_proto::RemoteRequest::Attach { session_id: session_id.clone() };
    nsh_proto::framing::write_message(&mut send, &req)
        .await
        .map_err(|e| e.to_string())?;

    let resp: nsh_proto::RemoteResponse = nsh_proto::framing::read_message(&mut recv)
        .await
        .map_err(|e| e.to_string())?;

    let initial_screen = match resp {
        nsh_proto::RemoteResponse::AttachOk { initial_screen } => initial_screen,
        nsh_proto::RemoteResponse::Error { message } => return Err(message),
        _ => return Err("unexpected response".into()),
    };

    // Store send stream and active session for input/resize/detach/resume
    *state.active_send.lock().await = Some(send);
    *state.active_session_id.lock().await = Some(session_id.clone());

    // Abort previous reader task if any
    if let Some(handle) = state.reader_task.lock().await.take() {
        handle.abort();
    }

    // Spawn background task to stream terminal data to frontend
    let app_clone = app.clone();
    let seq_map = Arc::clone(&state.last_seq_map);
    let sid = session_id;
    let handle = tokio::spawn(async move {
        loop {
            match nsh_proto::framing::read_message::<nsh_proto::RemoteResponse, _>(&mut recv).await
            {
                Ok(nsh_proto::RemoteResponse::TerminalData { seq, bytes }) => {
                    seq_map.lock().await.insert(sid.clone(), seq);
                    let _ = app_clone.emit("terminal-data", bytes);
                }
                Ok(nsh_proto::RemoteResponse::SessionUpdate { event }) => {
                    let _ = app_clone.emit("session-update", event.clone());
                    match &event {
                        nsh_proto::SessionEvent::CommandCompleted { command, exit_code, .. } => {
                            let _ = app_clone.emit("push-notification", serde_json::json!({
                                "title": if *exit_code == 0 { "Command completed" } else { "Command failed" },
                                "body": format!("{} (exit {})", command, exit_code),
                            }));
                        }
                        nsh_proto::SessionEvent::AwaitingInput { prompt, .. } => {
                            let _ = app_clone.emit("push-notification", serde_json::json!({
                                "title": "nsh: Awaiting input",
                                "body": prompt,
                            }));
                        }
                        _ => {}
                    }
                }
                _ => break,
            }
        }
    });
    *state.reader_task.lock().await = Some(handle);

    Ok(initial_screen)
}

#[tauri::command]
async fn resume_session(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    session_id: String,
) -> Result<Vec<u8>, String> {
    let conn = state.active_connection.lock().await;
    let conn = conn.as_ref().ok_or("not connected")?;

    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;

    let last_seq = state.last_seq_map.lock().await
        .get(&session_id).copied().unwrap_or(0);
    let req = nsh_proto::RemoteRequest::Resume { session_id: session_id.clone(), last_seq };
    nsh_proto::framing::write_message(&mut send, &req)
        .await
        .map_err(|e| e.to_string())?;

    let resp: nsh_proto::RemoteResponse = nsh_proto::framing::read_message(&mut recv)
        .await
        .map_err(|e| e.to_string())?;

    let initial_screen = match resp {
        nsh_proto::RemoteResponse::AttachOk { initial_screen } => initial_screen,
        nsh_proto::RemoteResponse::Error { message } => return Err(message),
        _ => return Err("unexpected response".into()),
    };

    *state.active_send.lock().await = Some(send);
    *state.active_session_id.lock().await = Some(session_id.clone());

    // Abort previous reader task if any
    if let Some(handle) = state.reader_task.lock().await.take() {
        handle.abort();
    }

    let app_clone = app.clone();
    let seq_map = Arc::clone(&state.last_seq_map);
    let sid = session_id;
    let handle = tokio::spawn(async move {
        loop {
            match nsh_proto::framing::read_message::<nsh_proto::RemoteResponse, _>(&mut recv).await
            {
                Ok(nsh_proto::RemoteResponse::TerminalData { seq, bytes }) => {
                    seq_map.lock().await.insert(sid.clone(), seq);
                    let _ = app_clone.emit("terminal-data", bytes);
                }
                Ok(nsh_proto::RemoteResponse::SessionUpdate { event }) => {
                    let _ = app_clone.emit("session-update", event.clone());
                    match &event {
                        nsh_proto::SessionEvent::CommandCompleted { command, exit_code, .. } => {
                            let _ = app_clone.emit("push-notification", serde_json::json!({
                                "title": if *exit_code == 0 { "Command completed" } else { "Command failed" },
                                "body": format!("{} (exit {})", command, exit_code),
                            }));
                        }
                        nsh_proto::SessionEvent::AwaitingInput { prompt, .. } => {
                            let _ = app_clone.emit("push-notification", serde_json::json!({
                                "title": "nsh: Awaiting input",
                                "body": prompt,
                            }));
                        }
                        _ => {}
                    }
                }
                _ => break,
            }
        }
    });
    *state.reader_task.lock().await = Some(handle);

    Ok(initial_screen)
}

#[tauri::command]
async fn send_input(
    state: tauri::State<'_, AppState>,
    bytes: Vec<u8>,
) -> Result<(), String> {
    let mut send_lock = state.active_send.lock().await;
    let send = send_lock.as_mut().ok_or("no active session")?;
    let req = nsh_proto::RemoteRequest::Input { bytes };
    nsh_proto::framing::write_message(send, &req)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn resize_terminal(
    state: tauri::State<'_, AppState>,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let mut send_lock = state.active_send.lock().await;
    let send = send_lock.as_mut().ok_or("no active session")?;
    let req = nsh_proto::RemoteRequest::Resize { cols, rows };
    nsh_proto::framing::write_message(send, &req)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn send_query(
    state: tauri::State<'_, AppState>,
    session_id: String,
    query: String,
    think: bool,
) -> Result<String, String> {
    let conn = state.active_connection.lock().await;
    let conn = conn.as_ref().ok_or("not connected")?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;

    let req = nsh_proto::RemoteRequest::Query {
        query,
        session_id,
        think,
        private: false,
    };
    nsh_proto::framing::write_message(&mut send, &req)
        .await
        .map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;

    let resp: nsh_proto::RemoteResponse = nsh_proto::framing::read_message(&mut recv)
        .await
        .map_err(|e| e.to_string())?;

    match resp {
        nsh_proto::RemoteResponse::QueryComplete { response } => Ok(response),
        nsh_proto::RemoteResponse::QueryError { message } => Err(message),
        nsh_proto::RemoteResponse::Error { message } => Err(message),
        _ => Err("unexpected response".into()),
    }
}

#[tauri::command]
async fn get_session_history(
    state: tauri::State<'_, AppState>,
    session_id: String,
    limit: u64,
) -> Result<Vec<nsh_proto::SessionHistoryEntry>, String> {
    let conn = state.active_connection.lock().await;
    let conn = conn.as_ref().ok_or("not connected")?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;

    let req = nsh_proto::RemoteRequest::SessionHistory { session_id, limit };
    nsh_proto::framing::write_message(&mut send, &req)
        .await
        .map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;

    let resp: nsh_proto::RemoteResponse = nsh_proto::framing::read_message(&mut recv)
        .await
        .map_err(|e| e.to_string())?;

    match resp {
        nsh_proto::RemoteResponse::SessionHistory { entries } => Ok(entries),
        nsh_proto::RemoteResponse::Error { message } => Err(message),
        _ => Err("unexpected response".into()),
    }
}

#[tauri::command]
async fn detach_session(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Abort reader task BEFORE clearing active_send to avoid races
    if let Some(handle) = state.reader_task.lock().await.take() {
        handle.abort();
    }
    let mut send_lock = state.active_send.lock().await;
    if let Some(send) = send_lock.as_mut() {
        let req = nsh_proto::RemoteRequest::Detach;
        let _ = nsh_proto::framing::write_message(send, &req).await;
    }
    *send_lock = None;
    // Keep last_seq_map intact across detach/resume so sequence numbers track correctly
    *state.active_session_id.lock().await = None;
    Ok(())
}

// SECURITY: File-based key storage is development-only.
// Production builds MUST use tauri-plugin-stronghold (iOS Keychain / Android Keystore).
#[cfg(all(not(debug_assertions), not(feature = "insecure-dev-keys")))]
compile_error!(
    "Production builds must use secure key storage (tauri-plugin-stronghold \
     for iOS Keychain / Android Keystore). Replace load_or_generate_mobile_key \
     with a Stronghold-backed implementation before shipping. \
     Pass --features insecure-dev-keys for development release builds."
);

fn load_or_generate_mobile_key(app: &tauri::App) -> anyhow::Result<iroh::SecretKey> {
    let data_dir = app.path().app_data_dir()?;
    let key_path = data_dir.join("device_key");
    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        if bytes.len() != 32 {
            // Regenerate corrupt key
            let key = iroh::SecretKey::generate(&mut rand::rng());
            write_key_file(&key_path, &key.to_bytes())?;
            return Ok(key);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(iroh::SecretKey::from(key_bytes))
    } else {
        std::fs::create_dir_all(&data_dir)?;
        let key = iroh::SecretKey::generate(&mut rand::rng());
        write_key_file(&key_path, &key.to_bytes())?;
        Ok(key)
    }
}

fn write_key_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
