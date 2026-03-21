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
    /// Last seen sequence number for resume support.
    last_seq: Arc<Mutex<u64>>,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_biometric::init())
        .setup(|app| {
            let key = load_or_generate_mobile_key(app)?;
            let state = AppState {
                endpoint: Arc::new(Mutex::new(None)),
                secret_key: key,
                connected_node: Arc::new(Mutex::new(None)),
                active_connection: Arc::new(Mutex::new(None)),
                active_send: Arc::new(Mutex::new(None)),
                last_seq: Arc::new(Mutex::new(0)),
            };
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect_to_daemon,
            disconnect_from_daemon,
            list_sessions,
            attach_session,
            send_input,
            resize_terminal,
            detach_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
async fn connect_to_daemon(
    state: tauri::State<'_, AppState>,
    node_id: String,
    _relay_url: Option<String>,
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

    let connection = endpoint
        .connect(node_id, nsh_proto::ALPN)
        .await
        .map_err(|e| e.to_string())?;

    *state.connected_node.lock().await = Some(node_id);
    *state.active_connection.lock().await = Some(connection);

    Ok(())
}

#[tauri::command]
async fn disconnect_from_daemon(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    *state.active_send.lock().await = None;
    *state.active_connection.lock().await = None;
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

    let req = nsh_proto::RemoteRequest::Attach { session_id };
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

    // Store send stream for input/resize/detach commands
    *state.active_send.lock().await = Some(send);

    // Spawn background task to stream terminal data to frontend
    let app_clone = app.clone();
    let last_seq = Arc::clone(&state.last_seq);
    tokio::spawn(async move {
        loop {
            match nsh_proto::framing::read_message::<nsh_proto::RemoteResponse, _>(&mut recv).await
            {
                Ok(nsh_proto::RemoteResponse::TerminalData { seq, bytes }) => {
                    *last_seq.lock().await = seq;
                    let _ = app_clone.emit("terminal-data", bytes);
                }
                Ok(nsh_proto::RemoteResponse::SessionUpdate { event }) => {
                    let _ = app_clone.emit("session-update", event);
                }
                _ => break,
            }
        }
    });

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
async fn detach_session(
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut send_lock = state.active_send.lock().await;
    if let Some(send) = send_lock.as_mut() {
        let req = nsh_proto::RemoteRequest::Detach;
        let _ = nsh_proto::framing::write_message(send, &req).await;
    }
    *send_lock = None;
    Ok(())
}

fn load_or_generate_mobile_key(app: &tauri::App) -> anyhow::Result<iroh::SecretKey> {
    // In production: use iOS Keychain / Android Keystore via tauri-plugin-stronghold.
    // For development: persist in app data directory.
    let data_dir = app.path().app_data_dir()?;
    let key_path = data_dir.join("device_key");
    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        if bytes.len() != 32 {
            // Regenerate corrupt key
            let key = iroh::SecretKey::generate(&mut rand::rng());
            std::fs::write(&key_path, key.to_bytes())?;
            return Ok(key);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(iroh::SecretKey::from(key_bytes))
    } else {
        std::fs::create_dir_all(&data_dir)?;
        let key = iroh::SecretKey::generate(&mut rand::rng());
        std::fs::write(&key_path, key.to_bytes())?;
        Ok(key)
    }
}
