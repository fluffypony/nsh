use crate::cli::RemoteAction;

pub fn handle_remote_command(action: RemoteAction) -> anyhow::Result<()> {
    match action {
        RemoteAction::Pair => handle_pair(),
        RemoteAction::Status => handle_status(),
        RemoteAction::Revoke { node_id } => handle_revoke(&node_id),
        RemoteAction::Discover => handle_discover(),
        RemoteAction::Connect {
            node_id,
            session,
            relay_url,
        } => handle_connect(&node_id, session.as_deref(), relay_url.as_deref()),
    }
}

fn handle_pair() -> anyhow::Result<()> {
    let key = crate::remote_key::load_or_create_secret_key()?;
    let node_id = key.public();
    let node_id_str = node_id.to_string();

    let relay_url = "https://relay.iroh.network";
    let qr_payload = format!("nsh://{node_id_str}/{relay_url}");

    // Render QR code with Unicode half-block characters
    let code = qrcode::QrCode::new(qr_payload.as_bytes())?;
    render_qr_terminal(&code);

    eprintln!();
    eprintln!("EndpointId: {node_id_str}");
    eprintln!();
    eprintln!("Scan this QR code with the nsh mobile app to pair.");
    eprintln!("Or enter the EndpointId manually in the app.");
    eprintln!();
    eprintln!("Waiting for connection... (Ctrl-C to cancel)");

    // Start a temporary iroh endpoint to listen for the pairing connection.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(key)
            .alpns(vec![nsh_proto::ALPN.to_vec()])
            .bind()
            .await?;

        // Accept exactly one connection for pairing
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                eprintln!("Endpoint closed before receiving a connection.");
                return Ok(());
            }
        };
        let connecting = match incoming.accept() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to accept incoming connection: {e}");
                return Ok(());
            }
        };
        let connection = connecting.await?;
        let remote_id = connection.remote_id();
        let remote_id_str = remote_id.to_string();

        eprintln!();
        eprintln!("Incoming connection from: {remote_id_str}");

        if crate::tools::prompt_tty_confirmation(&format!(
            "Allow this device ({remote_id_str})? [y/N] "
        ))? {
            crate::config::add_remote_allowed_key(&remote_id_str)?;
            eprintln!("Device paired successfully.");
            eprintln!("Remote access is now enabled.");
        } else {
            connection.close(1u32.into(), b"rejected");
            eprintln!("Pairing rejected.");
        }

        Ok::<_, anyhow::Error>(())
    })?;

    Ok(())
}

fn handle_status() -> anyhow::Result<()> {
    let config = crate::config::Config::load().unwrap_or_default();

    eprintln!(
        "Remote access: {}",
        if config.remote.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    if let Ok(key) = crate::remote_key::load_or_create_secret_key() {
        eprintln!("EndpointId: {}", key.public());
    } else {
        eprintln!("EndpointId: not generated (run `nsh remote pair`)");
    }

    // Query daemon for live status (relay URL, peer counts)
    let mut relay_displayed = false;
    #[cfg(unix)]
    {
        if let Ok(crate::daemon::DaemonResponse::Ok {
            data: Some(d),
        }) = crate::daemon_client::send_to_global(
            &crate::daemon::DaemonRequest::RemoteStatus,
        ) {
            if let Some(relay) = d.get("relay_url").and_then(|v| v.as_str()) {
                eprintln!("Relay: {relay}");
                relay_displayed = true;
            }
            if let Some(peers) = d.get("connected_peers").and_then(|v| v.as_u64()) {
                eprintln!("Connected peers: {peers}");
            }
            if let Some(sessions) = d.get("attached_sessions").and_then(|v| v.as_u64()) {
                eprintln!("Attached sessions: {sessions}");
            }
        }
    }
    if !relay_displayed {
        eprintln!("Relay: https://relay.iroh.network (default, daemon not running)");
    }

    eprintln!("Allowed keys ({}):", config.remote.allowed_keys.len());
    for key in &config.remote.allowed_keys {
        eprintln!("  {key}");
    }

    Ok(())
}

fn handle_revoke(node_id: &str) -> anyhow::Result<()> {
    let config = crate::config::Config::load().unwrap_or_default();

    // Support prefix matching
    let matching: Vec<&String> = config
        .remote
        .allowed_keys
        .iter()
        .filter(|k| {
            k.starts_with(node_id)
                || k.strip_prefix("ed25519:")
                    .unwrap_or(k)
                    .starts_with(node_id)
        })
        .collect();

    match matching.len() {
        0 => {
            eprintln!("Key not found: {node_id}");
        }
        1 => {
            let full_key = matching[0].clone();
            if crate::config::remove_remote_allowed_key(&full_key)? {
                eprintln!("Revoked: {full_key}");
                #[cfg(unix)]
                {
                    let _ = crate::daemon_client::send_to_global(
                        &crate::daemon::DaemonRequest::RemoteRevoke {
                            node_id: full_key,
                        },
                    );
                }
            }
        }
        _ => {
            eprintln!("Ambiguous prefix '{node_id}'. Matches:");
            for key in matching {
                eprintln!("  {key}");
            }
        }
    }
    Ok(())
}

fn handle_discover() -> anyhow::Result<()> {
    let key = crate::remote_key::load_or_create_secret_key()?;
    let node_id = key.public();
    let node_id_str = node_id.to_string();

    // Compute a verification code from our node ID
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(node_id_str.as_bytes());
    let hash = hasher.finalize();
    let sas_code = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000;

    eprintln!();
    eprintln!("nsh LAN discovery mode");
    eprintln!("Verification code: {:06}", sas_code);
    eprintln!("Share this code with the connecting device.");
    eprintln!("Waiting for connections... (Ctrl-C to cancel)");

    // Start mDNS advertisement so mobile apps can discover us on LAN
    let hostname = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "nsh-host".to_string());
    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|e| anyhow::anyhow!("mDNS daemon: {e}"))?;
    let service_info = mdns_sd::ServiceInfo::new(
        "_nsh._udp.local.",
        &format!("nsh-{}", &node_id_str[..std::cmp::min(8, node_id_str.len())]),
        &format!("{hostname}.local."),
        (),   // no static IPs — enable_addr_auto populates from interfaces
        0,
        Some(std::collections::HashMap::from([
            ("node_id".to_string(), node_id_str.clone()),
        ])),
    )
    .map_err(|e| anyhow::anyhow!("mDNS service info: {e}"))?
    .enable_addr_auto();
    mdns.register(service_info)
        .map_err(|e| anyhow::anyhow!("mDNS register: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let result = rt.block_on(async {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(key)
            .alpns(vec![nsh_proto::ALPN.to_vec()])
            .bind()
            .await?;

        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => return Ok(()),
        };
        let connecting = incoming.accept()?;
        let connection = connecting.await?;
        let remote_id = connection.remote_id();
        let remote_id_str = remote_id.to_string();

        // Compute SAS from both IDs (order-independent)
        let mut hasher = Sha256::new();
        let (min, max) = if node_id_str < remote_id_str {
            (&node_id_str, &remote_id_str)
        } else {
            (&remote_id_str, &node_id_str)
        };
        hasher.update(min.as_bytes());
        hasher.update(max.as_bytes());
        let hash = hasher.finalize();
        let pair_code = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000;

        eprintln!();
        eprintln!("Incoming connection from: {remote_id_str}");
        eprintln!("Verification code (SAS): {:06}", pair_code);

        if crate::tools::prompt_tty_confirmation(
            "Does the mobile app show the exact same code? Allow this device? [y/N] ",
        )? {
            crate::config::add_remote_allowed_key(&remote_id_str)?;
            eprintln!("Device paired via LAN discovery.");
        } else {
            connection.close(1u32.into(), b"rejected");
            eprintln!("Pairing rejected.");
        }

        Ok::<_, anyhow::Error>(())
    });

    // Unregister mDNS on exit
    let _ = mdns.shutdown();

    result
}

fn handle_connect(
    node_id_input: &str,
    target_session: Option<&str>,
    relay_url_override: Option<&str>,
) -> anyhow::Result<()> {
    // Parse nsh:// URI format (same format as QR payload and mobile app)
    let (node_id_str, uri_relay) = if let Some(path) = node_id_input.strip_prefix("nsh://") {
        if let Some(slash_idx) = path.find('/') {
            (&path[..slash_idx], Some(&path[slash_idx + 1..]))
        } else {
            (path, None)
        }
    } else {
        (node_id_input, None)
    };

    let relay = relay_url_override
        .or(uri_relay)
        .unwrap_or("https://relay.iroh.network");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        // Use ephemeral key so this works without any nsh setup on the client machine
        let key = iroh::SecretKey::generate(&mut rand::rng());
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(key)
            .bind()
            .await?;

        let remote_id: iroh::EndpointId = node_id_str
            .parse()
            .map_err(|e: iroh::KeyParsingError| anyhow::anyhow!("Invalid EndpointId: {e}"))?;
        let relay_parsed: iroh::RelayUrl = relay.parse()?;
        let addr = iroh::EndpointAddr::new(remote_id).with_relay_url(relay_parsed);

        let short_id = &node_id_str[..16.min(node_id_str.len())];
        eprintln!("Connecting to {short_id}...");
        let connection = endpoint.connect(addr, nsh_proto::ALPN).await?;
        eprintln!("Connected.");

        if let Some(sid) = target_session {
            // Direct attach mode
            eprintln!("\nAttaching to {sid}. Press Ctrl-] to detach.\n");
            run_remote_pty(&connection, sid).await
        } else {
            // List sessions, let user pick
            let (mut send, mut recv) = connection.open_bi().await?;
            nsh_proto::framing::write_message(&mut send, &nsh_proto::RemoteRequest::ListSessions)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            send.finish().map_err(|e| anyhow::anyhow!("{e}"))?;

            let resp: nsh_proto::RemoteResponse =
                nsh_proto::framing::read_message(&mut recv)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

            let sessions = match resp {
                nsh_proto::RemoteResponse::SessionList { sessions } => sessions,
                nsh_proto::RemoteResponse::Error { message } => {
                    anyhow::bail!("Remote error: {message}");
                }
                _ => anyhow::bail!("Unexpected response from remote"),
            };

            if sessions.is_empty() {
                eprintln!("No active sessions on the remote node.");
                return Ok(());
            }

            eprintln!("\nActive sessions:");
            for (i, s) in sessions.iter().enumerate() {
                let label = s.label.as_deref().unwrap_or(&s.session_id);
                let cwd = s.last_cwd.as_deref().unwrap_or("");
                let cmd = s
                    .running_command
                    .as_deref()
                    .or(s.last_command.as_deref())
                    .unwrap_or("");
                eprintln!("  {}) {} ({}) {} {}", i + 1, label, s.shell, cwd, cmd);
            }

            eprint!("\nSelect session to attach (1-{}), or 0 to exit: ", sessions.len());
            std::io::Write::flush(&mut std::io::stderr())?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let choice: usize = input.trim().parse().unwrap_or(0);

            if choice == 0 || choice > sessions.len() {
                eprintln!("Exiting.");
                connection.close(0u32.into(), b"done");
                return Ok(());
            }

            let selected = &sessions[choice - 1];
            eprintln!(
                "\nAttaching to {}. Press Ctrl-] to detach.\n",
                selected.session_id
            );

            run_remote_pty(&connection, &selected.session_id).await
        }
    })
}

async fn run_remote_pty(
    connection: &iroh::endpoint::Connection,
    session_id: &str,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = connection.open_bi().await?;
    let req = nsh_proto::RemoteRequest::Attach {
        session_id: session_id.to_string(),
    };
    nsh_proto::framing::write_message(&mut send, &req)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let resp: nsh_proto::RemoteResponse = nsh_proto::framing::read_message(&mut recv)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let initial_screen = match resp {
        nsh_proto::RemoteResponse::AttachOk { initial_screen } => initial_screen,
        nsh_proto::RemoteResponse::Error { message } => {
            anyhow::bail!("Attach failed: {message}");
        }
        _ => anyhow::bail!("Unexpected response to Attach"),
    };

    // Write initial screen snapshot
    {
        use std::io::Write;
        let mut stdout = std::io::stdout();
        stdout.write_all(&initial_screen)?;
        stdout.flush()?;
    }

    // Enter raw mode with RAII cleanup
    crossterm::terminal::enable_raw_mode()?;
    struct RawGuard;
    impl Drop for RawGuard {
        fn drop(&mut self) {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
    let _guard = RawGuard;

    // Send initial terminal size
    if let Ok((cols, rows)) = crossterm::terminal::size() {
        let resize_req = nsh_proto::RemoteRequest::Resize { cols, rows };
        let _ = nsh_proto::framing::write_message(&mut send, &resize_req).await;
    }

    // Channels for stdin input and resize events
    let (tx_in, mut rx_in) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let (tx_resize, mut rx_resize) = tokio::sync::mpsc::channel::<(u16, u16)>(4);

    // Spawn blocking stdin reader thread
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx_in.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Handle SIGWINCH on Unix for resize detection
    #[cfg(unix)]
    {
        let tx_resize_sig = tx_resize.clone();
        if let Ok(mut signals) =
            signal_hook::iterator::Signals::new([signal_hook::consts::SIGWINCH])
        {
            std::thread::spawn(move || {
                for _ in signals.forever() {
                    if let Ok(size) = crossterm::terminal::size() {
                        let _ = tx_resize_sig.blocking_send(size);
                    }
                }
            });
        }
    }

    // Polling-based resize fallback (cross-platform)
    std::thread::spawn(move || {
        let mut last_size = crossterm::terminal::size().unwrap_or((80, 24));
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if let Ok(size) = crossterm::terminal::size() {
                if size != last_size {
                    last_size = size;
                    let _ = tx_resize.blocking_send(size);
                }
            }
        }
    });

    // Main I/O loop
    let mut stdout = std::io::stdout();
    loop {
        tokio::select! {
            // Remote output → local stdout
            msg = nsh_proto::framing::read_message::<nsh_proto::RemoteResponse, _>(&mut recv) => {
                match msg {
                    Ok(nsh_proto::RemoteResponse::TerminalData { bytes, .. }) => {
                        use std::io::Write;
                        if stdout.write_all(&bytes).is_err() || stdout.flush().is_err() {
                            break;
                        }
                    }
                    Ok(nsh_proto::RemoteResponse::SessionUpdate { .. }) => {
                        // Ignore session updates in PTY mode
                    }
                    Ok(nsh_proto::RemoteResponse::Detached) | Err(_) => break,
                    _ => {}
                }
            }
            // Local stdin → remote input
            Some(bytes) = rx_in.recv() => {
                // Check for Ctrl-] (0x1D) detach sequence
                if bytes.len() == 1 && bytes[0] == 0x1D {
                    let _ = nsh_proto::framing::write_message(
                        &mut send,
                        &nsh_proto::RemoteRequest::Detach,
                    ).await;
                    break;
                }
                let input_req = nsh_proto::RemoteRequest::Input { bytes };
                if nsh_proto::framing::write_message(&mut send, &input_req).await.is_err() {
                    break;
                }
            }
            // Resize events
            Some((cols, rows)) = rx_resize.recv() => {
                let resize_req = nsh_proto::RemoteRequest::Resize { cols, rows };
                let _ = nsh_proto::framing::write_message(&mut send, &resize_req).await;
            }
        }
    }

    // RawGuard drop restores terminal automatically
    Ok(())
}

/// Render a QR code using Unicode half-block characters.
fn render_qr_terminal(code: &qrcode::QrCode) {
    use qrcode::types::Color;

    let width = code.width();
    let colors = code.to_colors();

    for y in (0..width).step_by(2) {
        eprint!(" "); // left quiet zone
        for x in 0..width {
            let top = colors[y * width + x];
            let bot = if y + 1 < width {
                colors[(y + 1) * width + x]
            } else {
                Color::Light
            };
            match (top, bot) {
                (Color::Dark, Color::Dark) => eprint!("\u{2588}"),
                (Color::Dark, Color::Light) => eprint!("\u{2580}"),
                (Color::Light, Color::Dark) => eprint!("\u{2584}"),
                (Color::Light, Color::Light) => eprint!(" "),
            }
        }
        eprint!(" "); // right quiet zone
        eprintln!();
    }
}
