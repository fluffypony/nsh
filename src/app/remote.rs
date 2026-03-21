use crate::cli::RemoteAction;

pub fn handle_remote_command(action: RemoteAction) -> anyhow::Result<()> {
    match action {
        RemoteAction::Pair => handle_pair(),
        RemoteAction::Status => handle_status(),
        RemoteAction::Revoke { node_id } => handle_revoke(&node_id),
        RemoteAction::Discover => handle_discover(),
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

    eprintln!("Relay: https://relay.iroh.network");
    eprintln!("Allowed keys ({}):", config.remote.allowed_keys.len());
    for key in &config.remote.allowed_keys {
        eprintln!("  {key}");
    }

    // Query daemon for live status
    #[cfg(unix)]
    {
        if let Ok(resp) = crate::daemon_client::send_to_global(
            &crate::daemon::DaemonRequest::RemoteStatus,
        ) {
            if let crate::daemon::DaemonResponse::Ok {
                data: Some(d),
            } = resp
            {
                if let Some(peers) = d.get("connected_peers").and_then(|v| v.as_u64()) {
                    eprintln!("Connected peers: {peers}");
                }
                if let Some(sessions) = d.get("attached_sessions").and_then(|v| v.as_u64()) {
                    eprintln!("Attached sessions: {sessions}");
                }
            }
        }
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
        "",
        0,
        Some(std::collections::HashMap::from([
            ("node_id".to_string(), node_id_str.clone()),
        ])),
    )
    .map_err(|e| anyhow::anyhow!("mDNS service info: {e}"))?;
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
