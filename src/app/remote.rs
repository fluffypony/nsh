use crate::cli::RemoteAction;

pub fn handle_remote_command(action: RemoteAction) -> anyhow::Result<()> {
    match action {
        RemoteAction::Pair => handle_pair(),
        RemoteAction::Status => handle_status(),
        RemoteAction::Revoke { node_id } => handle_revoke(&node_id),
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
            }
        }
    }

    Ok(())
}

fn handle_revoke(node_id: &str) -> anyhow::Result<()> {
    if crate::config::remove_remote_allowed_key(node_id)? {
        eprintln!("Revoked: {node_id}");
        // Signal daemon to disconnect active sessions from that peer
        #[cfg(unix)]
        {
            let _ = crate::daemon_client::send_to_global(
                &crate::daemon::DaemonRequest::RemoteRevoke {
                    node_id: node_id.to_string(),
                },
            );
        }
    } else {
        eprintln!("Key not found: {node_id}");
    }
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
        eprintln!();
    }
}
