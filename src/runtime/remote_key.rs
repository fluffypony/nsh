use std::path::PathBuf;

pub fn remote_key_path() -> PathBuf {
    crate::config::Config::nsh_dir().join("remote_key")
}

pub fn load_or_create_secret_key() -> anyhow::Result<iroh::SecretKey> {
    let path = remote_key_path();
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "~/.nsh/remote_key has invalid length (expected 32, got {}). \
                 Delete it and run `nsh remote pair` to regenerate.",
                bytes.len()
            );
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(iroh::SecretKey::from(key_bytes))
    } else {
        let key = iroh::SecretKey::generate(&mut rand::rng());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(&key.to_bytes())?;
        }
        #[cfg(not(unix))]
        std::fs::write(&path, key.to_bytes())?;

        Ok(key)
    }
}

/// Check if a remote peer's EndpointId is in the allowed list.
pub fn is_key_allowed(node_id: &iroh::EndpointId, allowed_keys: &[String]) -> bool {
    let id_str = node_id.to_string();
    allowed_keys.iter().any(|k| {
        let normalized = k.strip_prefix("ed25519:").unwrap_or(k);
        normalized == id_str
    })
}
