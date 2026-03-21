use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, AeadCore, OsRng},
};

pub fn encrypt_secret(plaintext: &str) -> anyhow::Result<String> {
    let key = get_or_create_key()?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(hex::encode(&combined))
}

pub fn decrypt_secret(hex_data: &str) -> anyhow::Result<String> {
    use aes_gcm::Nonce;

    let key = get_or_create_key()?;
    let data = hex::decode(hex_data)?;
    if data.len() < 12 {
        anyhow::bail!("encrypted data too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
    Ok(String::from_utf8(plaintext)?)
}

fn read_existing_key(key_path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    let bytes = std::fs::read(key_path)?;
    if bytes.len() < 32 {
        anyhow::bail!("vault.key is too short (expected 32 bytes)");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

fn get_or_create_key() -> anyhow::Result<[u8; 32]> {
    let key_path = crate::config::Config::nsh_dir().join("vault.key");
    if key_path.exists() {
        return read_existing_key(&key_path);
    }

    use aes_gcm::aead::rand_core::RngCore;
    let mut key = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut key);

    // Use create_new (O_EXCL) to prevent race conditions.
    // If another process created the file first, read their key instead.
    let create_result = {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)
                .map(|mut f| { let _ = f.write_all(&key); })
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)
                .map(|mut f| {
                    let _ = f.write_all(&key);
                    let mut perms = std::fs::metadata(&key_path).unwrap().permissions();
                    perms.set_readonly(true);
                    let _ = std::fs::set_permissions(&key_path, perms);
                })
        }
    };

    match create_result {
        Ok(()) => Ok(key),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process created the key first — use theirs
            read_existing_key(&key_path)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{decrypt_secret, encrypt_secret};
    use crate::test_support::EnvVarGuard;
    use serial_test::serial;

    fn temp_home_env() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().unwrap();
        let home_guard = EnvVarGuard::set("HOME", home.path());
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        (home, home_guard, xdg_config_guard, xdg_data_guard)
    }

    #[test]
    #[serial]
    fn encrypt_secret_round_trips_and_creates_vault_key() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();
        std::fs::create_dir_all(home.path().join(".nsh")).unwrap();

        let ciphertext = encrypt_secret("super-secret-value").unwrap();
        let key_path = home.path().join(".nsh").join("vault.key");

        assert!(key_path.exists());
        assert_eq!(std::fs::read(&key_path).unwrap().len(), 32);
        assert_ne!(ciphertext, "super-secret-value");
        assert_eq!(decrypt_secret(&ciphertext).unwrap(), "super-secret-value");
    }

    #[test]
    #[serial]
    fn encrypt_secret_reuses_existing_key() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();
        let nsh_dir = home.path().join(".nsh");
        let key_path = nsh_dir.join("vault.key");
        std::fs::create_dir_all(&nsh_dir).unwrap();
        let key = [7u8; 32];
        std::fs::write(&key_path, key).unwrap();

        let ciphertext = encrypt_secret("seeded-key").unwrap();

        assert_eq!(std::fs::read(&key_path).unwrap(), key);
        assert_eq!(decrypt_secret(&ciphertext).unwrap(), "seeded-key");
    }

    #[test]
    fn decrypt_secret_rejects_too_short_payload() {
        let err = decrypt_secret("aabbccdd").unwrap_err();
        assert!(err.to_string().contains("too short"));
    }
}
