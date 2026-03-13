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

#[cfg(test)]
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

fn get_or_create_key() -> anyhow::Result<[u8; 32]> {
    let key_path = crate::config::Config::nsh_dir().join("vault.key");
    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        if bytes.len() < 32 {
            anyhow::bail!("vault.key is too short (expected 32 bytes)");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[..32]);
        Ok(key)
    } else {
        use rand::{prelude::*, rng};
        let mut key = [0u8; 32];
        let mut r = rng();
        r.fill(&mut key);
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)?;
            file.write_all(&key)?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)?;
            file.write_all(&key)?;
            let mut perms = std::fs::metadata(&key_path)?.permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(&key_path, perms)?;
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("attrib")
                    .args(["+H", &key_path.to_string_lossy()])
                    .output();
            }
        }
        Ok(key)
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
