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
