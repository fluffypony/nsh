use std::io::Write;

pub fn audit_log(session_id: &str, query: &str, tool: &str, response: &str, risk: &str) {
    let path = crate::config::Config::nsh_dir().join("audit.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "session": session_id,
            "query": query,
            "tool": tool,
            "response": response,
            "risk": risk,
        });
        let _ = writeln!(f, "{entry}");
    }
    rotate_audit_log();
}

pub fn rotate_audit_log() {
    let log_path = crate::config::Config::nsh_dir().join("audit.log");
    let Ok(meta) = std::fs::metadata(&log_path) else { return };
    if meta.len() <= 15_000_000 {
        return;
    }

    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let archive_name = format!("audit_{ts}.log.gz");
    let archive_path = crate::config::Config::nsh_dir().join(&archive_name);

    let Ok(input_file) = std::fs::File::open(&log_path) else { return };
    let Ok(output_file) = std::fs::File::create(&archive_path) else { return };
    let mut encoder = flate2::write::GzEncoder::new(output_file, flate2::Compression::default());
    let mut reader = std::io::BufReader::new(input_file);
    if std::io::copy(&mut reader, &mut encoder).is_err() { return; }
    if encoder.finish().is_err() { return; }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o600));
    }

    let _ = std::fs::write(&log_path, "");

    cleanup_old_archives();
}

fn cleanup_old_archives() {
    let dir = crate::config::Config::nsh_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    let mut archives: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("audit_") && name.ends_with(".log.gz")
        })
        .map(|e| e.path())
        .collect();
    archives.sort();
    while archives.len() > 5 {
        let _ = std::fs::remove_file(archives.remove(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup_old_archives_limit() {
        cleanup_old_archives();
    }
}
