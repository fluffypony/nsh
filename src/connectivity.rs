use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, OnceLock};
use std::time::Duration;
use reqwest::Url;

static ONLINE: AtomicBool = AtomicBool::new(true);
static TRIGGER_TX: OnceLock<mpsc::Sender<()>> = OnceLock::new();

fn connectivity_probe_url(config: &crate::config::Config) -> String {
    let p = config.provider.default.as_str();
    match p {
        "openrouter" => "https://openrouter.ai/api/v1/models".into(),
        "openai" => "https://api.openai.com/v1/models".into(),
        "anthropic" => "https://api.anthropic.com/v1/messages".into(),
        "ollama" => "http://127.0.0.1:11434/api/tags".into(),
        _ if p.ends_with("_sub") => format!(
            "{}/models",
            crate::provider::openai_compat::cliproxyapi_base_url()
        ),
        _ => "https://openrouter.ai/api/v1/models".into(),
    }
}

fn schedule_for_attempt(attempt: usize) -> Duration {
    // 10s x3, 20s x3, 30s x3, 60s x3, then 300s thereafter
    let seq = [10, 10, 10, 20, 20, 20, 30, 30, 30, 60, 60, 60];
    if attempt < seq.len() {
        Duration::from_secs(seq[attempt] as u64)
    } else {
        Duration::from_secs(300)
    }
}

fn probe_once(url: &str) -> bool {
    // Use a blocking check in a dedicated thread to avoid introducing async here.
    // reqwest Client::builder().build() creates a handle; send() is async, so use a tiny blocking client via ureq fallback.
    // If ureq not available, fall back to TcpStream as a very rough check.
    // Basic TCP connectivity probe to host:port parsed from URL; if this succeeds, we assume online.
    // Fallback: treat http(s) as online if DNS resolution works quickly.
    if let Ok(u) = Url::parse(url) {
        if let Some(host) = u.host_str() {
            let port = u.port_or_known_default().unwrap_or(80);
            if let Ok(addr) = format!("{}:{}", host, port).parse::<std::net::SocketAddr>() {
                if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
                    return true;
                }
            }
            if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port)) {
                for addr in addrs {
                    if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn is_online() -> bool {
    ONLINE.load(Ordering::SeqCst)
}

pub fn trigger_immediate_check() {
    if let Some(tx) = TRIGGER_TX.get() {
        let _ = tx.send(());
    }
}

pub fn start(config: &crate::config::Config) {
    let url = connectivity_probe_url(config);
    let (tx, rx) = mpsc::channel::<()>();
    let _ = TRIGGER_TX.set(tx);
    std::thread::Builder::new()
        .name("nshd-connectivity".into())
        .spawn(move || {
            let mut attempt: usize = 0;
            loop {
                // Block for either a trigger or timeout for next scheduled probe
                let wait = schedule_for_attempt(attempt);
                let signaled = rx.recv_timeout(wait).is_ok();

                // Either due or forced, probe now
                let ok = probe_once(&url);
                ONLINE.store(ok, Ordering::SeqCst);
                if ok {
                    attempt = 0; // reset backoff on success
                } else if !signaled {
                    attempt = attempt.saturating_add(1);
                } else {
                    // If forced and still offline, only advance slightly
                    attempt = (attempt + 1).min(4);
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_schedule_progression() {
        let secs: Vec<u64> = (0..15).map(|i| schedule_for_attempt(i).as_secs()).collect();
        assert_eq!(&secs[..12], &[10,10,10,20,20,20,30,30,30,60,60,60]);
        assert!(secs[12] >= 300);
        assert!(secs[13] >= 300);
    }
}
