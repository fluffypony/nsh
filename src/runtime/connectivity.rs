use reqwest::Url;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

static ONLINE: AtomicBool = AtomicBool::new(true);

struct ConnectivityMonitor {
    probe_url: Arc<Mutex<String>>,
    trigger_tx: mpsc::Sender<()>,
}

static MONITOR: OnceLock<ConnectivityMonitor> = OnceLock::new();
static STATUS: AtomicU8 = AtomicU8::new(ConnectivityStatus::Unknown as u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ConnectivityStatus {
    Unknown = 0,
    Online = 1,
    Offline = 2,
}

fn connectivity_probe_url(config: &crate::config::Config) -> String {
    let p = config.provider.default.as_str();
    match p {
        "openrouter" => "https://openrouter.ai/api/v1/models".into(),
        "openai" => "https://api.openai.com/v1/models".into(),
        "anthropic" => "https://api.anthropic.com/v1/messages".into(),
        "ollama" => "http://127.0.0.1:11434/api/tags".into(),
        _ if p.ends_with("_sub") => {
            format!("{}/models", crate::provider_bootstrap::cliproxy_base_url())
        }
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
    // Probe inline with explicit socket/DNS timeouts to avoid leaking helper threads.
    probe_once_inner(url)
}

fn probe_once_inner(url: &str) -> bool {
    if let Ok(u) = Url::parse(url)
        && let Some(host) = u.host_str()
    {
        let port = u.port_or_known_default().unwrap_or(80);
        if let Ok(addr) = format!("{}:{}", host, port).parse::<std::net::SocketAddr>()
            && std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
        {
            return true;
        }

        // Resolve with explicit timeout to avoid blocking this monitoring thread
        // on slow or wedged system DNS resolvers.
        let resolved: Vec<std::net::SocketAddr> =
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt.block_on(async move {
                    use hickory_resolver::Resolver;
                    let resolver = match Resolver::builder_tokio() {
                        Ok(builder) => builder.build(),
                        Err(_) => return Vec::new(),
                    };
                    match tokio::time::timeout(Duration::from_secs(3), resolver.lookup_ip(host))
                        .await
                    {
                        Ok(Ok(lookup)) => lookup
                            .iter()
                            .map(|ip| std::net::SocketAddr::new(ip, port))
                            .collect(),
                        _ => Vec::new(),
                    }
                }),
                Err(_) => Vec::new(),
            };

        for addr in resolved {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
                return true;
            }
        }
    }
    false
}

pub fn is_online() -> bool {
    matches!(status(), ConnectivityStatus::Online)
}

pub fn status() -> ConnectivityStatus {
    match STATUS.load(Ordering::SeqCst) {
        1 => ConnectivityStatus::Online,
        2 => ConnectivityStatus::Offline,
        _ => ConnectivityStatus::Unknown,
    }
}

pub fn trigger_immediate_check() {
    let monitor = monitor();
    let _ = monitor.trigger_tx.send(());
}

fn monitor() -> &'static ConnectivityMonitor {
    MONITOR.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<()>();
        let probe_url = Arc::new(Mutex::new(String::new()));
        let probe_url_for_thread = Arc::clone(&probe_url);
        std::thread::Builder::new()
            .name("nshd-connectivity".into())
            .spawn(move || {
                let mut attempt: usize = 0;
                loop {
                    let wait = schedule_for_attempt(attempt);
                    let signaled = rx.recv_timeout(wait).is_ok();
                    let current_url = probe_url_for_thread
                        .lock()
                        .map(|url| url.clone())
                        .unwrap_or_default();
                    let current_status = if current_url.is_empty() {
                        ConnectivityStatus::Unknown
                    } else if probe_once(&current_url) {
                        ConnectivityStatus::Online
                    } else {
                        ConnectivityStatus::Offline
                    };
                    let ok = matches!(current_status, ConnectivityStatus::Online);
                    STATUS.store(current_status as u8, Ordering::SeqCst);
                    ONLINE.store(ok, Ordering::SeqCst);
                    if matches!(
                        current_status,
                        ConnectivityStatus::Online | ConnectivityStatus::Unknown
                    ) {
                        attempt = 0;
                    } else if !signaled {
                        attempt = attempt.saturating_add(1);
                    } else {
                        attempt = (attempt + 1).min(4);
                    }
                }
            })
            .ok();

        ConnectivityMonitor {
            probe_url,
            trigger_tx: tx,
        }
    })
}

#[cfg(test)]
fn current_probe_url() -> Option<String> {
    MONITOR
        .get()
        .and_then(|monitor| monitor.probe_url.lock().ok().map(|url| url.clone()))
}

pub fn start(config: &crate::config::Config) {
    let monitor = monitor();
    if let Ok(mut probe_url) = monitor.probe_url.lock() {
        *probe_url = connectivity_probe_url(config);
    }
    STATUS.store(ConnectivityStatus::Unknown as u8, Ordering::SeqCst);
    ONLINE.store(false, Ordering::SeqCst);
    let _ = monitor.trigger_tx.send(());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_progression() {
        let secs: Vec<u64> = (0..15).map(|i| schedule_for_attempt(i).as_secs()).collect();
        assert_eq!(
            &secs[..12],
            &[10, 10, 10, 20, 20, 20, 30, 30, 30, 60, 60, 60]
        );
        assert!(secs[12] >= 300);
        assert!(secs[13] >= 300);
    }

    #[test]
    fn test_start_updates_probe_url_when_reconfigured() {
        let mut config = crate::config::Config::default();
        config.provider.default = "openrouter".into();
        start(&config);
        assert_eq!(
            current_probe_url().as_deref(),
            Some("https://openrouter.ai/api/v1/models")
        );

        config.provider.default = "openai".into();
        start(&config);
        assert_eq!(
            current_probe_url().as_deref(),
            Some("https://api.openai.com/v1/models")
        );
    }

    #[test]
    fn test_status_defaults_to_unknown_before_start() {
        STATUS.store(ConnectivityStatus::Unknown as u8, Ordering::SeqCst);
        ONLINE.store(false, Ordering::SeqCst);

        assert_eq!(status(), ConnectivityStatus::Unknown);
        assert!(!is_online());
    }
}
