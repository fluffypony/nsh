use reqwest::Url;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

struct ConnectivityMonitor {
    probe_url: Arc<Mutex<String>>,
    trigger_tx: mpsc::Sender<()>,
    thread_running: bool,
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
            format!("{}/models", crate::provider::bootstrap::cliproxy_base_url())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MonitorStep {
    status: ConnectivityStatus,
    next_attempt: usize,
}

fn evaluate_monitor_step<F>(current_url: &str, attempt: usize, signaled: bool, probe: F) -> MonitorStep
where
    F: FnOnce(&str) -> bool,
{
    let status = if current_url.is_empty() {
        ConnectivityStatus::Unknown
    } else if probe(current_url) {
        ConnectivityStatus::Online
    } else {
        ConnectivityStatus::Offline
    };
    let next_attempt = if matches!(status, ConnectivityStatus::Online | ConnectivityStatus::Unknown)
    {
        0
    } else if signaled {
        (attempt + 1).min(4)
    } else {
        attempt.saturating_add(1)
    };
    MonitorStep {
        status,
        next_attempt,
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
    if monitor.thread_running {
        let _ = monitor.trigger_tx.send(());
    }
}

fn monitor() -> &'static ConnectivityMonitor {
    MONITOR.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<()>();
        let probe_url = Arc::new(Mutex::new(String::new()));
        let probe_url_for_thread = Arc::clone(&probe_url);
        let thread_running = std::thread::Builder::new()
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
                    let step = evaluate_monitor_step(&current_url, attempt, signaled, probe_once);
                    STATUS.store(step.status as u8, Ordering::SeqCst);
                    attempt = step.next_attempt;
                }
            })
            .map_err(|e| {
                eprintln!("nsh: failed to spawn connectivity monitor thread: {e}");
                // Mark as permanently offline since we can't monitor
                STATUS.store(ConnectivityStatus::Unknown as u8, Ordering::SeqCst);
            })
            .is_ok();

        ConnectivityMonitor {
            probe_url,
            trigger_tx: tx,
            thread_running,
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
    if !monitor.thread_running {
        return;
    }
    if let Ok(mut probe_url) = monitor.probe_url.lock() {
        *probe_url = connectivity_probe_url(config);
    }
    STATUS.store(ConnectivityStatus::Unknown as u8, Ordering::SeqCst);
    let _ = monitor.trigger_tx.send(());
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::{
        current_probe_url, evaluate_monitor_step, is_online, schedule_for_attempt, start, status,
        ConnectivityStatus, MonitorStep, STATUS,
    };

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

        assert_eq!(status(), ConnectivityStatus::Unknown);
        assert!(!is_online());
    }

    #[test]
    fn monitor_step_resets_attempt_for_unknown_and_online_results() {
        let unknown = evaluate_monitor_step("", 3, false, |_| false);
        assert_eq!(
            unknown,
            MonitorStep {
                status: ConnectivityStatus::Unknown,
                next_attempt: 0,
            }
        );

        let online = evaluate_monitor_step("https://example.test", 5, false, |_| true);
        assert_eq!(
            online,
            MonitorStep {
                status: ConnectivityStatus::Online,
                next_attempt: 0,
            }
        );
    }

    #[test]
    fn monitor_step_increments_attempts_for_unsignaled_failures() {
        let step = evaluate_monitor_step("https://example.test", 2, false, |_| false);
        assert_eq!(
            step,
            MonitorStep {
                status: ConnectivityStatus::Offline,
                next_attempt: 3,
            }
        );
    }

    #[test]
    fn monitor_step_caps_signaled_failures_at_short_backoff() {
        let first = evaluate_monitor_step("https://example.test", 1, true, |_| false);
        assert_eq!(first.next_attempt, 2);

        let capped = evaluate_monitor_step("https://example.test", 9, true, |_| false);
        assert_eq!(
            capped,
            MonitorStep {
                status: ConnectivityStatus::Offline,
                next_attempt: 4,
            }
        );
    }
}
