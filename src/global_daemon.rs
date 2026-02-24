use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::daemon::{DaemonRequest, DaemonResponse};

// ── Memory background task types ──────────────────────
enum MemoryTask {
    FlushIngestion,
    IngestBatch {
        events: Vec<crate::memory::types::ShellEvent>,
    },
    RunReflection,
    BootstrapScan,
}

type MemoryTaskSender = mpsc::Sender<MemoryTask>;

// In-memory active session tracking for per-session notifications
#[derive(Clone)]
pub struct SessionInfo {
    last_seen: Instant,
    tty: Option<String>,
    shell: Option<String>,
    pid: Option<i64>,
}
type ActiveSessions = std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, SessionInfo>>>;

fn log_daemon(action: &str, payload: &str) {
    crate::debug_io::daemon_log("daemon.log", action, payload);
}

#[cfg(unix)]
fn pid_alive(pid: i64) -> bool {
    if pid <= 0 { return false; }
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn tty_sanitized(tty: &str) -> String {
    tty.replace('/', "_")
}

/// Cleanup per-TTY/session artifacts when a session ends or is pruned.
fn cleanup_session_artifacts(session_id: &str, info: &SessionInfo) {
    let dir = crate::config::Config::nsh_dir();
    // Remove per-session message file if any
    let _ = std::fs::remove_file(dir.join(format!("nsh_msg_{}", session_id)));
    // Remove per-TTY CWD file if we know TTY
    if let Some(tty) = &info.tty {
        let safe = tty_sanitized(tty);
        let _ = std::fs::remove_file(dir.join(format!("cwd_{}", safe)));
    }
}

pub fn run_global_daemon() -> anyhow::Result<()> {
    log_daemon("server.lifecycle", "starting global daemon");
    // Restart cooldown: if we just restarted moments ago, wait a bit to avoid flapping
    let restart_marker = crate::config::Config::nsh_dir().join("nshd-restart-at");
    if let Ok(content) = std::fs::read_to_string(&restart_marker) {
        if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(content.trim()) {
            let age = chrono::Utc::now().signed_duration_since(ts);
            if age.num_seconds() < 5 {
                let wait = 5 - age.num_seconds();
                std::thread::sleep(Duration::from_secs(wait as u64));
            }
        }
        let _ = std::fs::remove_file(&restart_marker);
    }
    let lock_path = crate::daemon::global_daemon_lock_path();
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            log_daemon(
                "server.lifecycle",
                "another daemon already holds lock; exiting",
            );
            return Ok(());
        }
    }

    #[cfg(unix)]
    unsafe {
        libc::setsid();
    }

    let pid_path = crate::daemon::global_daemon_pid_path();
    std::fs::write(&pid_path, std::process::id().to_string())?;

    let socket_path = crate::daemon::global_daemon_socket_path();
    let _ = std::fs::remove_file(&socket_path);

    #[cfg(unix)]
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;

    let write_db = crate::db::Db::open()?;

    let _ = write_db.cleanup_orphaned_sessions();
    crate::history_import::import_if_needed(&write_db);
    let _ = write_db.backfill_command_entities_if_needed();

    let read_dbs: Vec<crate::db::Db> = (0..3)
        .filter_map(|_| crate::db::Db::open_readonly().ok())
        .collect();

    if read_dbs.is_empty() {
        anyhow::bail!("nshd: failed to open any read-only DB connections");
    }

    // ── Memory system ──────────────────────────────────
    let config = crate::config::Config::load().unwrap_or_default();
    let db_path = crate::config::Config::nsh_dir().join("nsh.db");
    let memory = Arc::new(
        crate::memory::MemorySystem::open(config.memory.clone(), db_path).unwrap_or_else(|e| {
            log_daemon("memory.init.error", &e.to_string());
            // Fall back to in-memory (will lose data on restart, but won't crash)
            crate::memory::MemorySystem::open(config.memory.clone(), ":memory:".into())
                .expect("in-memory MemorySystem must succeed")
        }),
    );

    // Start connectivity monitor (best-effort)
    crate::connectivity::start(&config);

    // Background async thread for LLM-dependent memory operations
    let (memory_tx, memory_rx) = mpsc::channel::<MemoryTask>();
    let memory_for_thread = Arc::clone(&memory);
    let config_for_memory = config.clone();
    let memory_thread = std::thread::Builder::new()
        .name("nshd-memory".into())
        .spawn(move || {
            run_memory_thread(memory_for_thread, memory_rx, config_for_memory);
        })?;

    let (write_tx, write_rx) = mpsc::channel::<WriteCommand>();
    let (read_tx, read_rx) = mpsc::channel::<ReadCommand>();
    let read_rx = Arc::new(Mutex::new(read_rx));

    let memory_for_writer = Arc::clone(&memory);
    let memory_tx_for_writer = memory_tx.clone();
    let write_thread = std::thread::Builder::new()
        .name("nshd-writer".into())
        .spawn(move || {
            run_write_thread(write_db, write_rx, memory_for_writer, memory_tx_for_writer);
        })?;

    let read_threads: Vec<_> = read_dbs
        .into_iter()
        .enumerate()
        .map(|(i, db)| {
            let rx = Arc::clone(&read_rx);
            let mem = Arc::clone(&memory);
            std::thread::Builder::new()
                .name(format!("nshd-reader-{i}"))
                .spawn(move || {
                    run_read_thread(db, rx, mem);
                })
                .unwrap()
        })
        .collect();

    // Startup maintenance tasks (wire MemorySystem methods to avoid dead code and keep system tidy)
    if !memory.has_bootstrapped() {
        let _ = memory_tx.send(MemoryTask::BootstrapScan);
    }
    if memory.should_run_decay() {
        let _ = memory_tx.send(MemoryTask::FlushIngestion);
        let _ = send_memory_decay_once(&memory);
    }
    if memory.should_run_reflection() {
        let _ = memory_tx.send(MemoryTask::RunReflection);
    }

    let active_conns = Arc::new(AtomicUsize::new(0));
    let active_sessions: ActiveSessions = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
    const MAX_GLOBAL_CONNS: usize = 32;

    let last_activity = Arc::new(Mutex::new(Instant::now()));

    // Shared restart flag (SIGHUP and monitor thread can set this)
    let restart_pending = Arc::new(AtomicBool::new(false));

    // Spawn system monitor thread — samples CPU/memory every 10 seconds. Also watches binary mtime.
    {
        let monitor_exe_path = std::env::current_exe().ok();
        let monitor_initial_mtime = monitor_exe_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok());
        let restart_flag = Arc::clone(&restart_pending);
        let sessions_for_monitor = std::sync::Arc::clone(&active_sessions);
        std::thread::spawn(move || {
            let mut last_skill_pull = std::time::Instant::now();
            let mut last_prune = std::time::Instant::now();
            loop {
                let _ = crate::context::sample_volatile_info();
                let _ = crate::context::get_semi_dynamic_info();
                // Periodically update skills by pulling latest changes (hourly)
                if last_skill_pull.elapsed() > std::time::Duration::from_secs(3600) {
                    last_skill_pull = std::time::Instant::now();
                    if let Some(skills_dir) = dirs::home_dir().map(|h| h.join(".nsh").join("skills")) {
                        if skills_dir.is_dir() {
                            if let Ok(entries) = std::fs::read_dir(&skills_dir) {
                                for entry in entries.flatten() {
                                    let path = entry.path();
                                    if path.join(".git").is_dir() {
                                        let _ = std::process::Command::new("git")
                                            .args(["-C", path.to_string_lossy().as_ref(), "pull", "--ff-only", "-q"]) 
                                            .status();
                                    }
                                }
                            }
                        }
                    }
                }
                // Prune inactive sessions every 5 minutes
                if last_prune.elapsed() > std::time::Duration::from_secs(300) {
                    last_prune = std::time::Instant::now();
                    let cutoff = Instant::now() - Duration::from_secs(600);
                    if let Ok(mut guard) = sessions_for_monitor.write() {
                        // Collect stale before retaining for cleanup
                        let stale: Vec<(String, SessionInfo)> = guard
                            .iter()
                            .filter(|(_, info)| info.last_seen < cutoff)
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        guard.retain(|_, info| info.last_seen >= cutoff);
                        drop(guard);
                        for (sid, info) in stale {
                            cleanup_session_artifacts(&sid, &info);
                        }
                    }
                }
                if let Some(ref path) = monitor_exe_path {
                    if let Ok(meta) = std::fs::metadata(path) {
                        if let Ok(mtime) = meta.modified() {
                            if Some(mtime) != monitor_initial_mtime {
                                tracing::info!(
                                    "nshd: binary updated on disk, scheduling graceful restart"
                                );
                                restart_flag.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(10));
            }
        });
    }

    // ── Hourly update checker for sidecar ─────────────────────────────────
    {
        std::thread::Builder::new()
            .name("nshd-update-checker".into())
            .spawn(|| loop {
                std::thread::sleep(Duration::from_secs(3600));
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build();
                let mut last_status = String::from("unknown");
                let mut last_version: Option<String> = None;
                if let Ok(rt) = rt {
                    let (status, version_opt) = rt.block_on(async move {
                        match crate::cliproxyapi::check_for_update().await {
                            Ok(Some((url, version))) => {
                                match crate::cliproxyapi::download_and_install(&url, &version).await {
                                    Ok(_) => {
                                        let _ = crate::cliproxyapi::stop_sidecar();
                                        let _ = crate::cliproxyapi::ensure_running();
                                        ("updated".to_string(), Some(version))
                                    }
                                    Err(_) => ("failed".to_string(), Some(version)),
                                }
                            }
                            Ok(None) => (
                                "up_to_date".to_string(),
                                std::fs::read_to_string(crate::cliproxyapi::version_file()).ok(),
                            ),
                            Err(_) => (
                                "error".to_string(),
                                std::fs::read_to_string(crate::cliproxyapi::version_file()).ok(),
                            ),
                        }
                    });
                    last_status = status;
                    last_version = version_opt;
                }

                // Record results in DB meta if possible, avoiding any migrations
                if let Ok(db) = crate::db::Db::open() {
                    let now = chrono::Utc::now().to_rfc3339();
                    let _ = db.set_meta("cliproxyapi_last_update_check", &now);
                    let _ = db.set_meta("cliproxyapi_last_update_status", &last_status);
                    if let Some(v) = last_version {
                        let _ = db.set_meta("cliproxyapi_installed_version", v.trim());
                    }
                }
            })?;
    }

    #[cfg(unix)]
    {
        listener.set_nonblocking(true)?;
        // Debounce restarts triggered via SIGHUP or monitor
        static LAST_RESTART_EPOCH: AtomicU64 = AtomicU64::new(0);

        // Handle SIGHUP for graceful restart
        {
            let hup_flag = Arc::clone(&restart_pending);
            signal_hook::flag::register(signal_hook::consts::SIGHUP, hup_flag)?;
        }

        let mut restart_requested_at: Option<Instant> = None;

        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    if !check_peer_uid(&stream) {
                        continue;
                    }
                    if active_conns.load(Ordering::Relaxed) >= MAX_GLOBAL_CONNS {
                        let _ =
                            write_response(&stream, &DaemonResponse::error("too many connections"));
                        continue;
                    }
                    active_conns.fetch_add(1, Ordering::Relaxed);
                    *last_activity.lock().unwrap() = Instant::now();
                    let wt = write_tx.clone();
                    let rt = read_tx.clone();
                    let ac = Arc::clone(&active_conns);
                    let la = Arc::clone(&last_activity);
                    let sessions_ref = std::sync::Arc::clone(&active_sessions);
                    std::thread::spawn(move || {
                        // Track sessions seen in this connection when appropriate
                        // (session IDs are inside request messages; handle_global_connection will process them)
                        handle_global_connection(stream, wt, rt, sessions_ref);
                        *la.lock().unwrap() = Instant::now();
                        ac.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let idle = last_activity.lock().unwrap().elapsed();
                    if idle > Duration::from_secs(300) {
                        tracing::info!("nshd: idle timeout, shutting down");
                        log_daemon("server.lifecycle", "idle timeout reached; shutting down");
                        break;
                    }
                    // Graceful restart: drain with timeout (10s)
                    if restart_pending.load(Ordering::Relaxed) {
                        // Debounce: ignore restart requests if a restart occurred <30s ago
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let last = LAST_RESTART_EPOCH.load(Ordering::Relaxed);
                        if now.saturating_sub(last) < 30 {
                            // Too soon; clear flag and continue
                            restart_pending.store(false, Ordering::Relaxed);
                            std::thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                        if restart_requested_at.is_none() {
                            restart_requested_at = Some(Instant::now());
                            log_daemon(
                                "server.lifecycle",
                                "restart requested, draining connections...",
                            );
                            // Let in-flight requests begin to drain
                            std::thread::sleep(Duration::from_secs(2));
                            // Record last restart request epoch for debounce
                            LAST_RESTART_EPOCH.store(now, Ordering::Relaxed);
                        }
                        let drained = active_conns.load(Ordering::Relaxed) == 0;
                        let timed_out = restart_requested_at
                            .map(|t| t.elapsed() > Duration::from_secs(10))
                            .unwrap_or(false);
                        if drained || timed_out {
                            if !drained {
                                log_daemon(
                                    "server.lifecycle",
                                    "drain timeout (10s), force exiting for restart",
                                );
                            } else {
                                log_daemon(
                                    "server.lifecycle",
                                    "all connections drained, exiting for restart",
                                );
                            }
                            break;
                        }
                    }
                    // Also check for the restart marker file from clients
                    let restart_marker =
                        crate::config::Config::nsh_dir().join("nshd_restart_pending");
                    if restart_marker.exists() {
                        log_daemon("server.lifecycle", "restart marker detected, shutting down");
                        restart_pending.store(true, std::sync::atomic::Ordering::Relaxed);
                        // Notify only live/active sessions about hook updates (best effort)
                        let dir = crate::config::Config::nsh_dir();
                        if let Ok(guard) = active_sessions.read() {
                            for (sid, info) in guard.iter() {
                                // Skip dead PIDs where available
                                #[cfg(unix)]
                                {
                                    if let Some(pid) = info.pid { if !pid_alive(pid) { continue; } }
                                }
                                // Skip messages for missing TTYs
                                if let Some(tty) = &info.tty {
                                    if !std::path::Path::new(tty).exists() { continue; }
                                }
                                // Tailor message by shell (minor copy variation)
                                let msg = match info.shell.as_deref() {
                                    Some("zsh") => "hooks_updated: zsh will auto-reload when idle\n",
                                    Some("bash") => "hooks_updated: bash will refresh hooks on next prompt\n",
                                    Some("fish") => "hooks_updated: fish auto-reloads hooks\n",
                                    _ => "hooks_updated\n",
                                };
                                let _ = std::fs::write(dir.join(format!("nsh_msg_{}", sid)), msg);
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    tracing::warn!("nshd: accept error: {e}");
                    log_daemon("server.accept.error", &e.to_string());
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    drop(write_tx);
    drop(read_tx);
    drop(memory_tx);
    let _ = write_thread.join();
    let _ = memory_thread.join();
    for t in read_threads {
        let _ = t.join();
    }
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&pid_path);
    log_daemon("server.lifecycle", "stopped global daemon");
    drop(lock_file);

    // Start connectivity monitor in background (non-fatal if it fails to spawn)
    crate::connectivity::start(&config);

    // Re-exec if restart was requested, so the new daemon starts immediately
    if restart_pending.load(Ordering::Relaxed) {
        let args: Vec<String> = std::env::args().collect();
        let core_path = crate::config::Config::nsh_dir()
            .join("bin")
            .join("nsh-core");
        let target = if core_path.exists() {
            core_path
        } else if let Ok(exe) = std::env::current_exe() {
            exe
        } else {
            return Ok(());
        };
        // Write restart marker for startup cooldown
        let _ = std::fs::write(&restart_marker, chrono::Utc::now().to_rfc3339());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(&target).args(&args[1..]).exec();
            tracing::info!("nshd re-exec failed: {err}");
        }
    }

    Ok(())
}

struct WriteCommand {
    request: DaemonRequest,
    reply: mpsc::Sender<DaemonResponse>,
}

struct ReadCommand {
    request: DaemonRequest,
    reply: mpsc::Sender<DaemonResponse>,
}

fn run_write_thread(
    db: crate::db::Db,
    rx: mpsc::Receiver<WriteCommand>,
    memory: Arc<crate::memory::MemorySystem>,
    memory_tx: MemoryTaskSender,
) {
    // Track last known project root per session for ProjectSwitch detection
    let mut session_project_roots: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    loop {
        let first = match rx.recv() {
            Ok(cmd) => cmd,
            Err(_) => break,
        };

        let mut batch = vec![first];
        loop {
            if batch.len() >= 10 {
                break;
            }
            match rx.try_recv() {
                Ok(cmd) => batch.push(cmd),
                Err(_) => break,
            }
        }

        if batch.len() > 1 {
            if let Ok(()) = db.conn_execute_batch("BEGIN IMMEDIATE;") {
                let mut pending: Vec<(mpsc::Sender<DaemonResponse>, DaemonResponse)> = Vec::new();
                for cmd in batch {
                    let resp = execute_write(
                        &db,
                        cmd.request,
                        &memory,
                        &memory_tx,
                        &mut session_project_roots,
                    );
                    pending.push((cmd.reply, resp));
                }
                if db.conn_execute_batch("COMMIT;").is_err() {
                    let _ = db.conn_execute_batch("ROLLBACK;");
                    for (reply, _) in pending {
                        let _ = reply.send(DaemonResponse::error("transaction commit failed"));
                    }
                } else {
                    for (reply, resp) in pending {
                        let _ = reply.send(resp);
                    }
                }
            } else {
                for cmd in batch {
                    let resp = execute_write(
                        &db,
                        cmd.request,
                        &memory,
                        &memory_tx,
                        &mut session_project_roots,
                    );
                    let _ = cmd.reply.send(resp);
                }
            }
        } else {
            let cmd = batch.into_iter().next().unwrap();
            let resp = execute_write(
                &db,
                cmd.request,
                &memory,
                &memory_tx,
                &mut session_project_roots,
            );
            let _ = cmd.reply.send(resp);
        }
    }
}

fn run_memory_thread(
    memory: Arc<crate::memory::MemorySystem>,
    rx: mpsc::Receiver<MemoryTask>,
    config: crate::config::Config,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log_daemon(
                "memory.thread.error",
                &format!("failed to create tokio runtime: {e}"),
            );
            return;
        }
    };

    let llm = crate::memory::llm_adapter::ProviderLlmClient::new(&config);

    // Process tasks: recv() blocks this thread until a task arrives (or channel closes).
    // Each task is executed via block_on for the async LLM calls.
    while let Ok(task) = rx.recv() {
        match task {
            MemoryTask::FlushIngestion => {
                rt.block_on(async {
                    match tokio::time::timeout(std::time::Duration::from_secs(120), memory.flush_ingestion(&llm)).await {
                        Ok(Err(e)) => {
                            tracing::debug!("memory flush_ingestion error: {e}");
                            log_daemon("memory.flush.error", &e.to_string());
                        }
                        Err(_) => {
                            tracing::warn!("memory flush_ingestion timed out after 120s");
                        }
                        _ => {}
                    }
                });
            }
            MemoryTask::IngestBatch { events } => {
                rt.block_on(async {
                    match tokio::time::timeout(std::time::Duration::from_secs(120), memory.ingest_batch(&events, &llm)).await {
                        Ok(Err(e)) => {
                            tracing::debug!("memory ingest_batch error: {e}");
                            log_daemon("memory.ingest.error", &e.to_string());
                        }
                        Err(_) => {
                            tracing::warn!("memory ingest_batch timed out after 120s");
                        }
                        _ => {}
                    }
                });
            }
            MemoryTask::RunReflection => {
                rt.block_on(async {
                    match tokio::time::timeout(std::time::Duration::from_secs(120), memory.run_reflection(&llm)).await {
                        Ok(Err(e)) => {
                            tracing::debug!("memory run_reflection error: {e}");
                            log_daemon("memory.reflection.error", &e.to_string());
                        }
                        Err(_) => {
                            tracing::warn!("memory run_reflection timed out after 120s");
                        }
                        _ => {}
                    }
                });
            }
            MemoryTask::BootstrapScan => {
                rt.block_on(async {
                    match tokio::time::timeout(std::time::Duration::from_secs(120), memory.bootstrap_scan(&llm)).await {
                        Ok(Err(e)) => {
                            tracing::debug!("memory bootstrap_scan error: {e}");
                            log_daemon("memory.bootstrap.error", &e.to_string());
                        }
                        Err(_) => {
                            tracing::warn!("memory bootstrap_scan timed out after 120s");
                        }
                        _ => {}
                    }
                });
            }
        }
    }

    log_daemon("memory.thread", "memory thread exiting");
}

fn send_memory_decay_once(memory: &crate::memory::MemorySystem) -> Result<(), ()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    rt.block_on(async {
        let _ = memory.run_decay();
    });
    Ok(())
}

fn execute_write(
    db: &crate::db::Db,
    request: DaemonRequest,
    memory: &crate::memory::MemorySystem,
    memory_tx: &MemoryTaskSender,
    session_project_roots: &mut std::collections::HashMap<String, String>,
) -> DaemonResponse {
    let req_dbg = format!("{request:?}");
    log_daemon("server.execute_write.request", &req_dbg);
    match request {
        DaemonRequest::Restart => {
            // Handled in accept loop via marker file; acknowledge
            let marker = crate::config::Config::nsh_dir().join("nshd_restart_pending");
            let _ = std::fs::write(&marker, "");
            DaemonResponse::ok()
        }
        DaemonRequest::GetVersion => DaemonResponse::ok_with_data(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "build_version": env!("NSH_BUILD_VERSION"),
            "build_fingerprint": env!("NSH_BUILD_FINGERPRINT"),
            "protocol_version": crate::daemon::DAEMON_PROTOCOL_VERSION,
        })),
        DaemonRequest::Record {
            session,
            command,
            cwd,
            exit_code,
            started_at,
            tty,
            pid,
            shell,
            duration_ms,
            output,
        } => {
            match db.insert_command(
                &session,
                &command,
                &cwd,
                Some(exit_code),
                &started_at,
                duration_ms,
                output.as_deref(),
                &tty,
                &shell,
                pid,
            ) {
                Ok(id) => {
                    if command.starts_with("ssh ") || command == "ssh" {
                        let _ = db.backfill_command_entities_if_needed();
                    }
                    let output_text = output.as_deref().unwrap_or("");
                    if let Some(trivial) =
                        crate::summary::trivial_summary(&command, exit_code, output_text)
                    {
                        let _ = db.update_summary(id, &trivial);
                    }
                    // Detect project switches via CWD change
                    if let Some(project_root) = detect_project_root_fast(&cwd) {
                        let switched = match session_project_roots.get(&session) {
                            Some(prev) => prev != &project_root,
                            None => true, // first command in session, record but don't emit event
                        };
                        let is_first = !session_project_roots.contains_key(&session);
                        session_project_roots.insert(session.clone(), project_root.clone());
                        if switched && !is_first {
                            let event = crate::memory::types::ShellEvent {
                                event_type: crate::memory::types::ShellEventType::ProjectSwitch,
                                command: None,
                                output: None,
                                exit_code: None,
                                working_dir: Some(cwd.clone()),
                                session_id: Some(session.clone()),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                git_context: None,
                                instruction: None,
                                file_path: None,
                            };
                            memory.record_event(event);
                        }
                    }

                    if let Ok(Some((conv_id, suggested_cmd))) =
                        db.find_pending_conversation(&session)
                    {
                        if command.trim() == suggested_cmd.trim() {
                            let snippet = crate::util::truncate(output_text, 500);
                            let snippet_ref = if snippet.is_empty() {
                                None
                            } else {
                                Some(snippet.as_str())
                            };
                            let _ = db.update_conversation_result(conv_id, exit_code, snippet_ref);
                        } else {
                            let correction = format!(
                                "User ran different command: {}",
                                crate::util::truncate(&command, 200)
                            );
                            let _ = db.update_conversation_result(
                                conv_id,
                                exit_code,
                                Some(&correction),
                            );
                        }
                    }

                    // ── Memory: record generic command execution ─────────────
                    // Skip internal project switch marker; we already emit a dedicated ProjectSwitch event above.
                    if command != "__nsh_project_switch" {
                        // Try to capture the per-command output from the per-session capture engine if present.
                        let mut captured_output: Option<String> = None;
                        #[cfg(unix)]
                        {
                            if !tty.is_empty() {
                                let req = crate::daemon::DaemonRequest::CaptureRead {
                                    session: session.clone(),
                                    max_lines: 500,
                                };
                                if let Some(crate::daemon::DaemonResponse::Ok { data: Some(d) }) =
                                    crate::daemon_client::try_send_request(&session, &req)
                                {
                                    captured_output = d
                                        .get("output")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                }
                            }
                        }
                        // Fallback to provided output (usually None in global path)
                        if captured_output.is_none() {
                            captured_output = output.clone();
                        }

                        let event = crate::memory::types::ShellEvent {
                            event_type: crate::memory::types::ShellEventType::CommandExecution,
                            command: Some(command.clone()),
                            output: captured_output,
                            exit_code: Some(exit_code),
                            working_dir: Some(cwd.clone()),
                            session_id: Some(session.clone()),
                            timestamp: started_at.clone(),
                            git_context: None,
                            instruction: None,
                            file_path: None,
                        };
                        memory.record_event(event);
                        if memory.should_flush_ingestion() {
                            let _ = memory_tx.send(MemoryTask::FlushIngestion);
                        }
                    }
                    DaemonResponse::ok_with_data(serde_json::json!({"id": id}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::Heartbeat { session } => match db.update_heartbeat(&session) {
            Ok(()) => {
                crate::daemon::generate_summaries_sync_pub(db);
                DaemonResponse::ok()
            }
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::CreateSession {
            session,
            tty,
            shell,
            pid,
        } => match db.create_session(&session, &tty, &shell, pid) {
            Ok(()) => {
                // Emit a SessionStart event into memory (best-effort)
                let event = crate::memory::types::ShellEvent {
                    event_type: crate::memory::types::ShellEventType::SessionStart,
                    command: None,
                    output: None,
                    exit_code: None,
                    working_dir: None,
                    session_id: Some(session.clone()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    git_context: None,
                    instruction: None,
                    file_path: None,
                };
                memory.record_event(event);
                if memory.should_flush_ingestion() {
                    let _ = memory_tx.send(MemoryTask::FlushIngestion);
                }
                DaemonResponse::ok()
            }
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::EndSession { session } => match db.end_session(&session) {
            Ok(()) => {
                session_project_roots.remove(&session);
                // Emit a SessionEnd event into memory (best-effort)
                let event = crate::memory::types::ShellEvent {
                    event_type: crate::memory::types::ShellEventType::SessionEnd,
                    command: None,
                    output: None,
                    exit_code: None,
                    working_dir: None,
                    session_id: Some(session.clone()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    git_context: None,
                    instruction: None,
                    file_path: None,
                };
                memory.record_event(event);
                if memory.should_flush_ingestion() {
                    let _ = memory_tx.send(MemoryTask::FlushIngestion);
                }
                DaemonResponse::ok()
            }
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::SetSessionLabel { session, label } => {
            match db.set_session_label(&session, &label) {
                Ok(updated) => {
                    DaemonResponse::ok_with_data(serde_json::json!({"updated": updated}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::ClearConversations { session } => match db.clear_conversations(&session) {
            Ok(()) => DaemonResponse::ok(),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::InsertConversation {
            session_id,
            query,
            response_type,
            response,
            explanation,
            executed,
            pending,
        } => {
            match db.insert_conversation(
                &session_id,
                &query,
                &response_type,
                &response,
                explanation.as_deref(),
                executed,
                pending,
            ) {
                Ok(id) => DaemonResponse::ok_with_data(serde_json::json!({"id": id})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::InsertUsage {
            session_id,
            query_text,
            model,
            provider,
            input_tokens,
            output_tokens,
            cost_usd,
            generation_id,
        } => {
            match db.insert_usage(
                &session_id,
                query_text.as_deref(),
                &model,
                &provider,
                input_tokens,
                output_tokens,
                cost_usd,
                generation_id.as_deref(),
            ) {
                Ok(id) => DaemonResponse::ok_with_data(serde_json::json!({"id": id})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::UpdateConversationResult {
            conv_id,
            exit_code,
            output_snippet,
        } => match db.update_conversation_result(conv_id, exit_code, output_snippet.as_deref()) {
            Ok(()) => DaemonResponse::ok(),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },

        DaemonRequest::SetMeta { key, value } => match db.set_meta(&key, &value) {
            Ok(()) => DaemonResponse::ok(),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::Prune { retention_days } => match db.prune(retention_days) {
            Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"pruned": count})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::RebuildFts => match db.rebuild_fts() {
            Ok(()) => DaemonResponse::ok(),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::CleanupOrphanedSessions => match db.cleanup_orphaned_sessions() {
            Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"cleaned": count})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::UpdateSummary { id, summary } => match db.update_summary(id, &summary) {
            Ok(updated) => DaemonResponse::ok_with_data(serde_json::json!({"updated": updated})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::MarkSummaryError { id, error } => match db.mark_summary_error(id, &error) {
            Ok(()) => DaemonResponse::ok(),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::UpdateUsageCost {
            generation_id,
            cost,
        } => match db.update_usage_cost(&generation_id, cost) {
            Ok(updated) => DaemonResponse::ok_with_data(serde_json::json!({"updated": updated})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::MarkUnsummarizedForLlm => match db.mark_unsummarized_for_llm() {
            Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"count": count})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::BackfillEntities => match db.backfill_command_entities_if_needed() {
            Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"backfilled": count})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::GenerateSummaries | DaemonRequest::SummarizeCheck { .. } => {
            crate::daemon::generate_summaries_sync_pub(db);
            DaemonResponse::ok()
        }
        // ── Memory write operations ──────────────────────
        DaemonRequest::MemoryRecordEvent { event_json } => {
            match serde_json::from_str::<crate::memory::types::ShellEvent>(&event_json) {
                Ok(event) => {
                    memory.record_event(event);
                    // Auto-flush when buffer is ready
                    if memory.should_flush_ingestion()
                        && memory_tx.send(MemoryTask::FlushIngestion).is_err()
                    {
                        tracing::debug!("memory thread disconnected, flush skipped");
                    }
                    DaemonResponse::ok()
                }
                Err(e) => DaemonResponse::error(format!("invalid event JSON: {e}")),
            }
        }
        DaemonRequest::MemoryFlushIngestion => {
            if memory_tx.send(MemoryTask::FlushIngestion).is_err() {
                tracing::debug!("memory thread disconnected, flush skipped");
            }
            DaemonResponse::ok()
        }
        DaemonRequest::MemoryIngestBatch { events_json } => {
            match serde_json::from_str::<Vec<crate::memory::types::ShellEvent>>(&events_json) {
                Ok(events) => {
                    if memory_tx.send(MemoryTask::IngestBatch { events }).is_err() {
                        tracing::debug!("memory thread disconnected, ingest skipped");
                    }
                    DaemonResponse::ok()
                }
                Err(e) => DaemonResponse::error(format!("invalid events JSON: {e}")),
            }
        }
        DaemonRequest::MemoryCoreAppend { label, content } => {
            let op = crate::memory::types::CoreOp::Append;
            let lbl = crate::memory::types::CoreLabel::from_str(&label)
                .ok_or_else(|| DaemonResponse::error(format!("invalid core label: {label}")));
            match lbl {
                Err(e) => e,
                Ok(l) => match memory.update_core_block(l, op, &content) {
                    Ok(()) => DaemonResponse::ok(),
                    Err(e) => DaemonResponse::error(format!("{e}")),
                },
            }
        }
        DaemonRequest::MemoryCoreRewrite { label, content } => {
            let op = crate::memory::types::CoreOp::Rewrite;
            let lbl = crate::memory::types::CoreLabel::from_str(&label)
                .ok_or_else(|| DaemonResponse::error(format!("invalid core label: {label}")));
            match lbl {
                Err(e) => e,
                Ok(l) => match memory.update_core_block(l, op, &content) {
                    Ok(()) => DaemonResponse::ok(),
                    Err(e) => DaemonResponse::error(format!("{e}")),
                },
            }
        }
        DaemonRequest::MemoryStore {
            memory_type,
            data_json,
        } => {
            use crate::daemon_db::DbAccess;
            match DbAccess::memory_store(db, &memory_type, &data_json) {
                Ok(id) => DaemonResponse::ok_with_data(serde_json::json!({"id": id})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MemoryDelete { memory_type, id } => {
            use crate::memory::types::MemoryType;
            let mt = match memory_type.as_str() {
                "episodic" => MemoryType::Episodic,
                "semantic" => MemoryType::Semantic,
                "procedural" => MemoryType::Procedural,
                "resource" => MemoryType::Resource,
                "knowledge" => MemoryType::Knowledge,
                _ => return DaemonResponse::error(format!("unknown memory type: {memory_type}")),
            };
            match memory.delete_memory(mt, &id) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MemoryRunDecay => match memory.run_decay() {
            Ok(report) => DaemonResponse::ok_with_data(serde_json::json!({
                "episodic_deleted": report.episodic_deleted,
                "semantic_deleted": report.semantic_deleted,
                "procedural_deleted": report.procedural_deleted,
                "resource_deleted": report.resource_deleted,
                "knowledge_deleted": report.knowledge_deleted,
            })),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::MemoryRunReflection => {
            if memory_tx.send(MemoryTask::RunReflection).is_err() {
                tracing::debug!("memory thread disconnected, reflection skipped");
            }
            DaemonResponse::ok()
        }
        DaemonRequest::MemoryBootstrapScan => {
            if memory_tx.send(MemoryTask::BootstrapScan).is_err() {
                tracing::debug!("memory thread disconnected, bootstrap skipped");
            }
            DaemonResponse::ok()
        }
        DaemonRequest::MemoryClearAll => match memory.clear_all() {
            Ok(()) => DaemonResponse::ok(),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::MemoryClearByType { memory_type } => {
            match db.clear_memories_by_type(&memory_type) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::RunDoctor {
            retention_days,
            no_prune,
            no_vacuum,
        } => {
            let config = crate::config::Config::load().unwrap_or_default();
            match db.run_doctor(retention_days, no_prune, no_vacuum, &config) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        other => {
            let _ = other;
            let resp = DaemonResponse::error("unexpected write request");
            log_daemon("server.execute_write.response", &format!("{resp:?}"));
            resp
        }
    }
}

fn run_read_thread(
    db: crate::db::Db,
    rx: Arc<Mutex<mpsc::Receiver<ReadCommand>>>,
    memory: Arc<crate::memory::MemorySystem>,
) {
    loop {
        let cmd = loop {
            let maybe = {
                let guard = rx.lock().unwrap_or_else(|e| e.into_inner());
                guard.try_recv()
            };
            match maybe {
                Ok(cmd) => break cmd,
                Err(mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(1)),
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        };
        let resp = execute_read(&db, &memory, cmd.request);
        let _ = cmd.reply.send(resp);
    }
}

fn execute_read(
    db: &crate::db::Db,
    memory: &crate::memory::MemorySystem,
    request: DaemonRequest,
) -> DaemonResponse {
    let req_dbg = format!("{request:?}");
    log_daemon("server.execute_read.request", &req_dbg);
    match request {
        DaemonRequest::SearchHistory { query, limit } => match db.search_history(&query, limit) {
            Ok(results) => {
                let json: Vec<serde_json::Value> = results
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id, "session_id": r.session_id, "command": r.command,
                            "cwd": r.cwd, "exit_code": r.exit_code, "started_at": r.started_at,
                            "output": r.output, "summary": r.summary,
                            "cmd_highlight": r.cmd_highlight,
                            "output_highlight": r.output_highlight,
                        })
                    })
                    .collect();
                DaemonResponse::ok_with_data(serde_json::json!({"results": json}))
            }
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::GetConversations { session, limit } => {
            match db.get_conversations(&session, limit) {
                Ok(convos) => {
                    let json: Vec<serde_json::Value> = convos
                        .iter()
                        .map(|c| {
                            serde_json::json!({
                                "query": c.query, "response_type": c.response_type,
                                "response": c.response, "explanation": c.explanation,
                                "result_exit_code": c.result_exit_code,
                                "result_output_snippet": c.result_output_snippet,
                                "created_at": c.created_at,
                            })
                        })
                        .collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"conversations": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::FindPendingConversation { session } => {
            match db.find_pending_conversation(&session) {
                Ok(Some((id, cmd))) => {
                    DaemonResponse::ok_with_data(serde_json::json!({"id": id, "command": cmd}))
                }
                Ok(None) => DaemonResponse::ok_with_data(serde_json::json!({"found": false})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::LatestCwdForTty { tty } => match db.latest_cwd_for_tty(&tty) {
            Ok(cwd) => DaemonResponse::ok_with_data(serde_json::json!({"cwd": cwd})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::GetUsageStats { period } => {
            let usage_period = match period.as_str() {
                "today" => crate::db::UsagePeriod::Today,
                "week" => crate::db::UsagePeriod::Week,
                "month" => crate::db::UsagePeriod::Month,
                "all" => crate::db::UsagePeriod::All,
                _ => crate::db::UsagePeriod::Month,
            };
            match db.get_usage_stats(usage_period) {
                Ok(stats) => {
                    let json: Vec<serde_json::Value> = stats.iter().map(|(model, calls, input, output, cost)| {
                        serde_json::json!({"model": model, "calls": calls, "input_tokens": input, "output_tokens": output, "cost_usd": cost})
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"stats": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }

        DaemonRequest::GetMeta { key } => match db.get_meta(&key) {
            Ok(value) => DaemonResponse::ok_with_data(serde_json::json!({"value": value})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::GetSessionLabel { session } => match db.get_session_label(&session) {
            Ok(label) => DaemonResponse::ok_with_data(serde_json::json!({"label": label})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::RecentCommandsWithSummaries { session, limit } => {
            match db.recent_commands_with_summaries(&session, limit) {
                Ok(cmds) => {
                    let json: Vec<serde_json::Value> = cmds.iter().map(|c| {
                        serde_json::json!({
                            "command": c.command, "cwd": c.cwd, "exit_code": c.exit_code,
                            "started_at": c.started_at, "duration_ms": c.duration_ms, "summary": c.summary,
                            "output": c.output,
                        })
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"commands": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::OtherSessionsWithSummaries {
            session,
            max_ttys,
            summaries_per_tty,
        } => match db.other_sessions_with_summaries(&session, max_ttys, summaries_per_tty) {
            Ok(cmds) => {
                let json: Vec<serde_json::Value> = cmds
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "command": c.command, "cwd": c.cwd, "exit_code": c.exit_code,
                            "started_at": c.started_at, "summary": c.summary,
                            "tty": c.tty, "shell": c.shell, "session_id": c.session_id,
                        })
                    })
                    .collect();
                DaemonResponse::ok_with_data(serde_json::json!({"commands": json}))
            }
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::SearchHistoryAdvanced {
            fts_query,
            regex_pattern,
            since,
            until,
            exit_code,
            failed_only,
            session_filter,
            current_session,
            limit,
        } => {
            match db.search_history_advanced(
                fts_query.as_deref(),
                regex_pattern.as_deref(),
                since.as_deref(),
                until.as_deref(),
                exit_code,
                failed_only,
                session_filter.as_deref(),
                current_session.as_deref(),
                limit,
            ) {
                Ok(results) => {
                    let json: Vec<serde_json::Value> = results
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "id": r.id, "session_id": r.session_id, "command": r.command,
                                "cwd": r.cwd, "exit_code": r.exit_code, "started_at": r.started_at,
                                "output": r.output, "summary": r.summary,
                                "cmd_highlight": r.cmd_highlight,
                                "output_highlight": r.output_highlight,
                            })
                        })
                        .collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::SearchCommandEntities {
            executable,
            entity,
            entity_type,
            since,
            until,
            session_filter,
            current_session,
            limit,
        } => {
            match db.search_command_entities(
                executable.as_deref(),
                entity.as_deref(),
                entity_type.as_deref(),
                since.as_deref(),
                until.as_deref(),
                session_filter.as_deref(),
                current_session.as_deref(),
                limit,
            ) {
                Ok(results) => {
                    let json: Vec<serde_json::Value> = results.iter().map(|r| {
                        serde_json::json!({
                            "command_id": r.command_id, "session_id": r.session_id,
                            "command": crate::util::truncate(&r.command, 500), "cwd": r.cwd, "started_at": r.started_at,
                            "executable": r.executable, "entity": r.entity, "entity_type": r.entity_type,
                        })
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::CommandCount => match db.command_count() {
            Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"count": count})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::CommandsNeedingSummary { limit } => {
            match db.commands_needing_summary(limit) {
                Ok(cmds) => {
                    let json: Vec<serde_json::Value> = cmds.iter().map(|c| {
                        serde_json::json!({"id": c.id, "command": c.command, "cwd": c.cwd, "exit_code": c.exit_code, "output": c.output})
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"commands": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::CommandsNeedingLlmSummary { limit } => {
            match db.commands_needing_llm_summary(limit) {
                Ok(cmds) => {
                    let json: Vec<serde_json::Value> = cmds.iter().map(|c| {
                        serde_json::json!({"id": c.id, "command": c.command, "cwd": c.cwd, "exit_code": c.exit_code, "output": c.output})
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"commands": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::Status => DaemonResponse::ok_with_data(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "daemon_type": "global",
        })),
        DaemonRequest::GetSystemInfo => {
            let static_info = crate::context::get_static_info();
            let semi_dynamic = crate::context::get_semi_dynamic_info();
            let (cpu_samples, memory_usage, load_average) = crate::context::sample_volatile_info();
            let bundle = crate::context::SystemInfoBundle {
                static_info: static_info.to_snapshot(),
                semi_dynamic: semi_dynamic.to_snapshot(),
                cpu_samples,
                memory_usage,
                load_average,
            };
            match serde_json::to_value(bundle) {
                Ok(value) => DaemonResponse::ok_with_data(value),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        // ── Memory read operations ──────────────────────
        DaemonRequest::MemoryRetrieve { context_json } => {
            tracing::debug!("memory: retrieve (len={})", context_json.len());
            // Parse context
            match serde_json::from_str::<crate::memory::types::MemoryQueryContext>(&context_json) {
                Ok(ctx) => {
                    // For read path, perform retrieval without LLM (fast path handles most cases)
                    let rt = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            return DaemonResponse::error(format!(
                                "memory runtime init failed: {e}"
                            ));
                        }
                    };
                    let result = rt.block_on(async { memory.retrieve_for_query(&ctx, None).await });
                    match result {
                        Ok(memories) => {
                            let prompt = memory.build_memory_prompt(&memories);
                            DaemonResponse::ok_with_data(serde_json::json!({
                                "prompt": prompt,
                            }))
                        }
                        Err(e) => DaemonResponse::error(format!("{e}")),
                    }
                }
                Err(e) => DaemonResponse::error(format!("invalid context JSON: {e}")),
            }
        }
        DaemonRequest::MemorySearch {
            query,
            memory_type: _,
            limit,
        } => {
            // Use MemorySystem search across all types for now
            match memory.search(&query, None, limit) {
                Ok(results) => {
                    let json: Vec<serde_json::Value> = results
                        .into_iter()
                        .map(|r| {
                            serde_json::json!({
                                "type": r.memory_type.as_str(),
                                "id": r.id,
                                "summary": r.summary,
                                "score": r.score,
                            })
                        })
                        .collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MemoryGetCore => match memory.get_core_memory() {
            Ok(blocks) => {
                let json: Vec<serde_json::Value> = blocks
                    .iter()
                    .map(|b| {
                        serde_json::json!({
                            "label": b.label.as_str(),
                            "value": b.value,
                            "char_limit": b.char_limit,
                            "updated_at": b.updated_at,
                        })
                    })
                    .collect();
                DaemonResponse::ok_with_data(serde_json::json!({"blocks": json}))
            }
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::MemoryRetrieveSecret { caption_query } => {
            match db.search_knowledge_fts(&caption_query, 3, &["low", "medium", "high"]) {
                Ok(results) => {
                    let json: Vec<serde_json::Value> = results
                        .iter()
                        .map(|r| {
                            serde_json::json!({
                                "id": r.id,
                                "caption": r.caption,
                                "entry_type": r.entry_type,
                                "sensitivity": r.sensitivity.as_str(),
                            })
                        })
                        .collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MemoryExportAll => match memory.export_all() {
            Ok(data) => DaemonResponse::ok_with_data(data),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::MemoryStats => {
            match memory.stats() {
                Ok(stats) => {
                    // Read telemetry from memory_config (NULL-safe defaults)
                    let decay_runs: i64 = db
                        .get_memory_config("decay_runs")
                        .ok()
                        .flatten()
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(0);
                    let last_decay_at = db
                        .get_memory_config("last_decay_at")
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| "".into());
                    let reflection_runs: i64 = db
                        .get_memory_config("reflection_runs")
                        .ok()
                        .flatten()
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(0);
                    let last_reflection_at = db
                        .get_memory_config("last_reflection_at")
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| "".into());

                    DaemonResponse::ok_with_data(serde_json::json!({
                        "core": stats.core_count,
                        "episodic": stats.episodic_count,
                        "semantic": stats.semantic_count,
                        "procedural": stats.procedural_count,
                        "resource": stats.resource_count,
                        "knowledge": stats.knowledge_count,
                        "decay_runs": decay_runs,
                        "last_decay_at": last_decay_at,
                        "reflection_runs": reflection_runs,
                        "last_reflection_at": last_reflection_at,
                    }))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::Scrollback { .. }
        | DaemonRequest::CaptureMark { .. }
        | DaemonRequest::CaptureRead { .. } => {
            DaemonResponse::error("capture operations are per-session only")
        }
        other => {
            let _ = other;
            let resp = DaemonResponse::error("unexpected read request");
            log_daemon("server.execute_read.response", &format!("{resp:?}"));
            resp
        }
    }
}

#[cfg(test)]
mod tests_memory_stats {
    use super::*;

    #[test]
    fn memory_stats_includes_telemetry() {
        // In-memory DB and MemorySystem
        let db = crate::db::Db::open_in_memory().expect("db");
        let mem = crate::memory::MemorySystem::open_in_memory().expect("mem");
        // Seed telemetry
        db.set_memory_config("decay_runs", "9").unwrap();
        db.set_memory_config("reflection_runs", "3").unwrap();
        db.set_memory_config("last_decay_at", "2026-02-21 12:34:56")
            .unwrap();
        db.set_memory_config("last_reflection_at", "2026-02-20 08:10:11")
            .unwrap();

        let resp = execute_read(&db, &mem, DaemonRequest::MemoryStats);
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                assert!(d.get("core").is_some());
                assert_eq!(d["decay_runs"].as_i64(), Some(9));
                assert_eq!(d["reflection_runs"].as_i64(), Some(3));
                assert_eq!(d["last_decay_at"].as_str(), Some("2026-02-21 12:34:56"));
                assert_eq!(
                    d["last_reflection_at"].as_str(),
                    Some("2026-02-20 08:10:11")
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
#[cfg(unix)]
fn handle_global_connection(
    stream: std::os::unix::net::UnixStream,
    write_tx: mpsc::Sender<WriteCommand>,
    read_tx: mpsc::Sender<ReadCommand>,
    active_sessions: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, SessionInfo>>>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));

    let limited_stream = (&stream).take(1024 * 1024);
    let mut reader = BufReader::new(limited_stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }

    let request: DaemonRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = DaemonResponse::error(format!("parse error: {e}"));
            if let Err(e) = write_response(&stream, &resp) {
                tracing::warn!("daemon: failed to write parse error response: {e}");
            }
            let _ = stream.shutdown(std::net::Shutdown::Write);
            return;
        }
    };
    log_daemon("server.connection.request", line.trim());
    // Track active session IDs for per-session notifications (in-memory)
    match &request {
        DaemonRequest::CreateSession { session, tty, shell, pid } => {
            if let Ok(mut guard) = active_sessions.write() {
                guard.insert(session.clone(), SessionInfo { last_seen: Instant::now(), tty: Some(tty.clone()), shell: Some(shell.clone()), pid: Some(*pid) });
            }
        }
        DaemonRequest::Heartbeat { session } => {
            if let Ok(mut guard) = active_sessions.write() {
                guard.entry(session.clone()).and_modify(|info| info.last_seen = Instant::now()).or_insert(SessionInfo { last_seen: Instant::now(), tty: None, shell: None, pid: None });
            }
        }
        DaemonRequest::EndSession { session } => {
            if let Ok(mut guard) = active_sessions.write() { let _ = guard.remove(session); }
        }
        _ => {}
    }

    let (reply_tx, reply_rx) = mpsc::channel();

    // Intercept sidecar management requests in the main thread, since they are
    // fast and not DB-bound, to avoid unnecessary worker routing.
    if let Some(resp) = handle_sidecar_requests_inline(&request) {
        let _ = write_response(&stream, &resp);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        return;
    }

    let is_write = is_write_request(&request);
    let send_result = if is_write {
        write_tx
            .send(WriteCommand {
                request,
                reply: reply_tx,
            })
            .map_err(|_| ())
    } else {
        read_tx
            .send(ReadCommand {
                request,
                reply: reply_tx,
            })
            .map_err(|_| ())
    };

    if send_result.is_err() {
        if let Err(e) = write_response(&stream, &DaemonResponse::error("daemon shutting down")) {
            tracing::warn!("daemon: failed to write shutdown response: {e}");
        }
        let _ = stream.shutdown(std::net::Shutdown::Write);
        return;
    }

    match reply_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(resp) => {
            log_daemon("server.connection.response", &format!("{resp:?}"));
            if let Err(e) = write_response(&stream, &resp) {
                tracing::warn!("daemon: failed to write response: {e}");
            }
        }
        Err(_) => {
            if let Err(e) = write_response(&stream, &DaemonResponse::error("timeout")) {
                tracing::warn!("daemon: failed to write timeout response: {e}");
            }
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn handle_sidecar_requests_inline(req: &DaemonRequest) -> Option<DaemonResponse> {
    match req {
        DaemonRequest::EnsureCLIProxyApi => Some(match crate::cliproxyapi::ensure_running() {
            Ok(port) => DaemonResponse::ok_with_data(serde_json::json!({"port": port})),
            Err(e) => DaemonResponse::error(e.to_string()),
        }),
        DaemonRequest::CLIProxyApiStatus => {
            let running = crate::cliproxyapi::is_sidecar_running();
            let port = crate::cliproxyapi::get_port();
            let version = std::fs::read_to_string(crate::cliproxyapi::version_file()).ok();
            let pid = std::fs::read_to_string(crate::cliproxyapi::pid_file())
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok());
            // Read last update info from DB meta if present
            let (last_check, last_status, installed_version) = match crate::db::Db::open_readonly() {
                Ok(db) => {
                    let lc = db.get_meta("cliproxyapi_last_update_check").ok().flatten();
                    let ls = db.get_meta("cliproxyapi_last_update_status").ok().flatten();
                    let iv = db.get_meta("cliproxyapi_installed_version").ok().flatten();
                    (lc, ls, iv)
                }
                Err(_) => (None, None, None),
            };
            Some(DaemonResponse::ok_with_data(serde_json::json!({
                "running": running,
                "port": port,
                "version": version,
                "pid": pid,
                "last_update_check": last_check,
                "last_update_status": last_status,
                "installed_version": installed_version,
            })))
        }
        DaemonRequest::CLIProxyApiRestart => {
            let _ = crate::cliproxyapi::stop_sidecar();
            Some(match crate::cliproxyapi::ensure_running() {
                Ok(port) => DaemonResponse::ok_with_data(serde_json::json!({"port": port})),
                Err(e) => DaemonResponse::error(e.to_string()),
            })
        }
        DaemonRequest::StopCLIProxyApi => Some(match crate::cliproxyapi::stop_sidecar() {
            Ok(()) => DaemonResponse::ok(),
            Err(e) => DaemonResponse::error(e.to_string()),
        }),
        DaemonRequest::CheckForUpdates => {
            let _ = std::thread::Builder::new().name("nshd-update-check".into()).spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build();
                if let Ok(rt) = rt {
                    rt.block_on(async move {
                        if let Ok(Some((url, version))) = crate::cliproxyapi::check_for_update().await {
                            let _ = crate::cliproxyapi::download_and_install(&url, &version).await;
                        }
                    });
                }
            });
            Some(DaemonResponse::ok())
        }
        _ => None,
    }
}

// Expose a minimal hook for integration tests to fetch sidecar status
pub mod test_helpers {
    pub fn sidecar_status_inline() -> Option<crate::daemon::DaemonResponse> {
        super::handle_sidecar_requests_inline(&crate::daemon::DaemonRequest::CLIProxyApiStatus)
    }
}

fn is_write_request(req: &DaemonRequest) -> bool {
    matches!(
        req,
        DaemonRequest::Record { .. }
            | DaemonRequest::Heartbeat { .. }
            | DaemonRequest::CreateSession { .. }
            | DaemonRequest::EndSession { .. }
            | DaemonRequest::SetSessionLabel { .. }
            | DaemonRequest::ClearConversations { .. }
            | DaemonRequest::InsertConversation { .. }
            | DaemonRequest::InsertUsage { .. }
            | DaemonRequest::UpdateConversationResult { .. }
            | DaemonRequest::SetMeta { .. }
            | DaemonRequest::Prune { .. }
            | DaemonRequest::RebuildFts
            | DaemonRequest::CleanupOrphanedSessions
            | DaemonRequest::UpdateSummary { .. }
            | DaemonRequest::MarkSummaryError { .. }
            | DaemonRequest::UpdateUsageCost { .. }
            | DaemonRequest::MarkUnsummarizedForLlm
            | DaemonRequest::BackfillEntities
            | DaemonRequest::GenerateSummaries
            | DaemonRequest::SummarizeCheck { .. }
            | DaemonRequest::RunDoctor { .. }
            // Memory write operations
            | DaemonRequest::MemoryRecordEvent { .. }
            | DaemonRequest::MemoryFlushIngestion
            | DaemonRequest::MemoryIngestBatch { .. }
            | DaemonRequest::MemoryCoreAppend { .. }
            | DaemonRequest::MemoryCoreRewrite { .. }
            | DaemonRequest::MemoryStore { .. }
            | DaemonRequest::MemoryDelete { .. }
            | DaemonRequest::MemoryRunDecay
            | DaemonRequest::MemoryRunReflection
            | DaemonRequest::MemoryBootstrapScan
            | DaemonRequest::MemoryClearAll
            | DaemonRequest::MemoryClearByType { .. }
    )
}

/// Walk up from `cwd` to find a project root (directory containing `.git`, `Cargo.toml`,
/// `package.json`, `go.mod`, `pyproject.toml`, etc.). Returns the root path string,
/// or `None` if the CWD is at or above the home directory with no markers.
fn detect_project_root_fast(cwd: &str) -> Option<String> {
    use std::path::Path;

    let markers = [
        ".git",
        "Cargo.toml",
        "package.json",
        "go.mod",
        "pyproject.toml",
        "setup.py",
        "Makefile",
        "CMakeLists.txt",
        "pom.xml",
        "build.gradle",
    ];

    let mut dir = Path::new(cwd);
    let home = dirs::home_dir();
    loop {
        for marker in &markers {
            if dir.join(marker).exists() {
                return Some(dir.to_string_lossy().to_string());
            }
        }
        // Stop at home directory or filesystem root
        if let Some(ref h) = home {
            if dir == h.as_path() {
                return None;
            }
        }
        match dir.parent() {
            Some(p) if p != dir => dir = p,
            _ => return None,
        }
    }
}

#[cfg(unix)]
fn write_response(
    stream: &std::os::unix::net::UnixStream,
    resp: &DaemonResponse,
) -> std::io::Result<()> {
    let mut w = std::io::BufWriter::with_capacity(256 * 1024, stream);
    let mut json_val =
        serde_json::to_value(resp).unwrap_or_else(|_| serde_json::json!({"status":"error"}));
    if let serde_json::Value::Object(ref mut map) = json_val {
        map.insert(
            "v".into(),
            serde_json::json!(crate::daemon::DAEMON_PROTOCOL_VERSION),
        );
        map.insert(
            "daemon_version".into(),
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        );
        map.insert(
            "daemon_fingerprint".into(),
            serde_json::json!(env!("NSH_BUILD_FINGERPRINT")),
        );
    }
    let mut json = serde_json::to_string(&json_val)
        .unwrap_or_else(|_| r#"{"status":"error","message":"serialize error"}"#.into());
    json.push('\n');
    w.write_all(json.as_bytes())?;
    w.flush()
}

#[cfg(unix)]
fn check_peer_uid(stream: &std::os::unix::net::UnixStream) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return false;
        }
        if cred.uid != unsafe { libc::getuid() } {
            return false;
        }
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        use std::os::fd::AsRawFd;
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
        if rc != 0 {
            return false;
        }
        if euid != unsafe { libc::getuid() } {
            return false;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        tracing::warn!(
            "Peer UID check not implemented for this platform, relying on socket permissions"
        );
    }
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    fn send_request_and_read_response(
        request_line: &str,
        write_tx: mpsc::Sender<WriteCommand>,
        read_tx: mpsc::Sender<ReadCommand>,
        write_rx: mpsc::Receiver<WriteCommand>,
        read_rx: mpsc::Receiver<ReadCommand>,
    ) -> (String, Option<WriteCommand>, Option<ReadCommand>) {
        let (server, mut client) = UnixStream::pair().expect("unix stream pair");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");

        let handler = std::thread::spawn(move || {
            let sessions = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
            handle_global_connection(server, write_tx, read_tx, sessions);
        });

        let mut line = request_line.to_string();
        if !line.ends_with('\n') {
            line.push('\n');
        }
        client
            .write_all(line.as_bytes())
            .expect("write request to daemon conn");
        client.flush().expect("flush request");

        let write_cmd = write_rx.recv_timeout(Duration::from_millis(300)).ok();
        let read_cmd = read_rx.recv_timeout(Duration::from_millis(300)).ok();

        if let Some(cmd) = &write_cmd {
            let _ = cmd
                .reply
                .send(DaemonResponse::ok_with_data(serde_json::json!({
                    "routed": "write"
                })));
        }
        if let Some(cmd) = &read_cmd {
            let _ = cmd
                .reply
                .send(DaemonResponse::ok_with_data(serde_json::json!({
                    "routed": "read"
                })));
        }

        let mut response = String::new();
        let mut reader = BufReader::new(client);
        reader
            .read_line(&mut response)
            .expect("read daemon response");

        handler.join().expect("join daemon connection handler");
        (response, write_cmd, read_cmd)
    }

    #[test]
    fn is_write_request_classifies_representative_variants() {
        assert!(is_write_request(&DaemonRequest::Heartbeat {
            session: "s".into()
        }));
        assert!(is_write_request(&DaemonRequest::RunDoctor {
            retention_days: 30,
            no_prune: false,
            no_vacuum: false,
        }));
        assert!(!is_write_request(&DaemonRequest::Status));
        assert!(!is_write_request(&DaemonRequest::SearchHistory {
            query: "ls".into(),
            limit: 5,
        }));
    }

    #[test]
    fn handle_global_connection_routes_write_request_to_write_channel() {
        let request = serde_json::to_string(&DaemonRequest::Heartbeat {
            session: "sess-write".into(),
        })
        .expect("serialize request");

        let (write_tx, write_rx) = mpsc::channel();
        let (read_tx, read_rx) = mpsc::channel();
        let (response, write_cmd, read_cmd) =
            send_request_and_read_response(&request, write_tx, read_tx, write_rx, read_rx);

        assert!(write_cmd.is_some(), "expected write command to be routed");
        assert!(read_cmd.is_none(), "did not expect read command");
        assert!(response.contains("routed"));
        assert!(response.contains("write"));
    }

    #[test]
    fn handle_global_connection_routes_read_request_to_read_channel() {
        let request = serde_json::to_string(&DaemonRequest::Status).expect("serialize request");

        let (write_tx, write_rx) = mpsc::channel();
        let (read_tx, read_rx) = mpsc::channel();
        let (response, write_cmd, read_cmd) =
            send_request_and_read_response(&request, write_tx, read_tx, write_rx, read_rx);

        assert!(write_cmd.is_none(), "did not expect write command");
        assert!(read_cmd.is_some(), "expected read command to be routed");
        assert!(response.contains("routed"));
        assert!(response.contains("read"));
    }

    #[test]
    fn handle_global_connection_returns_parse_error_for_invalid_json() {
        let (write_tx, write_rx) = mpsc::channel();
        let (read_tx, read_rx) = mpsc::channel();
        let (response, write_cmd, read_cmd) =
            send_request_and_read_response("{not-json", write_tx, read_tx, write_rx, read_rx);

        assert!(write_cmd.is_none());
        assert!(read_cmd.is_none());
        assert!(
            response.contains("parse error"),
            "unexpected response: {response}"
        );
    }
}
