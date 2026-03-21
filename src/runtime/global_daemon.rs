use anyhow::Context;
use std::io::{Read, Write};
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
    RunDecay,
    RunReflection,
    BootstrapScan,
}

fn exclude_core_from_search(
    requested: Option<crate::memory::types::MemoryType>,
) -> Option<crate::memory::types::MemoryType> {
    match requested {
        Some(crate::memory::types::MemoryType::Core) => None,
        other => other,
    }
}

fn parse_memory_json(input: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str::<serde_json::Value>(input)
        .map_err(|error| format!("invalid memory tool JSON: {error}"))
}

fn caller_conversation(caller: &crate::daemon::CallerContext) -> Vec<crate::provider::Message> {
    caller
        .explicit_user_request
        .as_ref()
        .map(|text| {
            vec![crate::provider::Message {
                role: crate::provider::Role::User,
                content: vec![crate::provider::ContentBlock::Text { text: text.clone() }],
            }]
        })
        .unwrap_or_default()
}

fn authorize_memory_tool_request(
    caller: &crate::daemon::CallerContext,
    tool_name: &str,
    input: &serde_json::Value,
) -> Result<(), String> {
    crate::security::assess_memory_tool_call(tool_name, input, &caller_conversation(caller))
}

fn require_sensitive_memory_confirmation(action: &str, confirmed: bool) -> Result<(), String> {
    if confirmed {
        Ok(())
    } else {
        Err(format!("{action} requires explicit confirmation"))
    }
}

fn sensitive_daemon_audit_fields(
    caller: &crate::daemon::CallerContext,
    action: &str,
    details: &str,
) -> (String, String, String) {
    let query = caller.explicit_user_request.as_deref().unwrap_or(action);
    (
        caller
            .session
            .clone()
            .unwrap_or_else(|| "global".to_string()),
        query.to_string(),
        details.to_string(),
    )
}

fn audit_sensitive_daemon_action(
    caller: &crate::daemon::CallerContext,
    action: &str,
    details: &str,
) -> anyhow::Result<()> {
    audit_sensitive_daemon_action_with(caller, action, details, |session, query, tool, response, risk| {
        crate::audit::audit_log(session, query, tool, response, risk)
    })
}

fn audit_sensitive_daemon_action_with<F>(
    caller: &crate::daemon::CallerContext,
    action: &str,
    details: &str,
    audit_log: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&str, &str, &str, &str, &str) -> anyhow::Result<()>,
{
    let (session, query, response) = sensitive_daemon_audit_fields(caller, action, details);
    audit_log(&session, &query, action, &response, "high")
        .with_context(|| format!("failed to audit sensitive daemon action `{action}`"))
}

fn authorize_session_access(
    db: &crate::db::Db,
    caller: &crate::daemon::CallerContext,
    target_session: &str,
) -> Result<(), String> {
    match db.session_visible_to_caller(caller.session.as_deref(), target_session) {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "caller session {:?} cannot access session '{target_session}'",
            caller.session
        )),
        Err(error) => Err(format!("session access check failed: {error}")),
    }
}

type MemoryTaskSender = mpsc::Sender<MemoryTask>;
type MemoryRuntimeParts = (
    crate::config::Config,
    Arc<crate::memory::MemorySystem>,
    MemoryQueueGuards,
    MemoryTaskTracker,
    MemoryTaskSender,
    std::thread::JoinHandle<()>,
);
type DbWorkerParts = (
    mpsc::Sender<WriteCommand>,
    mpsc::Sender<ReadCommand>,
    std::thread::JoinHandle<()>,
    Vec<std::thread::JoinHandle<()>>,
);

enum MemoryQueueDecision {
    Enqueued,
    Busy,
}

impl MemoryQueueDecision {
    fn as_status(&self) -> &'static str {
        match self {
            MemoryQueueDecision::Enqueued => "queued",
            MemoryQueueDecision::Busy => "already_queued",
        }
    }
}

#[derive(Clone)]
struct MemoryQueueGuards {
    decay_pending: Arc<AtomicBool>,
    reflection_pending: Arc<AtomicBool>,
    bootstrap_pending: Arc<AtomicBool>,
}

impl MemoryQueueGuards {
    fn new() -> Self {
        Self {
            decay_pending: Arc::new(AtomicBool::new(false)),
            reflection_pending: Arc::new(AtomicBool::new(false)),
            bootstrap_pending: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum MemoryTaskKind {
    FlushIngestion,
    IngestBatch,
    RunDecay,
    RunReflection,
    BootstrapScan,
}

impl MemoryTaskKind {
    fn from_task(task: &MemoryTask) -> Self {
        match task {
            MemoryTask::FlushIngestion => Self::FlushIngestion,
            MemoryTask::IngestBatch { .. } => Self::IngestBatch,
            MemoryTask::RunDecay => Self::RunDecay,
            MemoryTask::RunReflection => Self::RunReflection,
            MemoryTask::BootstrapScan => Self::BootstrapScan,
        }
    }

    fn status_key(self) -> &'static str {
        match self {
            Self::FlushIngestion => "flush_ingestion",
            Self::IngestBatch => "ingest_batch",
            Self::RunDecay => "run_decay",
            Self::RunReflection => "run_reflection",
            Self::BootstrapScan => "bootstrap_scan",
        }
    }

    fn error_log_key(self) -> &'static str {
        match self {
            Self::FlushIngestion => "memory.flush.error",
            Self::IngestBatch => "memory.ingest.error",
            Self::RunDecay => "memory.decay.error",
            Self::RunReflection => "memory.reflection.error",
            Self::BootstrapScan => "memory.bootstrap.error",
        }
    }
}

#[derive(Clone, Debug)]
struct MemoryTaskStatus {
    state: String,
    finished_at: Option<String>,
    error: Option<String>,
}

impl Default for MemoryTaskStatus {
    fn default() -> Self {
        Self {
            state: "idle".to_string(),
            finished_at: None,
            error: None,
        }
    }
}

#[derive(Clone, Default)]
struct MemoryTaskTracker {
    flush_ingestion: Arc<Mutex<MemoryTaskStatus>>,
    ingest_batch: Arc<Mutex<MemoryTaskStatus>>,
    run_decay: Arc<Mutex<MemoryTaskStatus>>,
    run_reflection: Arc<Mutex<MemoryTaskStatus>>,
    bootstrap_scan: Arc<Mutex<MemoryTaskStatus>>,
}

impl MemoryTaskTracker {
    fn slot(&self, kind: MemoryTaskKind) -> &Arc<Mutex<MemoryTaskStatus>> {
        match kind {
            MemoryTaskKind::FlushIngestion => &self.flush_ingestion,
            MemoryTaskKind::IngestBatch => &self.ingest_batch,
            MemoryTaskKind::RunDecay => &self.run_decay,
            MemoryTaskKind::RunReflection => &self.run_reflection,
            MemoryTaskKind::BootstrapScan => &self.bootstrap_scan,
        }
    }

    fn update(&self, kind: MemoryTaskKind, update: impl FnOnce(&mut MemoryTaskStatus)) {
        let mut guard = self
            .slot(kind)
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        update(&mut guard);
    }

    fn mark_running(&self, kind: MemoryTaskKind) {
        self.update(kind, |status| {
            status.state = "running".to_string();
            status.error = None;
        });
    }

    fn mark_queued(&self, kind: MemoryTaskKind) {
        self.update(kind, |status| {
            status.state = "queued".to_string();
            status.error = None;
        });
    }

    fn mark_succeeded(&self, kind: MemoryTaskKind) {
        self.update(kind, |status| {
            status.state = "ok".to_string();
            status.finished_at = Some(chrono::Utc::now().to_rfc3339());
            status.error = None;
        });
    }

    fn mark_failed(&self, kind: MemoryTaskKind, error: String) {
        self.update(kind, |status| {
            status.state = "error".to_string();
            status.finished_at = Some(chrono::Utc::now().to_rfc3339());
            status.error = Some(error);
        });
    }

    fn task_snapshot(&self, kind: MemoryTaskKind) -> serde_json::Value {
        let guard = self
            .slot(kind)
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        serde_json::json!({
            "state": guard.state,
            "finished_at": guard.finished_at,
            "error": guard.error,
        })
    }

    fn snapshot_json(&self) -> serde_json::Value {
        serde_json::json!({
            "flush_ingestion": self.task_snapshot(MemoryTaskKind::FlushIngestion),
            "ingest_batch": self.task_snapshot(MemoryTaskKind::IngestBatch),
            "run_decay": self.task_snapshot(MemoryTaskKind::RunDecay),
            "run_reflection": self.task_snapshot(MemoryTaskKind::RunReflection),
            "bootstrap_scan": self.task_snapshot(MemoryTaskKind::BootstrapScan),
        })
    }
}

// In-memory active session tracking for per-session notifications
#[derive(Clone)]
pub struct SessionInfo {
    last_seen: Instant,
    tty: Option<String>,
    shell: Option<String>,
    pid: Option<i64>,
}
type ActiveSessions =
    std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, SessionInfo>>>;

pub(crate) fn log_daemon(action: &str, payload: &str) {
    crate::debug_io::daemon_log("daemon.log", action, payload);
}

#[cfg(unix)]
fn pid_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: libc::kill with signal 0 performs an existence check without
    // delivering a signal. The pid is validated > 0 above and cast to i32 is
    // lossless for valid Unix PIDs.
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

fn apply_restart_cooldown(restart_marker: &std::path::Path) {
    if let Ok(content) = std::fs::read_to_string(restart_marker) {
        if let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(content.trim()) {
            let age = chrono::Utc::now().signed_duration_since(timestamp);
            if age.num_seconds() < 5 {
                let wait = 5 - age.num_seconds();
                std::thread::sleep(Duration::from_secs(wait as u64));
            }
        }
        let _ = std::fs::remove_file(restart_marker);
    }
}

fn acquire_global_daemon_lock() -> anyhow::Result<Option<std::fs::File>> {
    let lock_path = crate::daemon::global_daemon_lock_path();
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)?;

    use std::os::fd::AsRawFd;
    // SAFETY: lock_file is an open File whose fd is valid for the duration
    // of this call. LOCK_EX | LOCK_NB is a valid flock operation.
    let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        log_daemon(
            "server.lifecycle",
            "another daemon already holds lock; exiting",
        );
        return Ok(None);
    }

    Ok(Some(lock_file))
}

fn detach_global_daemon() {
    // SAFETY: setsid() creates a new session for the calling process. This is
    // called once during daemon startup before any threads are spawned, so there
    // are no concurrent thread-safety concerns.
    unsafe {
        libc::setsid();
    }
}

fn write_global_pid_file() -> anyhow::Result<std::path::PathBuf> {
    let pid_path = crate::daemon::global_daemon_pid_path();
    std::fs::write(&pid_path, std::process::id().to_string())?;
    Ok(pid_path)
}

fn bind_global_listener() -> anyhow::Result<(std::path::PathBuf, std::os::unix::net::UnixListener)>
{
    let socket_path = crate::daemon::global_daemon_socket_path();
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    Ok((socket_path, listener))
}

fn open_daemon_datastores() -> anyhow::Result<(crate::db::Db, Vec<crate::db::Db>)> {
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

    Ok((write_db, read_dbs))
}

fn start_memory_runtime() -> anyhow::Result<MemoryRuntimeParts> {
    let config = crate::config::Config::load().unwrap_or_default();
    let db_path = crate::config::Config::nsh_dir().join("nsh.db");
    let memory_queue_guards = MemoryQueueGuards::new();
    let memory_task_tracker = MemoryTaskTracker::default();
    let memory = Arc::new(
        crate::memory::MemorySystem::open(config.memory.clone(), db_path).unwrap_or_else(|e| {
            log_daemon("memory.init.error", &e.to_string());
            crate::memory::MemorySystem::open(config.memory.clone(), ":memory:".into())
                .expect("in-memory MemorySystem must succeed")
        }),
    );

    crate::connectivity::start(&config);

    let (memory_tx, memory_rx) = mpsc::channel::<MemoryTask>();
    let memory_for_thread = Arc::clone(&memory);
    let config_for_memory = config.clone();
    let memory_guards_for_thread = memory_queue_guards.clone();
    let memory_tracker_for_thread = memory_task_tracker.clone();
    let memory_thread = std::thread::Builder::new()
        .name("nshd-memory".into())
        .spawn(move || {
            run_memory_thread(
                memory_for_thread,
                memory_rx,
                config_for_memory,
                memory_guards_for_thread,
                memory_tracker_for_thread,
            );
        })?;

    Ok((
        config,
        memory,
        memory_queue_guards,
        memory_task_tracker,
        memory_tx,
        memory_thread,
    ))
}

fn start_db_worker_threads(
    write_db: crate::db::Db,
    read_dbs: Vec<crate::db::Db>,
    memory: Arc<crate::memory::MemorySystem>,
    memory_task_tracker: MemoryTaskTracker,
    memory_tx: MemoryTaskSender,
    memory_queue_guards: MemoryQueueGuards,
) -> anyhow::Result<DbWorkerParts> {
    let (write_tx, write_rx) = mpsc::channel::<WriteCommand>();
    let (read_tx, read_rx) = mpsc::channel::<ReadCommand>();
    let read_rx = Arc::new(Mutex::new(read_rx));

    let memory_for_writer = Arc::clone(&memory);
    let memory_tracker_for_writer = memory_task_tracker.clone();
    let memory_tx_for_writer = memory_tx.clone();
    let memory_guards_for_writer = memory_queue_guards.clone();
    let write_thread = std::thread::Builder::new()
        .name("nshd-writer".into())
        .spawn(move || {
            run_write_thread(
                write_db,
                write_rx,
                memory_for_writer,
                memory_tracker_for_writer,
                memory_tx_for_writer,
                memory_guards_for_writer,
            );
        })?;

    let read_threads: Vec<_> = read_dbs
        .into_iter()
        .enumerate()
        .map(|(index, db)| {
            let rx = Arc::clone(&read_rx);
            let memory = Arc::clone(&memory);
            let tracker = memory_task_tracker.clone();
            std::thread::Builder::new()
                .name(format!("nshd-reader-{index}"))
                .spawn(move || {
                    run_read_thread(db, rx, memory, tracker);
                })
                .unwrap()
        })
        .collect();

    Ok((write_tx, read_tx, write_thread, read_threads))
}

fn schedule_startup_memory_maintenance(
    memory: &crate::memory::MemorySystem,
    memory_tx: &MemoryTaskSender,
    memory_queue_guards: &MemoryQueueGuards,
    memory_task_tracker: &MemoryTaskTracker,
) {
    if !memory.has_bootstrapped()
        && let Err(error) = queue_memory_task(
            memory_tx,
            memory_queue_guards,
            memory_task_tracker,
            MemoryTask::BootstrapScan,
        )
    {
        tracing::debug!("bootstrap task enqueue failed at startup: {error}");
    }
    if memory.should_run_decay()
        && let Err(error) = queue_memory_task(
            memory_tx,
            memory_queue_guards,
            memory_task_tracker,
            MemoryTask::RunDecay,
        )
    {
        tracing::debug!("decay task enqueue failed at startup: {error}");
    }
    if memory.should_run_reflection()
        && let Err(error) = queue_memory_task(
            memory_tx,
            memory_queue_guards,
            memory_task_tracker,
            MemoryTask::RunReflection,
        )
    {
        tracing::debug!("reflection task enqueue failed at startup: {error}");
    }
}

fn spawn_background_monitors(
    restart_pending: Arc<AtomicBool>,
    active_sessions: ActiveSessions,
) -> anyhow::Result<()> {
    spawn_system_monitor(restart_pending, active_sessions);
    spawn_sidecar_update_checker()?;
    Ok(())
}

fn spawn_system_monitor(restart_pending: Arc<AtomicBool>, active_sessions: ActiveSessions) {
    let monitor_exe_path = std::env::current_exe().ok();
    let monitor_initial_mtime = monitor_exe_path
        .as_ref()
        .and_then(|path| std::fs::metadata(path).ok())
        .and_then(|metadata| metadata.modified().ok());
    std::thread::spawn(move || {
        let mut last_skill_pull = std::time::Instant::now();
        let mut last_prune = std::time::Instant::now();
        loop {
            let _ = crate::context::load_or_sample_volatile_info();
            let _ = crate::context::load_or_refresh_semi_dynamic_info();
            if last_skill_pull.elapsed() > std::time::Duration::from_secs(3600) {
                last_skill_pull = std::time::Instant::now();
                if let Some(skills_dir) =
                    dirs::home_dir().map(|home| home.join(".nsh").join("skills"))
                    && skills_dir.is_dir()
                    && let Ok(entries) = std::fs::read_dir(&skills_dir)
                {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.join(".git").is_dir() {
                            let _ = std::process::Command::new("git")
                                .args([
                                    "-C",
                                    path.to_string_lossy().as_ref(),
                                    "pull",
                                    "--ff-only",
                                    "-q",
                                ])
                                .stdin(std::process::Stdio::null())
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status();
                        }
                    }
                }
            }
            if last_prune.elapsed() > std::time::Duration::from_secs(300) {
                last_prune = std::time::Instant::now();
                let cutoff = Instant::now() - Duration::from_secs(600);
                if let Ok(mut guard) = active_sessions.write() {
                    let stale: Vec<(String, SessionInfo)> = guard
                        .iter()
                        .filter(|(_, info)| info.last_seen < cutoff)
                        .map(|(session_id, info)| (session_id.clone(), info.clone()))
                        .collect();
                    guard.retain(|_, info| info.last_seen >= cutoff);
                    drop(guard);
                    for (session_id, info) in stale {
                        cleanup_session_artifacts(&session_id, &info);
                    }
                }
            }
            if let Some(ref path) = monitor_exe_path
                && let Ok(metadata) = std::fs::metadata(path)
                && let Ok(mtime) = metadata.modified()
                && Some(mtime) != monitor_initial_mtime
            {
                tracing::info!("nshd: binary updated on disk, scheduling graceful restart");
                restart_pending.store(true, Ordering::Relaxed);
                break;
            }
            std::thread::sleep(Duration::from_secs(10));
        }
    });
}

fn spawn_sidecar_update_checker() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .name("nshd-update-checker".into())
        .spawn(|| {
            loop {
                std::thread::sleep(Duration::from_secs(3600));
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let mut last_status = String::from("unknown");
                let mut last_version: Option<String> = None;
                if let Ok(runtime) = runtime {
                    let (status, version_opt) = runtime.block_on(async move {
                        match crate::cliproxyapi::check_for_update().await {
                            Ok(Some((url, version))) => {
                                match crate::cliproxyapi::download_and_install(&url, &version).await
                                {
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

                if let Ok(db) = crate::db::Db::open() {
                    let now = chrono::Utc::now().to_rfc3339();
                    let _ = db.set_meta("cliproxyapi_last_update_check", &now);
                    let _ = db.set_meta("cliproxyapi_last_update_status", &last_status);
                    if let Some(version) = last_version {
                        let _ = db.set_meta("cliproxyapi_installed_version", version.trim());
                    }
                }
            }
        })?;
    Ok(())
}

fn run_global_accept_loop(
    listener: &std::os::unix::net::UnixListener,
    write_tx: &mpsc::Sender<WriteCommand>,
    read_tx: &mpsc::Sender<ReadCommand>,
    active_conns: Arc<AtomicUsize>,
    active_sessions: ActiveSessions,
    last_activity: Arc<Mutex<Instant>>,
    restart_pending: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    const MAX_GLOBAL_CONNS: usize = 32;

    listener.set_nonblocking(true)?;
    static LAST_RESTART_EPOCH: AtomicU64 = AtomicU64::new(0);

    {
        let hup_flag = Arc::clone(&restart_pending);
        signal_hook::flag::register(signal_hook::consts::SIGHUP, hup_flag)?;
    }

    let mut restart_requested_at: Option<Instant> = None;

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if !crate::util::check_peer_uid(&stream, false) {
                    continue;
                }
                if active_conns.load(Ordering::Relaxed) >= MAX_GLOBAL_CONNS {
                    let _ = write_response(&stream, &DaemonResponse::error("too many connections"));
                    continue;
                }
                active_conns.fetch_add(1, Ordering::Relaxed);
                *last_activity.lock().unwrap() = Instant::now();
                let write_tx = write_tx.clone();
                let read_tx = read_tx.clone();
                let active_conns = Arc::clone(&active_conns);
                let last_activity = Arc::clone(&last_activity);
                let active_sessions = Arc::clone(&active_sessions);
                std::thread::spawn(move || {
                    handle_global_connection(stream, write_tx, read_tx, active_sessions);
                    *last_activity.lock().unwrap() = Instant::now();
                    active_conns.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let idle = last_activity.lock().unwrap().elapsed();
                if idle > Duration::from_secs(300) {
                    tracing::info!("nshd: idle timeout, shutting down");
                    log_daemon("server.lifecycle", "idle timeout reached; shutting down");
                    break;
                }
                if restart_pending.load(Ordering::Relaxed) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let last = LAST_RESTART_EPOCH.load(Ordering::Relaxed);
                    if now.saturating_sub(last) < 30 {
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
                        std::thread::sleep(Duration::from_secs(2));
                        LAST_RESTART_EPOCH.store(now, Ordering::Relaxed);
                    }
                    let drained = active_conns.load(Ordering::Relaxed) == 0;
                    let timed_out = restart_requested_at
                        .map(|started| started.elapsed() > Duration::from_secs(10))
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
                let restart_marker = crate::config::Config::nsh_dir().join("nshd_restart_pending");
                if restart_marker.exists() {
                    log_daemon("server.lifecycle", "restart marker detected, shutting down");
                    restart_pending.store(true, Ordering::Relaxed);
                    notify_sessions_about_hook_restart(&active_sessions);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                tracing::warn!("nshd: accept error: {error}");
                log_daemon("server.accept.error", &error.to_string());
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Ok(())
}

fn notify_sessions_about_hook_restart(active_sessions: &ActiveSessions) {
    let dir = crate::config::Config::nsh_dir();
    if let Ok(guard) = active_sessions.read() {
        for (session_id, info) in guard.iter() {
            if let Some(pid) = info.pid
                && !pid_alive(pid)
            {
                continue;
            }
            if let Some(tty) = &info.tty
                && !std::path::Path::new(tty).exists()
            {
                continue;
            }
            let message = match info.shell.as_deref() {
                Some("zsh") => "hooks_updated: zsh will auto-reload when idle\n",
                Some("bash") => "hooks_updated: bash will refresh hooks on next prompt\n",
                Some("fish") => "hooks_updated: fish auto-reloads hooks\n",
                _ => "hooks_updated\n",
            };
            let _ = std::fs::write(dir.join(format!("nsh_msg_{}", session_id)), message);
        }
    }
}

fn maybe_reexec_global_daemon(
    restart_pending: &Arc<AtomicBool>,
    restart_cooldown_marker: &std::path::Path,
) {
    if !restart_pending.load(Ordering::Relaxed) {
        return;
    }

    let args: Vec<String> = std::env::args().collect();
    let core_path = crate::config::Config::nsh_dir()
        .join("bin")
        .join("nsh-core");
    let target = if core_path.exists() {
        core_path
    } else if let Ok(exe) = std::env::current_exe() {
        exe
    } else {
        let cargo_home = std::env::var("CARGO_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| dirs::home_dir().unwrap_or_default().join(".cargo"));
        let cargo_nsh = cargo_home.join("bin").join("nsh");
        if cargo_nsh.exists() {
            cargo_nsh
        } else {
            tracing::error!("cannot find binary for re-exec");
            return;
        }
    };
    let _ = std::fs::write(restart_cooldown_marker, chrono::Utc::now().to_rfc3339());
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(&target).args(&args[1..]).exec();
    tracing::info!("nshd re-exec failed: {err}");
}

pub fn run_global_daemon() -> anyhow::Result<()> {
    log_daemon("server.lifecycle", "starting global daemon");
    let restart_cooldown_marker = crate::config::Config::nsh_dir().join("nshd-restart-at");
    apply_restart_cooldown(&restart_cooldown_marker);

    let lock_file = match acquire_global_daemon_lock()? {
        Some(lock_file) => lock_file,
        None => return Ok(()),
    };
    detach_global_daemon();

    let pid_path = write_global_pid_file()?;
    let (socket_path, listener) = bind_global_listener()?;
    let (write_db, read_dbs) = open_daemon_datastores()?;
    let (config, memory, memory_queue_guards, memory_task_tracker, memory_tx, memory_thread) =
        start_memory_runtime()?;
    let (write_tx, read_tx, write_thread, read_threads) = start_db_worker_threads(
        write_db,
        read_dbs,
        Arc::clone(&memory),
        memory_task_tracker.clone(),
        memory_tx.clone(),
        memory_queue_guards.clone(),
    )?;
    schedule_startup_memory_maintenance(
        &memory,
        &memory_tx,
        &memory_queue_guards,
        &memory_task_tracker,
    );

    let active_conns = Arc::new(AtomicUsize::new(0));
    let active_sessions: ActiveSessions =
        std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let restart_pending = Arc::new(AtomicBool::new(false));

    // Start iroh remote endpoint if enabled
    #[cfg(feature = "remote")]
    let _iroh_handle = if config.remote.enabled {
        match crate::runtime::remote::spawn_iroh_endpoint(&config) {
            Ok(handle) => {
                let node_id_str = crate::runtime::remote_key::load_or_create_secret_key()
                    .map(|k| k.public().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                log_daemon(
                    "server.lifecycle",
                    &format!("iroh remote enabled, EndpointId: {node_id_str}"),
                );
                Some(handle)
            }
            Err(e) => {
                log_daemon("iroh.startup_error", &e.to_string());
                None
            }
        }
    } else {
        None
    };

    // Initialize memory sync engine in a persistent background thread if remote is enabled.
    // The thread keeps its own tokio runtime alive for the engine's async operations.
    #[cfg(feature = "remote")]
    let _memory_sync_handle = if config.remote.enabled {
        match crate::runtime::remote_key::load_or_create_secret_key() {
            Ok(secret_key) => {
                let handle = std::thread::Builder::new()
                    .name("nshd-memory-sync".into())
                    .spawn(move || {
                        let rt = match tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            Ok(rt) => rt,
                            Err(e) => {
                                tracing::warn!("memory sync runtime build failed: {e}");
                                return;
                            }
                        };
                        rt.block_on(async move {
                            match crate::memory::sync::MemorySyncEngine::new(&secret_key).await {
                                Ok(_engine) => {
                                    // Engine initialized; keep runtime alive for future
                                    // background sync operations (currently scaffolding).
                                    // Park indefinitely until process exit.
                                    std::future::pending::<()>().await;
                                }
                                Err(e) => {
                                    tracing::warn!("memory sync init failed: {e}");
                                }
                            }
                        });
                    });
                match handle {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!("memory sync thread spawn failed: {e}");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!("memory sync key load failed: {e}");
                None
            }
        }
    } else {
        None
    };

    spawn_background_monitors(Arc::clone(&restart_pending), Arc::clone(&active_sessions))?;
    run_global_accept_loop(
        &listener,
        &write_tx,
        &read_tx,
        Arc::clone(&active_conns),
        Arc::clone(&active_sessions),
        Arc::clone(&last_activity),
        Arc::clone(&restart_pending),
    )?;

    drop(write_tx);
    drop(read_tx);
    drop(memory_tx);
    let _ = write_thread.join();
    let _ = memory_thread.join();
    for thread in read_threads {
        let _ = thread.join();
    }
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&pid_path);
    log_daemon("server.lifecycle", "stopped global daemon");
    drop(lock_file);

    crate::connectivity::start(&config);
    maybe_reexec_global_daemon(&restart_pending, &restart_cooldown_marker);
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
    memory_task_tracker: MemoryTaskTracker,
    memory_tx: MemoryTaskSender,
    queue_guards: MemoryQueueGuards,
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

        for cmd in batch {
            let resp = execute_write(
                &db,
                cmd.request,
                &memory,
                &memory_task_tracker,
                &memory_tx,
                &queue_guards,
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
    queue_guards: MemoryQueueGuards,
    memory_task_tracker: MemoryTaskTracker,
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
    // Each task is executed via block_on for the async LLM calls, wrapped in
    // catch_unwind to prevent a panic from killing the memory thread.
    while let Ok(task) = rx.recv() {
        let task_kind = MemoryTaskKind::from_task(&task);
        let task_name = task_kind.status_key();
        memory_task_tracker.mark_running(task_kind);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match task {
            MemoryTask::FlushIngestion => rt.block_on(async {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(120),
                    memory.flush_ingestion(&llm),
                )
                .await
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("timed out after 120s".to_string()),
                }
            }),
            MemoryTask::IngestBatch { events } => rt.block_on(async {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(120),
                    memory.ingest_batch(&events, &llm),
                )
                .await
                {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("timed out after 120s".to_string()),
                }
            }),
            MemoryTask::RunDecay => rt.block_on(async {
                match tokio::time::timeout(std::time::Duration::from_secs(120), async {
                    memory.flush_ingestion(&llm).await?;
                    memory.run_decay()?;
                    Ok::<(), anyhow::Error>(())
                })
                .await
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("timed out after 120s".to_string()),
                }
            }),
            MemoryTask::RunReflection => rt.block_on(async {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(120),
                    memory.run_reflection(&llm),
                )
                .await
                {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("timed out after 120s".to_string()),
                }
            }),
            MemoryTask::BootstrapScan => rt.block_on(async {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(120),
                    memory.bootstrap_scan(&llm),
                )
                .await
                {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(error)) => Err(error.to_string()),
                    Err(_) => Err("timed out after 120s".to_string()),
                }
            }),
        }));

        // Always clear queue flags, even after panic, so maintenance work can be retried.
        match task_name {
            "run_decay" => {
                queue_guards.decay_pending.store(false, Ordering::SeqCst);
            }
            "run_reflection" => {
                queue_guards
                    .reflection_pending
                    .store(false, Ordering::SeqCst);
            }
            "bootstrap_scan" => {
                queue_guards
                    .bootstrap_pending
                    .store(false, Ordering::SeqCst);
            }
            _ => {}
        }
        match result {
            Ok(Ok(())) => {
                memory_task_tracker.mark_succeeded(task_kind);
            }
            Ok(Err(error)) => {
                tracing::warn!("memory {task_name} failed: {error}");
                log_daemon(task_kind.error_log_key(), &error);
                memory_task_tracker.mark_failed(task_kind, error);
            }
            Err(error) => {
                let panic_message = format!("panic in {task_name}: {error:?}");
                log_daemon("memory.thread.panic", &panic_message);
                memory_task_tracker.mark_failed(task_kind, panic_message);
            }
        }
    }

    log_daemon("memory.thread", "memory thread exiting");
}

fn execute_write(
    db: &crate::db::Db,
    request: DaemonRequest,
    memory: &crate::memory::MemorySystem,
    memory_task_tracker: &MemoryTaskTracker,
    memory_tx: &MemoryTaskSender,
    queue_guards: &MemoryQueueGuards,
    session_project_roots: &mut std::collections::HashMap<String, String>,
) -> DaemonResponse {
    try_execute_write(
        db,
        request,
        memory,
        memory_task_tracker,
        memory_tx,
        queue_guards,
        session_project_roots,
    )
    .unwrap_or_else(|error| DaemonResponse::error(format!("{error:#}")))
}

fn rollback_failed_command_record(
    db: &crate::db::Db,
    command_id: i64,
    error: anyhow::Error,
) -> anyhow::Error {
    match db.delete_command_by_id(command_id) {
        Ok(()) => error,
        Err(cleanup_error) => error.context(format!(
            "failed to remove partially recorded command {command_id}: {cleanup_error}"
        )),
    }
}

fn try_execute_write(
    db: &crate::db::Db,
    request: DaemonRequest,
    memory: &crate::memory::MemorySystem,
    memory_task_tracker: &MemoryTaskTracker,
    memory_tx: &MemoryTaskSender,
    queue_guards: &MemoryQueueGuards,
    session_project_roots: &mut std::collections::HashMap<String, String>,
) -> anyhow::Result<DaemonResponse> {
    let req_dbg = format!("{request:?}");
    log_daemon("server.execute_write.request", &req_dbg);
    match request {
        DaemonRequest::Restart => {
            // Handled in accept loop via marker file; acknowledge
            let marker = crate::config::Config::nsh_dir().join("nshd_restart_pending");
            std::fs::write(&marker, "").with_context(|| {
                format!("failed to write restart marker at {}", marker.display())
            })?;
            Ok(DaemonResponse::ok())
        }
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
            let id = db
                .insert_command(
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
                )
                .with_context(|| {
                    format!("failed to record command `{command}` for session `{session}`")
                })?;

            let output_text = output.as_deref().unwrap_or("");
            let required_side_effects = (|| -> anyhow::Result<()> {
                if let Some(trivial) =
                    crate::summary::trivial_summary(&command, exit_code, output_text)
                {
                    db.update_summary(id, &trivial).with_context(|| {
                        format!("failed to persist trivial summary for command record {id}")
                    })?;
                }

                if let Some((conv_id, suggested_cmd)) = db
                    .find_pending_conversation(&session)
                    .with_context(|| {
                        format!(
                            "failed to look up pending conversation after recording command {id} for session `{session}`"
                        )
                    })?
                {
                    if command.trim() == suggested_cmd.trim() {
                        let snippet = crate::util::truncate(output_text, 500);
                        let snippet_ref = if snippet.is_empty() {
                            None
                        } else {
                            Some(snippet.as_str())
                        };
                        db.update_conversation_result(conv_id, exit_code, snippet_ref)
                            .with_context(|| {
                                format!(
                                    "failed to update pending conversation {conv_id} for command record {id}"
                                )
                            })?;
                    } else {
                        let correction = format!(
                            "User ran different command: {}",
                            crate::util::truncate(&command, 200)
                        );
                        db.update_conversation_result(conv_id, exit_code, Some(&correction))
                            .with_context(|| {
                                format!(
                                    "failed to mark pending conversation {conv_id} as superseded by command record {id}"
                                )
                            })?;
                    }
                }

                Ok(())
            })();

            if let Err(error) = required_side_effects {
                return Err(rollback_failed_command_record(db, id, error));
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

            if command.starts_with("ssh ") || command == "ssh" {
                if let Err(error) = db.backfill_command_entities_if_needed() {
                    tracing::warn!(
                        "failed to backfill command entities after recording command {id} for session `{session}`: {error}"
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

            Ok(DaemonResponse::ok_with_payload(serde_json::json!({"id": id})))
        }
        DaemonRequest::Heartbeat { session } => {
            db.update_heartbeat(&session)
                .with_context(|| format!("failed to update heartbeat for session `{session}`"))?;
            crate::daemon::generate_pending_summaries(db);
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::CreateSession {
            session,
            tty,
            shell,
            pid,
        } => {
            db.create_session(&session, &tty, &shell, pid)
                .with_context(|| format!("failed to create session `{session}`"))?;
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
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::EndSession { session } => {
            db.end_session(&session)
                .with_context(|| format!("failed to end session `{session}`"))?;
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
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::SetSessionLabel {
            session,
            label,
            caller,
        } => {
            if let Err(error) = authorize_session_access(db, &caller, &session) {
                return Ok(DaemonResponse::error(format!(
                    "Security check failed: {error}"
                )));
            }
            let updated = db
                .set_session_label(&session, &label)
                .with_context(|| format!("failed to set label for session `{session}`"))?;
            Ok(DaemonResponse::ok_with_payload(
                crate::daemon::SessionLabelUpdatePayload { updated },
            ))
        }
        DaemonRequest::ClearConversations { session, caller } => {
            if let Err(error) = authorize_session_access(db, &caller, &session) {
                return Ok(DaemonResponse::error(format!(
                    "Security check failed: {error}"
                )));
            }
            db.clear_conversations(&session).with_context(|| {
                format!("failed to clear conversations for session `{session}`")
            })?;
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::InsertConversation {
            session_id,
            query,
            response_type,
            response,
            explanation,
            executed,
            pending,
            caller,
        } => {
            if let Err(error) = authorize_session_access(db, &caller, &session_id) {
                return Ok(DaemonResponse::error(format!(
                    "Security check failed: {error}"
                )));
            }
            let id = db
                .insert_conversation(
                    &session_id,
                    &query,
                    response_type.as_str(),
                    &response,
                    explanation.as_deref(),
                    executed,
                    pending,
                )
                .with_context(|| {
                    format!("failed to insert conversation for session `{session_id}`")
                })?;
            Ok(DaemonResponse::ok_with_payload(serde_json::json!({"id": id})))
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
            caller,
        } => {
            if let Err(error) = authorize_session_access(db, &caller, &session_id) {
                return Ok(DaemonResponse::error(format!(
                    "Security check failed: {error}"
                )));
            }
            let id = db
                .insert_usage(
                    &session_id,
                    query_text.as_deref(),
                    &model,
                    &provider,
                    input_tokens,
                    output_tokens,
                    cost_usd,
                    generation_id.as_deref(),
                )
                .with_context(|| format!("failed to insert usage for session `{session_id}`"))?;
            Ok(DaemonResponse::ok_with_payload(serde_json::json!({"id": id})))
        }
        DaemonRequest::UpdateConversationResult {
            conv_id,
            exit_code,
            output_snippet,
            caller,
        } => {
            match db.conversation_session_id(conv_id) {
                Ok(Some(session_id)) => {
                    if let Err(error) = authorize_session_access(db, &caller, &session_id) {
                        return Ok(DaemonResponse::error(format!(
                            "Security check failed: {error}"
                        )));
                    }
                }
                Ok(None) => {} // conversation not found — update will be a no-op
                Err(error) => {
                    return Ok(DaemonResponse::error(format!(
                        "Security check failed: could not verify conversation ownership: {error}"
                    )));
                }
            }
            db.update_conversation_result(conv_id, exit_code, output_snippet.as_deref())
                .with_context(|| format!("failed to update conversation result for {conv_id}"))?;
            Ok(DaemonResponse::ok())
        }

        DaemonRequest::SetMeta { key, value } => {
            db.set_meta(&key, &value)
                .with_context(|| format!("failed to set metadata key `{key}`"))?;
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::Prune { retention_days } => {
            let count = db.prune(retention_days).with_context(|| {
                format!("failed to prune records older than {retention_days} days")
            })?;
            Ok(DaemonResponse::ok_with_payload(
                serde_json::json!({"pruned": count}),
            ))
        }
        DaemonRequest::RebuildFts => {
            db.rebuild_fts().context("failed to rebuild FTS indexes")?;
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::CleanupOrphanedSessions => {
            let count = db
                .cleanup_orphaned_sessions()
                .context("failed to clean up orphaned sessions")?;
            Ok(DaemonResponse::ok_with_payload(
                serde_json::json!({"cleaned": count}),
            ))
        }
        DaemonRequest::UpdateSummary { id, summary } => {
            let updated = db
                .update_summary(id, &summary)
                .with_context(|| format!("failed to update summary for command {id}"))?;
            Ok(DaemonResponse::ok_with_payload(
                serde_json::json!({"updated": updated}),
            ))
        }
        DaemonRequest::MarkSummaryError { id, error } => {
            db.mark_summary_error(id, &error)
                .with_context(|| format!("failed to mark summary error for command {id}"))?;
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::UpdateUsageCost {
            generation_id,
            cost,
        } => {
            let updated = db
                .update_usage_cost(&generation_id, cost)
                .with_context(|| {
                    format!("failed to update usage cost for generation `{generation_id}`")
                })?;
            Ok(DaemonResponse::ok_with_payload(
                serde_json::json!({"updated": updated}),
            ))
        }
        DaemonRequest::MarkUnsummarizedForLlm => {
            let count = db
                .mark_unsummarized_for_llm()
                .context("failed to mark unsummarized commands for LLM processing")?;
            Ok(DaemonResponse::ok_with_payload(
                serde_json::json!({"count": count}),
            ))
        }
        DaemonRequest::BackfillEntities => {
            let count = db
                .backfill_command_entities_if_needed()
                .context("failed to backfill command entities")?;
            Ok(DaemonResponse::ok_with_payload(
                serde_json::json!({"backfilled": count}),
            ))
        }
        DaemonRequest::GenerateSummaries | DaemonRequest::SummarizeCheck { .. } => {
            crate::daemon::generate_pending_summaries(db);
            Ok(DaemonResponse::ok())
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
                    Ok(DaemonResponse::ok())
                }
                Err(e) => Ok(DaemonResponse::error(format!("invalid event JSON: {e}"))),
            }
        }
        DaemonRequest::MemoryFlushIngestion => {
            if memory_tx.send(MemoryTask::FlushIngestion).is_err() {
                tracing::debug!("memory thread disconnected, flush skipped");
            }
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::MemoryIngestBatch { events_json } => {
            match serde_json::from_str::<Vec<crate::memory::types::ShellEvent>>(&events_json) {
                Ok(events) => {
                    if memory_tx.send(MemoryTask::IngestBatch { events }).is_err() {
                        tracing::debug!("memory thread disconnected, ingest skipped");
                    }
                    Ok(DaemonResponse::ok())
                }
                Err(e) => Ok(DaemonResponse::error(format!("invalid events JSON: {e}"))),
            }
        }
        DaemonRequest::MemoryCoreAppend {
            label,
            content,
            caller,
        } => {
            let op = crate::memory::types::CoreOp::Append;
            let lbl = crate::memory::types::CoreLabel::from_str(&label)
                .map_err(|_| DaemonResponse::error(format!("invalid core label: {label}")));
            match lbl {
                Err(e) => Ok(e),
                Ok(l) => {
                    let input = serde_json::json!({
                        "label": label,
                        "content": content,
                    });
                    if let Err(error) =
                        authorize_memory_tool_request(&caller, "core_memory_append", &input)
                    {
                        return Ok(DaemonResponse::error(format!(
                            "Security check failed: {error}"
                        )));
                    }
                    memory
                        .update_core_block(l, op, &content)
                        .with_context(|| format!("failed to append core memory block `{label}`"))?;
                    Ok(DaemonResponse::ok())
                }
            }
        }
        DaemonRequest::MemoryCoreRewrite {
            label,
            content,
            caller,
        } => {
            let op = crate::memory::types::CoreOp::Rewrite;
            let lbl = crate::memory::types::CoreLabel::from_str(&label)
                .map_err(|_| DaemonResponse::error(format!("invalid core label: {label}")));
            match lbl {
                Err(e) => Ok(e),
                Ok(l) => {
                    let input = serde_json::json!({
                        "label": label,
                        "content": content,
                    });
                    if let Err(error) =
                        authorize_memory_tool_request(&caller, "core_memory_rewrite", &input)
                    {
                        return Ok(DaemonResponse::error(format!(
                            "Security check failed: {error}"
                        )));
                    }
                    memory.update_core_block(l, op, &content).with_context(|| {
                        format!("failed to rewrite core memory block `{label}`")
                    })?;
                    Ok(DaemonResponse::ok())
                }
            }
        }
        DaemonRequest::MemoryStore {
            memory_type,
            data_json,
            caller,
        } => {
            let parsed_data = match parse_memory_json(&data_json) {
                Ok(parsed_data) => parsed_data,
                Err(error) => return Ok(DaemonResponse::error(error)),
            };
            let input = serde_json::json!({
                "memory_type": memory_type.as_str(),
                "data": parsed_data
            });
            if let Err(error) = authorize_memory_tool_request(&caller, "store_memory", &input) {
                return Ok(DaemonResponse::error(format!(
                    "Security check failed: {error}"
                )));
            }
            use crate::daemon_db::DbAccess;
            let id = DbAccess::memory_store(db, memory_type, &data_json).with_context(|| {
                format!("failed to store {} memory entry", memory_type.as_str())
            })?;
            Ok(DaemonResponse::ok_with_payload(serde_json::json!({"id": id})))
        }
        DaemonRequest::MemoryDelete {
            memory_type,
            id,
            confirmed,
            caller,
        } => {
            if let Err(error) = require_sensitive_memory_confirmation("memory delete", confirmed) {
                return Ok(DaemonResponse::error(format!(
                    "Security check failed: {error}"
                )));
            }
            audit_sensitive_daemon_action(
                &caller,
                "memory_delete",
                &format!("{}:{id}", memory_type.as_str()),
            )?;
            memory.delete_memory(memory_type, &id).with_context(|| {
                format!("failed to delete {} memory `{id}`", memory_type.as_str())
            })?;
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::MemoryRunDecay => {
            queue_memory_task_response(
                memory_tx,
                queue_guards,
                memory_task_tracker,
                MemoryTask::RunDecay,
            )
        }
        DaemonRequest::MemoryRunReflection => {
            queue_memory_task_response(
                memory_tx,
                queue_guards,
                memory_task_tracker,
                MemoryTask::RunReflection,
            )
        }
        DaemonRequest::MemoryBootstrapScan => {
            queue_memory_task_response(
                memory_tx,
                queue_guards,
                memory_task_tracker,
                MemoryTask::BootstrapScan,
            )
        }
        DaemonRequest::MemoryClearAll { confirmed, caller } => {
            if let Err(error) = require_sensitive_memory_confirmation("memory clear-all", confirmed)
            {
                return Ok(DaemonResponse::error(format!(
                    "Security check failed: {error}"
                )));
            }
            audit_sensitive_daemon_action(&caller, "memory_clear_all", "all")?;
            memory
                .clear_all()
                .context("failed to clear all memory data")?;
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::MemoryClearByType {
            memory_type,
            confirmed,
            caller,
        } => {
            if let Err(error) =
                require_sensitive_memory_confirmation("memory clear-by-type", confirmed)
            {
                return Ok(DaemonResponse::error(format!(
                    "Security check failed: {error}"
                )));
            }
            audit_sensitive_daemon_action(&caller, "memory_clear_by_type", memory_type.as_str())?;
            db.clear_memories_by_type(memory_type).with_context(|| {
                format!("failed to clear {} memory records", memory_type.as_str())
            })?;
            Ok(DaemonResponse::ok())
        }
        DaemonRequest::RunDoctor {
            retention_days,
            no_prune,
            no_vacuum,
        } => {
            let config = crate::config::Config::load().unwrap_or_default();
            db.run_doctor(retention_days, no_prune, no_vacuum, &config)
                .context("failed to run doctor checks")?;
            Ok(DaemonResponse::ok())
        }
        other => {
            let _ = other;
            let resp = DaemonResponse::error("unexpected write request");
            log_daemon("server.execute_write.response", &format!("{resp:?}"));
            Ok(resp)
        }
    }
}

fn enqueue_unique_memory_task(
    memory_tx: &MemoryTaskSender,
    queue_guards: &MemoryQueueGuards,
    task: MemoryTask,
) -> anyhow::Result<MemoryQueueDecision> {
    let pending_flag = match task {
        MemoryTask::RunDecay => Some(&queue_guards.decay_pending),
        MemoryTask::RunReflection => Some(&queue_guards.reflection_pending),
        MemoryTask::BootstrapScan => Some(&queue_guards.bootstrap_pending),
        _ => None,
    };

    if let Some(flag) = pending_flag
        && flag
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
    {
        return Ok(MemoryQueueDecision::Busy);
    }

    if memory_tx.send(task).is_err() {
        if let Some(flag) = pending_flag {
            flag.store(false, Ordering::SeqCst);
        }
        anyhow::bail!("memory thread disconnected");
    }

    Ok(MemoryQueueDecision::Enqueued)
}

fn queue_memory_task(
    memory_tx: &MemoryTaskSender,
    queue_guards: &MemoryQueueGuards,
    memory_task_tracker: &MemoryTaskTracker,
    task: MemoryTask,
) -> anyhow::Result<MemoryQueueDecision> {
    let task_kind = MemoryTaskKind::from_task(&task);
    let decision = enqueue_unique_memory_task(memory_tx, queue_guards, task)?;
    if matches!(decision, MemoryQueueDecision::Enqueued) {
        memory_task_tracker.mark_queued(task_kind);
    }
    Ok(decision)
}

fn queue_memory_task_response(
    memory_tx: &MemoryTaskSender,
    queue_guards: &MemoryQueueGuards,
    memory_task_tracker: &MemoryTaskTracker,
    task: MemoryTask,
) -> anyhow::Result<DaemonResponse> {
    let task_kind = MemoryTaskKind::from_task(&task);
    let task_name = task_kind.status_key();
    match queue_memory_task(memory_tx, queue_guards, memory_task_tracker, task) {
        Ok(status) => Ok(DaemonResponse::ok_with_payload(serde_json::json!({
            "status": status.as_status(),
            "task": memory_task_tracker.task_snapshot(task_kind),
        }))),
        Err(error) => {
            memory_task_tracker.mark_failed(task_kind, error.to_string());
            tracing::debug!("memory thread disconnected, {task_name} skipped: {error}");
            Err(error)
        }
    }
}

fn run_read_thread(
    db: crate::db::Db,
    rx: Arc<Mutex<mpsc::Receiver<ReadCommand>>>,
    memory: Arc<crate::memory::MemorySystem>,
    memory_task_tracker: MemoryTaskTracker,
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
        let resp = execute_read(&db, &memory, &memory_task_tracker, cmd.request);
        let _ = cmd.reply.send(resp);
    }
}

fn execute_read(
    db: &crate::db::Db,
    memory: &crate::memory::MemorySystem,
    memory_task_tracker: &MemoryTaskTracker,
    request: DaemonRequest,
) -> DaemonResponse {
    let req_dbg = format!("{request:?}");
    log_daemon("server.execute_read.request", &req_dbg);
    match request {
        DaemonRequest::GetVersion => {
            DaemonResponse::ok_with_payload(crate::daemon::DaemonStatusPayload {
                version: env!("CARGO_PKG_VERSION").to_string(),
                build_version: env!("NSH_BUILD_VERSION").to_string(),
                build_fingerprint: env!("NSH_BUILD_FINGERPRINT").to_string(),
                pid: None,
                daemon_type: None,
                protocol_version: Some(crate::daemon::DAEMON_PROTOCOL_VERSION),
                wrapper_protocol_version: None,
            })
        }
        DaemonRequest::SearchHistory { query, limit } => match db.search_history(&query, limit) {
            Ok(results) => {
                DaemonResponse::ok_with_payload(crate::daemon::HistorySearchPayload { results })
            }
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::GetConversations {
            session,
            limit,
            caller,
        } => {
            if let Err(error) = authorize_session_access(db, &caller, &session) {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
            match db.get_conversations(&session, limit) {
                Ok(conversations) => {
                    DaemonResponse::ok_with_payload(crate::daemon::ConversationsPayload {
                        conversations,
                    })
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::FindPendingConversation { session, caller } => {
            if let Err(error) = authorize_session_access(db, &caller, &session) {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
            match db.find_pending_conversation(&session) {
                Ok(Some((id, cmd))) => {
                    DaemonResponse::ok_with_payload(serde_json::json!({"id": id, "command": cmd}))
                }
                Ok(None) => DaemonResponse::ok_with_payload(serde_json::json!({"found": false})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::LatestCwdForTty { tty } => match db.latest_cwd_for_tty(&tty) {
            Ok(cwd) => DaemonResponse::ok_with_payload(crate::daemon::LatestCwdPayload { cwd }),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::GetUsageStats { period } => {
            match db.get_usage_stats(period) {
                Ok(stats) => {
                    let payload = crate::daemon::UsageStatsPayload {
                        stats: stats
                            .into_iter()
                            .map(|(model, calls, input_tokens, output_tokens, cost_usd)| {
                                crate::daemon::UsageStatsEntry {
                                    model,
                                    calls,
                                    input_tokens,
                                    output_tokens,
                                    cost_usd,
                                }
                            })
                            .collect(),
                    };
                    DaemonResponse::ok_with_payload(payload)
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }

        DaemonRequest::GetMeta { key } => match db.get_meta(&key) {
            Ok(value) => DaemonResponse::ok_with_payload(serde_json::json!({"value": value})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::GetSessionLabel { session, caller } => {
            if let Err(error) = authorize_session_access(db, &caller, &session) {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
            match db.get_session_label(&session) {
                Ok(label) => {
                    DaemonResponse::ok_with_payload(crate::daemon::SessionLabelPayload { label })
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::RecentCommandsWithSummaries {
            session,
            limit,
            caller,
        } => {
            if let Err(error) = authorize_session_access(db, &caller, &session) {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
            match db.recent_commands_with_summaries(&session, limit) {
                Ok(cmds) => {
                    let json: Vec<serde_json::Value> = cmds.iter().map(|c| {
                        serde_json::json!({
                            "command": c.command, "cwd": c.cwd, "exit_code": c.exit_code,
                            "started_at": c.started_at, "duration_ms": c.duration_ms, "summary": c.summary,
                            "output": c.output,
                        })
                    }).collect();
                    DaemonResponse::ok_with_payload(serde_json::json!({"commands": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::OtherSessionsWithSummaries {
            session,
            max_ttys,
            summaries_per_tty,
            caller,
        } => {
            if let Err(error) = authorize_session_access(db, &caller, &session) {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
            match db.other_sessions_with_summaries(&session, max_ttys, summaries_per_tty) {
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
                    DaemonResponse::ok_with_payload(serde_json::json!({"commands": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
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
                    DaemonResponse::ok_with_payload(serde_json::json!({"results": json}))
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
                    DaemonResponse::ok_with_payload(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::CommandCount => match db.command_count() {
            Ok(count) => DaemonResponse::ok_with_payload(serde_json::json!({"count": count})),
            Err(e) => DaemonResponse::error(format!("{e}")),
        },
        DaemonRequest::CommandsNeedingSummary { limit } => {
            match db.commands_needing_summary(limit) {
                Ok(cmds) => {
                    let json: Vec<serde_json::Value> = cmds.iter().map(|c| {
                        serde_json::json!({"id": c.id, "command": c.command, "cwd": c.cwd, "exit_code": c.exit_code, "output": c.output})
                    }).collect();
                    DaemonResponse::ok_with_payload(serde_json::json!({"commands": json}))
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
                    DaemonResponse::ok_with_payload(serde_json::json!({"commands": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::Status => {
            DaemonResponse::ok_with_payload(crate::daemon::DaemonStatusPayload {
                version: env!("CARGO_PKG_VERSION").to_string(),
                build_version: env!("NSH_BUILD_VERSION").to_string(),
                build_fingerprint: env!("NSH_BUILD_FINGERPRINT").to_string(),
                pid: Some(std::process::id()),
                daemon_type: Some("global".to_string()),
                protocol_version: None,
                wrapper_protocol_version: None,
            })
        }
        DaemonRequest::GetSystemInfo => {
            let static_info = crate::context::load_or_refresh_static_info();
            let semi_dynamic = crate::context::load_or_refresh_semi_dynamic_info();
            let (cpu_samples, memory_usage, load_average) =
                crate::context::load_or_sample_volatile_info();
            let bundle = crate::context::SystemInfoBundle {
                static_info: static_info.to_snapshot(),
                semi_dynamic: semi_dynamic.to_snapshot(),
                cpu_samples,
                memory_usage,
                load_average,
            };
            match serde_json::to_value(bundle) {
                Ok(value) => DaemonResponse::ok_with_payload(value),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        // ── Memory read operations ──────────────────────
        DaemonRequest::MemoryRetrieve {
            context_json,
            caller,
        } => {
            let input = serde_json::json!({ "context_json_len": context_json.len() });
            if let Err(error) =
                authorize_memory_tool_request(&caller, "memory_retrieve", &input)
            {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
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
                            DaemonResponse::ok_with_payload(serde_json::json!({
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
            memory_type,
            limit,
            caller,
        } => {
            let input = serde_json::json!({ "query": &query });
            if let Err(error) =
                authorize_memory_tool_request(&caller, "memory_search", &input)
            {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
            // Use MemorySystem search across all types for now
            match memory.search(&query, exclude_core_from_search(memory_type), limit) {
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
                    DaemonResponse::ok_with_payload(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MemoryGetCore { caller } => {
            let input = serde_json::json!({});
            if let Err(error) =
                authorize_memory_tool_request(&caller, "memory_get_core", &input)
            {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
            match memory.core_memory() {
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
                    DaemonResponse::ok_with_payload(serde_json::json!({"blocks": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MemoryRetrieveSecret {
            caption_query,
            caller,
        } => {
            let input = serde_json::json!({ "caption_query": caption_query });
            if let Err(error) = authorize_memory_tool_request(&caller, "retrieve_secret", &input) {
                return DaemonResponse::error(format!("Security check failed: {error}"));
            }
            if let Err(error) =
                audit_sensitive_daemon_action(&caller, "retrieve_secret", &caption_query)
            {
                return DaemonResponse::error(format!("{error:#}"));
            }
            match db.search_knowledge_fts(&caption_query, 3, &["low", "medium", "high"]) {
                Ok(results) => {
                    let json: Vec<serde_json::Value> = results
                        .iter()
                        .map(|r| {
                            let decrypted = if !r.secret_value.is_empty() {
                                crate::memory::store::knowledge_crypto::decrypt_secret(
                                    &r.secret_value,
                                )
                                .unwrap_or_else(|_| "[Decryption Failed]".into())
                            } else {
                                String::new()
                            };
                            serde_json::json!({
                                "id": r.id,
                                "caption": r.caption,
                                "entry_type": r.entry_type,
                                "sensitivity": r.sensitivity.as_str(),
                                "secret_value": decrypted,
                            })
                        })
                        .collect();
                    DaemonResponse::ok_with_payload(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MemoryExportAll => match memory.export_all() {
            Ok(data) => DaemonResponse::ok_with_payload(data),
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

                    DaemonResponse::ok_with_payload(serde_json::json!({
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
                        "background_tasks": memory_task_tracker.snapshot_json(),
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
    use super::{execute_read, MemoryTaskTracker};
    use crate::daemon::{DaemonRequest, DaemonResponse};

    #[test]
    fn memory_stats_includes_telemetry() {
        // In-memory DB and MemorySystem
        let db = crate::db::Db::open_in_memory().expect("db");
        let mem = crate::memory::MemorySystem::open_in_memory().expect("mem");
        let tracker = MemoryTaskTracker::default();
        // Seed telemetry
        db.set_memory_config("decay_runs", "9").unwrap();
        db.set_memory_config("reflection_runs", "3").unwrap();
        db.set_memory_config("last_decay_at", "2026-02-21 12:34:56")
            .unwrap();
        db.set_memory_config("last_reflection_at", "2026-02-20 08:10:11")
            .unwrap();

        let resp = execute_read(&db, &mem, &tracker, DaemonRequest::MemoryStats);
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
                assert_eq!(d["background_tasks"]["run_decay"]["state"].as_str(), Some("idle"));
                assert_eq!(
                    d["background_tasks"]["run_reflection"]["state"].as_str(),
                    Some("idle")
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
    active_sessions: std::sync::Arc<
        std::sync::RwLock<std::collections::HashMap<String, SessionInfo>>,
    >,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));

    let payload = match nsh_proto::sync_framing::read_frame(&mut &stream) {
        Ok(data) => data,
        Err(_) => return,
    };

    let request: DaemonRequest = match serde_json::from_slice(&payload) {
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
    log_daemon(
        "server.connection.request",
        &String::from_utf8_lossy(&payload),
    );
    // Track active session IDs for per-session notifications (in-memory)
    match &request {
        DaemonRequest::CreateSession {
            session,
            tty,
            shell,
            pid,
        } => {
            if let Ok(mut guard) = active_sessions.write() {
                guard.insert(
                    session.clone(),
                    SessionInfo {
                        last_seen: Instant::now(),
                        tty: Some(tty.clone()),
                        shell: Some(shell.clone()),
                        pid: Some(*pid),
                    },
                );
            }
        }
        DaemonRequest::Heartbeat { session } => {
            if let Ok(mut guard) = active_sessions.write() {
                guard
                    .entry(session.clone())
                    .and_modify(|info| info.last_seen = Instant::now())
                    .or_insert(SessionInfo {
                        last_seen: Instant::now(),
                        tty: None,
                        shell: None,
                        pid: None,
                    });
            }
        }
        DaemonRequest::EndSession { session } => {
            if let Ok(mut guard) = active_sessions.write()
                && let Some(info) = guard.remove(session)
            {
                cleanup_session_artifacts(session, &info);
            }
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
            Ok(port) => DaemonResponse::ok_with_payload(serde_json::json!({"port": port})),
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
            let (last_check, last_status, installed_version) = match crate::db::Db::open_readonly()
            {
                Ok(db) => {
                    let lc = db.get_meta("cliproxyapi_last_update_check").ok().flatten();
                    let ls = db.get_meta("cliproxyapi_last_update_status").ok().flatten();
                    let iv = db.get_meta("cliproxyapi_installed_version").ok().flatten();
                    (lc, ls, iv)
                }
                Err(_) => (None, None, None),
            };
            Some(DaemonResponse::ok_with_payload(
                crate::daemon::CLIProxyApiStatusPayload {
                    running,
                    port,
                    version,
                    pid,
                    last_update_check: last_check,
                    last_update_status: last_status,
                    installed_version,
                },
            ))
        }
        DaemonRequest::CLIProxyApiRestart => {
            let _ = crate::cliproxyapi::stop_sidecar();
            Some(match crate::cliproxyapi::ensure_running() {
                Ok(port) => DaemonResponse::ok_with_payload(serde_json::json!({"port": port})),
                Err(e) => DaemonResponse::error(e.to_string()),
            })
        }
        DaemonRequest::StopCLIProxyApi => Some(match crate::cliproxyapi::stop_sidecar() {
            Ok(()) => DaemonResponse::ok(),
            Err(e) => DaemonResponse::error(e.to_string()),
        }),
        DaemonRequest::CheckForUpdates => {
            let _ = std::thread::Builder::new()
                .name("nshd-update-check".into())
                .spawn(|| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    if let Ok(rt) = rt {
                        rt.block_on(async move {
                            if let Ok(Some((url, version))) =
                                crate::cliproxyapi::check_for_update().await
                            {
                                let _ =
                                    crate::cliproxyapi::download_and_install(&url, &version).await;
                            }
                        });
                    }
                });
            Some(DaemonResponse::ok())
        }
        #[cfg(feature = "remote")]
        DaemonRequest::RemoteStatus => {
            let config = crate::config::Config::load().unwrap_or_default();
            let node_id = crate::runtime::remote_key::load_or_create_secret_key()
                .ok()
                .map(|k| k.public().to_string());
            let (peers, sessions) = crate::runtime::remote::live_peer_counts();
            Some(DaemonResponse::ok_with_payload(
                crate::runtime::remote::RemoteStatusPayload {
                    enabled: config.remote.enabled,
                    node_id,
                    relay_url: crate::runtime::remote::home_relay_url(),
                    connected_peers: peers,
                    attached_sessions: sessions,
                },
            ))
        }
        #[cfg(feature = "remote")]
        DaemonRequest::RemoteRevoke { node_id } => {
            match crate::config::remove_remote_allowed_key(node_id) {
                Ok(true) => Some(DaemonResponse::ok()),
                Ok(false) => Some(DaemonResponse::error("key not found")),
                Err(e) => Some(DaemonResponse::error(e.to_string())),
            }
        }
        #[cfg(feature = "remote")]
        DaemonRequest::SubscribeEvents { .. } => {
            Some(DaemonResponse::error("event subscription not yet implemented"))
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
            | DaemonRequest::MemoryClearAll { .. }
            | DaemonRequest::MemoryClearByType { .. }
            | DaemonRequest::RemoteRevoke { .. }
    )
}

/// Walk up from `cwd` to find a project root (directory containing `.git`, `Cargo.toml`,
/// `package.json`, `go.mod`, `pyproject.toml`, etc.). Returns the root path string,
/// or `None` if the CWD is at or above the home directory with no markers.
fn detect_project_root_fast(cwd: &str) -> Option<String> {
    use std::path::Path;

    // Skip project detection for paths under ~/.nsh/ (skills, config, etc.)
    if let Some(nsh_dir) = dirs::home_dir().map(|h| h.join(".nsh")) {
        if Path::new(cwd).starts_with(&nsh_dir) {
            return None;
        }
    }

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
                // Canonicalize to handle symlinks consistently
                return Some(
                    dir.canonicalize()
                        .ok()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| dir.to_string_lossy().to_string()),
                );
            }
        }
        // Stop at home directory or filesystem root
        if let Some(ref h) = home
            && dir == h.as_path()
        {
            return None;
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
    let json_bytes = serde_json::to_vec(&json_val)
        .unwrap_or_else(|_| br#"{"status":"error","message":"serialize error"}"#.to_vec());
    nsh_proto::sync_framing::write_frame(&mut w, &json_bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        audit_sensitive_daemon_action_with, enqueue_unique_memory_task, execute_read,
        execute_write, handle_global_connection, is_write_request, parse_memory_json,
        sensitive_daemon_audit_fields, MemoryQueueDecision, MemoryQueueGuards, MemoryTask,
        MemoryTaskTracker, ReadCommand, WriteCommand,
    };
    use crate::daemon::{DaemonRequest, DaemonResponse};
    use crate::test_support::EnvVarGuard;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

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
            let sessions =
                std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
            handle_global_connection(server, write_tx, read_tx, sessions);
        });

        // Send request as length-prefixed frame
        let req_bytes = request_line.as_bytes();
        nsh_proto::sync_framing::write_frame(&mut client, req_bytes)
            .expect("write request to daemon conn");

        let write_cmd = write_rx.recv_timeout(Duration::from_millis(300)).ok();
        let read_cmd = read_rx.recv_timeout(Duration::from_millis(300)).ok();

        if let Some(cmd) = &write_cmd {
            let _ = cmd
                .reply
                .send(DaemonResponse::ok_with_payload(serde_json::json!({
                    "routed": "write"
                })));
        }
        if let Some(cmd) = &read_cmd {
            let _ = cmd
                .reply
                .send(DaemonResponse::ok_with_payload(serde_json::json!({
                    "routed": "read"
                })));
        }

        // Read response as length-prefixed frame
        let response_bytes = nsh_proto::sync_framing::read_frame(&mut client)
            .expect("read daemon response");
        let response = String::from_utf8_lossy(&response_bytes).to_string();

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

    #[test]
    fn parse_memory_json_rejects_invalid_json() {
        let err = parse_memory_json("{not-json").expect_err("invalid JSON should fail");
        assert!(err.contains("invalid memory tool JSON"));
    }

    #[test]
    fn execute_read_rejects_cross_tty_session_access() {
        let db = crate::db::Db::open_in_memory().expect("open db");
        db.create_session("caller", "/dev/pts/0", "zsh", 1)
            .expect("create caller");
        db.create_session("target", "/dev/pts/1", "zsh", 2)
            .expect("create target");
        db.insert_conversation("target", "q", "chat", "r", None, false, false)
            .expect("insert conversation");
        let memory = crate::memory::MemorySystem::open_in_memory().expect("open memory");
        let tracker = MemoryTaskTracker::default();

        let response = execute_read(
            &db,
            &memory,
            &tracker,
            DaemonRequest::GetConversations {
                session: "target".into(),
                limit: 10,
                caller: crate::daemon::CallerContext {
                    session: Some("caller".into()),
                    explicit_user_request: None,
                },
            },
        );

        match response {
            DaemonResponse::Error { message } => {
                assert!(message.contains("Security check failed"));
                assert!(message.contains("cannot access session"));
            }
            other => panic!("expected access error, got {other:?}"),
        }
    }

    #[test]
    fn execute_read_requires_explicit_user_request_for_secret_lookup() {
        let db = crate::db::Db::open_in_memory().expect("open db");
        let memory = crate::memory::MemorySystem::open_in_memory().expect("open memory");
        let tracker = MemoryTaskTracker::default();

        let response = execute_read(
            &db,
            &memory,
            &tracker,
            DaemonRequest::MemoryRetrieveSecret {
                caption_query: "prod api".into(),
                caller: crate::daemon::CallerContext {
                    session: Some("caller".into()),
                    explicit_user_request: None,
                },
            },
        );

        match response {
            DaemonResponse::Error { message } => {
                assert!(message.contains("Security check failed"));
                assert!(message.contains("explicitly requests"));
            }
            other => panic!("expected secret access error, got {other:?}"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn execute_read_audits_authorized_secret_lookup() {
        let home = tempfile::tempdir().expect("temp home");
        let _home_guard = EnvVarGuard::set("HOME", home.path());
        let _xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let _xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        std::fs::create_dir_all(crate::config::Config::nsh_dir()).expect("create nsh dir");

        let db = crate::db::Db::open_in_memory().expect("open db");
        db.store_knowledge_memory(
            "token",
            "Production API key",
            "sk-prod-123",
            crate::memory::types::Sensitivity::High,
            "prod api key",
        )
        .expect("store knowledge");
        let memory = crate::memory::MemorySystem::open_in_memory().expect("open memory");
        let tracker = MemoryTaskTracker::default();

        let response = execute_read(
            &db,
            &memory,
            &tracker,
            DaemonRequest::MemoryRetrieveSecret {
                caption_query: "Production API".into(),
                caller: crate::daemon::CallerContext {
                    session: Some("caller".into()),
                    explicit_user_request: Some("show me the production api key".into()),
                },
            },
        );

        match response {
            DaemonResponse::Ok { data: Some(data) } => {
                let results = data["results"].as_array().expect("results array");
                assert_eq!(results.len(), 1);
                assert_eq!(results[0]["caption"], "Production API key");
            }
            other => panic!("expected ok response, got {other:?}"),
        }
    }

    #[test]
    fn sensitive_daemon_audit_fields_use_caller_context() {
        let caller = crate::daemon::CallerContext {
            session: Some("caller".into()),
            explicit_user_request: Some("show me the production api key".into()),
        };

        let (session, query, response) =
            sensitive_daemon_audit_fields(&caller, "retrieve_secret", "Production API");

        assert_eq!(session, "caller");
        assert_eq!(query, "show me the production api key");
        assert_eq!(response, "Production API");
    }

    #[test]
    fn audit_sensitive_daemon_action_surfaces_audit_failures() {
        let caller = crate::daemon::CallerContext {
            session: Some("caller".into()),
            explicit_user_request: Some("show me the production api key".into()),
        };

        let error = audit_sensitive_daemon_action_with(
            &caller,
            "retrieve_secret",
            "Production API",
            |_, _, _, _, _| Err(anyhow::anyhow!("disk full")),
        )
        .expect_err("audit error should surface");

        assert!(
            error
                .to_string()
                .contains("failed to audit sensitive daemon action `retrieve_secret`"),
            "unexpected message: {error:#}"
        );
        assert!(format!("{error:#}").contains("disk full"));
    }

    #[test]
    fn execute_write_requires_confirmation_for_memory_clear_all() {
        let db = crate::db::Db::open_in_memory().expect("open db");
        let memory = crate::memory::MemorySystem::open_in_memory().expect("open memory");
        let tracker = MemoryTaskTracker::default();
        let (memory_tx, _memory_rx) = mpsc::channel();
        let queue_guards = MemoryQueueGuards::new();
        let mut session_project_roots = std::collections::HashMap::new();

        let response = execute_write(
            &db,
            DaemonRequest::MemoryClearAll {
                confirmed: false,
                caller: crate::daemon::CallerContext::default(),
            },
            &memory,
            &tracker,
            &memory_tx,
            &queue_guards,
            &mut session_project_roots,
        );

        match response {
            DaemonResponse::Error { message } => {
                assert!(message.contains("Security check failed"));
                assert!(message.contains("explicit confirmation"));
            }
            other => panic!("expected confirmation error, got {other:?}"),
        }
    }

    #[test]
    fn enqueue_unique_memory_task_deduplicates_decay() {
        let (memory_tx, memory_rx) = mpsc::channel();
        let queue_guards = MemoryQueueGuards::new();

        assert!(matches!(
            enqueue_unique_memory_task(&memory_tx, &queue_guards, MemoryTask::RunDecay)
                .expect("first enqueue"),
            MemoryQueueDecision::Enqueued
        ));
        assert!(matches!(
            enqueue_unique_memory_task(&memory_tx, &queue_guards, MemoryTask::RunDecay)
                .expect("second enqueue"),
            MemoryQueueDecision::Busy
        ));
        assert!(matches!(
            memory_rx.recv().expect("queued task"),
            MemoryTask::RunDecay
        ));
    }

    #[test]
    fn execute_write_queues_memory_decay_task() {
        let db = crate::db::Db::open_in_memory().expect("open db");
        let memory = crate::memory::MemorySystem::open_in_memory().expect("open memory");
        let tracker = MemoryTaskTracker::default();
        let (memory_tx, memory_rx) = mpsc::channel();
        let queue_guards = MemoryQueueGuards::new();
        let mut session_project_roots = std::collections::HashMap::new();

        let response = execute_write(
            &db,
            DaemonRequest::MemoryRunDecay,
            &memory,
            &tracker,
            &memory_tx,
            &queue_guards,
            &mut session_project_roots,
        );

        match response {
            DaemonResponse::Ok { data: Some(data) } => {
                assert_eq!(data["status"].as_str(), Some("queued"));
                assert_eq!(data["task"]["state"].as_str(), Some("queued"));
            }
            other => panic!("expected queued response, got {other:?}"),
        }
        assert!(matches!(
            memory_rx.recv().expect("queued task"),
            MemoryTask::RunDecay
        ));
    }

    #[test]
    fn execute_write_rolls_back_record_when_summary_side_effect_fails() {
        let db = crate::db::Db::open_in_memory().expect("open db");
        db.conn_execute_batch(
            "
            CREATE TRIGGER fail_summary_update
            BEFORE UPDATE OF summary ON commands
            BEGIN
                SELECT RAISE(ABORT, 'summary write blocked');
            END;
            ",
        )
        .expect("install summary failure trigger");
        let memory = crate::memory::MemorySystem::open_in_memory().expect("open memory");
        let tracker = MemoryTaskTracker::default();
        let (memory_tx, _memory_rx) = mpsc::channel();
        let queue_guards = MemoryQueueGuards::new();
        let mut session_project_roots = std::collections::HashMap::new();

        let response = execute_write(
            &db,
            DaemonRequest::Record {
                session: "sess-1".into(),
                command: "true".into(),
                cwd: "/tmp".into(),
                exit_code: 0,
                started_at: "2026-02-01T10:00:00Z".into(),
                tty: "/dev/pts/0".into(),
                pid: 1234,
                shell: "zsh".into(),
                duration_ms: Some(12),
                output: None,
            },
            &memory,
            &tracker,
            &memory_tx,
            &queue_guards,
            &mut session_project_roots,
        );

        match response {
            DaemonResponse::Error { message } => {
                assert!(
                    message.contains("failed to persist trivial summary"),
                    "unexpected message: {message}"
                );
                assert!(
                    message.contains("summary write blocked"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected record failure, got {other:?}"),
        }

        assert_eq!(db.command_count().expect("count commands"), 0);
    }
}
