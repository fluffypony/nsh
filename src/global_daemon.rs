use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::daemon::{DaemonRequest, DaemonResponse};

pub fn run_global_daemon() -> anyhow::Result<()> {
    let lock_path = crate::daemon::global_daemon_lock_path();
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
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

    let write_db = crate::db::Db::open()?;
    let _ = write_db.conn_execute_batch("PRAGMA wal_autocheckpoint = 0;");

    let _ = write_db.cleanup_orphaned_sessions();
    crate::history_import::import_if_needed(&write_db);
    let _ = write_db.backfill_command_entities_if_needed();

    let read_dbs: Vec<crate::db::Db> = (0..3)
        .filter_map(|_| crate::db::Db::open_readonly().ok())
        .collect();

    if read_dbs.is_empty() {
        anyhow::bail!("nshd: failed to open any read-only DB connections");
    }

    let (write_tx, write_rx) = mpsc::channel::<WriteCommand>();
    let (read_tx, read_rx) = mpsc::channel::<ReadCommand>();
    let read_rx = Arc::new(Mutex::new(read_rx));

    let write_thread = std::thread::Builder::new()
        .name("nshd-writer".into())
        .spawn(move || {
            run_write_thread(write_db, write_rx);
        })?;

    let read_threads: Vec<_> = read_dbs
        .into_iter()
        .enumerate()
        .map(|(i, db)| {
            let rx = Arc::clone(&read_rx);
            std::thread::Builder::new()
                .name(format!("nshd-reader-{i}"))
                .spawn(move || {
                    run_read_thread(db, rx);
                })
                .unwrap()
        })
        .collect();

    let _checkpoint_thread = std::thread::Builder::new()
        .name("nshd-checkpoint".into())
        .spawn(move || {
            if let Ok(db) = crate::db::Db::open_readonly() {
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                    let _ = db.checkpoint_wal();
                }
            }
        })?;

    let last_activity = Arc::new(Mutex::new(Instant::now()));

    #[cfg(unix)]
    {
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;

        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    if !check_peer_uid(&stream) {
                        continue;
                    }
                    *last_activity.lock().unwrap() = Instant::now();
                    let wt = write_tx.clone();
                    let rt = read_tx.clone();
                    std::thread::spawn(move || {
                        handle_global_connection(stream, wt, rt);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let idle = last_activity.lock().unwrap().elapsed();
                    if idle > Duration::from_secs(300) {
                        tracing::info!("nshd: idle timeout, shutting down");
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    tracing::warn!("nshd: accept error: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    drop(write_tx);
    drop(read_tx);
    let _ = write_thread.join();
    for t in read_threads {
        let _ = t.join();
    }
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&pid_path);
    drop(lock_file);
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

fn run_write_thread(db: crate::db::Db, rx: mpsc::Receiver<WriteCommand>) {
    loop {
        let first = match rx.recv() {
            Ok(cmd) => cmd,
            Err(_) => break,
        };

        let mut batch = vec![first];
        let deadline = Instant::now() + Duration::from_millis(50);
        while Instant::now() < deadline && batch.len() < 10 {
            match rx.try_recv() {
                Ok(cmd) => batch.push(cmd),
                Err(mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }

        if batch.len() > 1 {
            let _ = db.conn_execute_batch("BEGIN IMMEDIATE;");
            for cmd in batch {
                let resp = execute_write(&db, cmd.request);
                let _ = cmd.reply.send(resp);
            }
            let _ = db.conn_execute_batch("COMMIT;");
        } else {
            let cmd = batch.into_iter().next().unwrap();
            let resp = execute_write(&db, cmd.request);
            let _ = cmd.reply.send(resp);
        }
    }
}

fn execute_write(db: &crate::db::Db, request: DaemonRequest) -> DaemonResponse {
    match request {
        DaemonRequest::Record {
            session, command, cwd, exit_code, started_at,
            tty, pid, shell, duration_ms, output,
        } => {
            match db.insert_command(
                &session, &command, &cwd, Some(exit_code), &started_at,
                duration_ms, output.as_deref(), &tty, &shell, pid,
            ) {
                Ok(id) => {
                    if command.starts_with("ssh ") || command == "ssh" {
                        let _ = db.backfill_command_entities_if_needed();
                    }
                    let output_text = output.as_deref().unwrap_or("");
                    if let Some(trivial) = crate::summary::trivial_summary(&command, exit_code, output_text) {
                        let _ = db.update_summary(id, &trivial);
                    }
                    if exit_code == 0 {
                        if let Some((key, value)) = crate::summary::extract_package_association(&command, exit_code) {
                            let _ = db.upsert_memory(&key, &value);
                        }
                    }
                    if let Ok(Some((conv_id, suggested_cmd))) = db.find_pending_conversation(&session) {
                        if command.trim() == suggested_cmd.trim() {
                            let snippet = crate::util::truncate(output_text, 500);
                            let snippet_ref = if snippet.is_empty() { None } else { Some(snippet.as_str()) };
                            let _ = db.update_conversation_result(conv_id, exit_code, snippet_ref);
                        } else {
                            let correction = format!("User ran different command: {}", crate::util::truncate(&command, 200));
                            let _ = db.update_conversation_result(conv_id, exit_code, Some(&correction));
                        }
                    }
                    DaemonResponse::ok_with_data(serde_json::json!({"id": id}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::Heartbeat { session } => {
            match db.update_heartbeat(&session) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::CreateSession { session, tty, shell, pid } => {
            match db.create_session(&session, &tty, &shell, pid) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::EndSession { session } => {
            match db.end_session(&session) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::SetSessionLabel { session, label } => {
            match db.set_session_label(&session, &label) {
                Ok(updated) => DaemonResponse::ok_with_data(serde_json::json!({"updated": updated})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::ClearConversations { session } => {
            match db.clear_conversations(&session) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::InsertConversation {
            session_id, query, response_type, response,
            explanation, executed, pending,
        } => {
            match db.insert_conversation(
                &session_id, &query, &response_type, &response,
                explanation.as_deref(), executed, pending,
            ) {
                Ok(id) => DaemonResponse::ok_with_data(serde_json::json!({"id": id})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::InsertUsage {
            session_id, query_text, model, provider,
            input_tokens, output_tokens, cost_usd, generation_id,
        } => {
            match db.insert_usage(
                &session_id, query_text.as_deref(), &model, &provider,
                input_tokens, output_tokens, cost_usd, generation_id.as_deref(),
            ) {
                Ok(id) => DaemonResponse::ok_with_data(serde_json::json!({"id": id})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::UpdateConversationResult { conv_id, exit_code, output_snippet } => {
            match db.update_conversation_result(conv_id, exit_code, output_snippet.as_deref()) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::UpsertMemory { key, value } => {
            match db.upsert_memory(&key, &value) {
                Ok((id, was_update)) => DaemonResponse::ok_with_data(serde_json::json!({"id": id, "updated": was_update})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::DeleteMemory { id } => {
            match db.delete_memory(id) {
                Ok(deleted) => DaemonResponse::ok_with_data(serde_json::json!({"deleted": deleted})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::UpdateMemory { id, key, value } => {
            match db.update_memory(id, Some(&key), Some(&value)) {
                Ok(updated) => DaemonResponse::ok_with_data(serde_json::json!({"updated": updated})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::SetMeta { key, value } => {
            match db.set_meta(&key, &value) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::Prune { retention_days } => {
            match db.prune(retention_days) {
                Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"pruned": count})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::RebuildFts => {
            match db.rebuild_fts() {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::CleanupOrphanedSessions => {
            match db.cleanup_orphaned_sessions() {
                Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"cleaned": count})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::UpdateSummary { id, summary } => {
            match db.update_summary(id, &summary) {
                Ok(updated) => DaemonResponse::ok_with_data(serde_json::json!({"updated": updated})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MarkSummaryError { id, error } => {
            match db.mark_summary_error(id, &error) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::UpdateUsageCost { generation_id, cost } => {
            match db.update_usage_cost(&generation_id, cost) {
                Ok(updated) => DaemonResponse::ok_with_data(serde_json::json!({"updated": updated})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::MarkUnsummarizedForLlm => {
            match db.mark_unsummarized_for_llm() {
                Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"count": count})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::BackfillEntities => {
            match db.backfill_command_entities_if_needed() {
                Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"backfilled": count})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::GenerateSummaries | DaemonRequest::SummarizeCheck { .. } => {
            crate::daemon::generate_summaries_sync_pub(db);
            DaemonResponse::ok()
        }
        DaemonRequest::RunDoctor { retention_days, no_prune, no_vacuum } => {
            let config = crate::config::Config::load().unwrap_or_default();
            match db.run_doctor(retention_days, no_prune, no_vacuum, &config) {
                Ok(()) => DaemonResponse::ok(),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        other => {
            let _ = other;
            DaemonResponse::error("unexpected write request")
        }
    }
}

fn run_read_thread(db: crate::db::Db, rx: Arc<Mutex<mpsc::Receiver<ReadCommand>>>) {
    loop {
        let cmd = {
            let guard = match rx.lock() {
                Ok(g) => g,
                Err(_) => break,
            };
            match guard.recv() {
                Ok(cmd) => cmd,
                Err(_) => break,
            }
        };
        let resp = execute_read(&db, cmd.request);
        let _ = cmd.reply.send(resp);
    }
}

fn execute_read(db: &crate::db::Db, request: DaemonRequest) -> DaemonResponse {
    match request {
        DaemonRequest::SearchHistory { query, limit } => {
            match db.search_history(&query, limit) {
                Ok(results) => {
                    let json: Vec<serde_json::Value> = results.iter().map(|r| {
                        serde_json::json!({
                            "id": r.id, "session_id": r.session_id, "command": r.command,
                            "cwd": r.cwd, "exit_code": r.exit_code, "started_at": r.started_at,
                            "output": r.output, "cmd_highlight": r.cmd_highlight,
                            "output_highlight": r.output_highlight,
                        })
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::GetConversations { session, limit } => {
            match db.get_conversations(&session, limit) {
                Ok(convos) => {
                    let json: Vec<serde_json::Value> = convos.iter().map(|c| {
                        serde_json::json!({
                            "query": c.query, "response_type": c.response_type,
                            "response": c.response, "explanation": c.explanation,
                            "result_exit_code": c.result_exit_code,
                            "result_output_snippet": c.result_output_snippet,
                        })
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"conversations": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::FindPendingConversation { session } => {
            match db.find_pending_conversation(&session) {
                Ok(Some((id, cmd))) => DaemonResponse::ok_with_data(serde_json::json!({"id": id, "command": cmd})),
                Ok(None) => DaemonResponse::ok_with_data(serde_json::json!({"found": false})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::LatestCwdForTty { tty } => {
            match db.latest_cwd_for_tty(&tty) {
                Ok(cwd) => DaemonResponse::ok_with_data(serde_json::json!({"cwd": cwd})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
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
        DaemonRequest::GetMemories { limit } => {
            match db.get_memories(limit) {
                Ok(memories) => {
                    let json: Vec<serde_json::Value> = memories.iter().map(|m| {
                        serde_json::json!({"id": m.id, "key": m.key, "value": m.value, "created_at": m.created_at, "updated_at": m.updated_at})
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"memories": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::SearchMemories { query } => {
            match db.search_memories(&query) {
                Ok(memories) => {
                    let json: Vec<serde_json::Value> = memories.iter().map(|m| {
                        serde_json::json!({"id": m.id, "key": m.key, "value": m.value, "created_at": m.created_at, "updated_at": m.updated_at})
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"memories": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::GetMeta { key } => {
            match db.get_meta(&key) {
                Ok(value) => DaemonResponse::ok_with_data(serde_json::json!({"value": value})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::GetSessionLabel { session } => {
            match db.get_session_label(&session) {
                Ok(label) => DaemonResponse::ok_with_data(serde_json::json!({"label": label})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::RecentCommandsWithSummaries { session, limit } => {
            match db.recent_commands_with_summaries(&session, limit) {
                Ok(cmds) => {
                    let json: Vec<serde_json::Value> = cmds.iter().map(|c| {
                        serde_json::json!({
                            "command": c.command, "cwd": c.cwd, "exit_code": c.exit_code,
                            "started_at": c.started_at, "duration_ms": c.duration_ms, "summary": c.summary,
                        })
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"commands": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::OtherSessionsWithSummaries { session, max_ttys, summaries_per_tty } => {
            match db.other_sessions_with_summaries(&session, max_ttys, summaries_per_tty) {
                Ok(cmds) => {
                    let json: Vec<serde_json::Value> = cmds.iter().map(|c| {
                        serde_json::json!({
                            "command": c.command, "cwd": c.cwd, "exit_code": c.exit_code,
                            "started_at": c.started_at, "summary": c.summary,
                            "tty": c.tty, "shell": c.shell, "session_id": c.session_id,
                        })
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"commands": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::SearchHistoryAdvanced {
            fts_query, regex_pattern, since, until,
            exit_code, failed_only, session_filter, current_session, limit,
        } => {
            match db.search_history_advanced(
                fts_query.as_deref(), regex_pattern.as_deref(),
                since.as_deref(), until.as_deref(),
                exit_code, failed_only,
                session_filter.as_deref(), current_session.as_deref(), limit,
            ) {
                Ok(results) => {
                    let json: Vec<serde_json::Value> = results.iter().map(|r| {
                        serde_json::json!({
                            "id": r.id, "session_id": r.session_id, "command": r.command,
                            "cwd": r.cwd, "exit_code": r.exit_code, "started_at": r.started_at,
                            "output": r.output, "cmd_highlight": r.cmd_highlight,
                            "output_highlight": r.output_highlight,
                        })
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::SearchCommandEntities {
            executable, entity, entity_type, since, until,
            session_filter, current_session, limit,
        } => {
            match db.search_command_entities(
                executable.as_deref(), entity.as_deref(), entity_type.as_deref(),
                since.as_deref(), until.as_deref(),
                session_filter.as_deref(), current_session.as_deref(), limit,
            ) {
                Ok(results) => {
                    let json: Vec<serde_json::Value> = results.iter().map(|r| {
                        serde_json::json!({
                            "command_id": r.command_id, "session_id": r.session_id,
                            "command": r.command, "cwd": r.cwd, "started_at": r.started_at,
                            "executable": r.executable, "entity": r.entity, "entity_type": r.entity_type,
                        })
                    }).collect();
                    DaemonResponse::ok_with_data(serde_json::json!({"results": json}))
                }
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
        DaemonRequest::CommandCount => {
            match db.command_count() {
                Ok(count) => DaemonResponse::ok_with_data(serde_json::json!({"count": count})),
                Err(e) => DaemonResponse::error(format!("{e}")),
            }
        }
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
        DaemonRequest::Status => {
            DaemonResponse::ok_with_data(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "pid": std::process::id(),
                "daemon_type": "global",
            }))
        }
        DaemonRequest::Scrollback { .. }
        | DaemonRequest::CaptureMark { .. }
        | DaemonRequest::CaptureRead { .. } => {
            DaemonResponse::error("capture operations are per-session only")
        }
        other => {
            let _ = other;
            DaemonResponse::error("unexpected read request")
        }
    }
}

#[cfg(unix)]
fn handle_global_connection(
    stream: std::os::unix::net::UnixStream,
    write_tx: mpsc::Sender<WriteCommand>,
    read_tx: mpsc::Sender<ReadCommand>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }

    let request: DaemonRequest = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = DaemonResponse::error(format!("parse error: {e}"));
            let _ = write_response(&stream, &resp);
            return;
        }
    };

    let (reply_tx, reply_rx) = mpsc::channel();

    let is_write = is_write_request(&request);
    let send_result = if is_write {
        write_tx
            .send(WriteCommand { request, reply: reply_tx })
            .map_err(|_| ())
    } else {
        read_tx
            .send(ReadCommand { request, reply: reply_tx })
            .map_err(|_| ())
    };

    if send_result.is_err() {
        let _ = write_response(&stream, &DaemonResponse::error("daemon shutting down"));
        return;
    }

    match reply_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(resp) => {
            let _ = write_response(&stream, &resp);
        }
        Err(_) => {
            let _ = write_response(&stream, &DaemonResponse::error("timeout"));
        }
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
            | DaemonRequest::UpsertMemory { .. }
            | DaemonRequest::DeleteMemory { .. }
            | DaemonRequest::UpdateMemory { .. }
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
    )
}

#[cfg(unix)]
fn write_response(
    stream: &std::os::unix::net::UnixStream,
    resp: &DaemonResponse,
) -> std::io::Result<()> {
    let mut w = stream;
    let mut json = serde_json::to_string(resp)
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
    #[cfg(target_os = "macos")]
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
    true
}
