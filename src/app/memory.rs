use crate::cli::MemoryAction;

pub(super) fn handle_memory_command(action: MemoryAction) -> anyhow::Result<()> {
    if !super::daemon_runtime::ensure_daemon_ready(false)? {
        return Ok(());
    }
    match action {
        MemoryAction::Search {
            query,
            r#type,
            limit,
        } => {
            let request = crate::daemon::DaemonRequest::MemorySearch {
                query,
                memory_type: match r#type {
                    Some(memory_type) => {
                        Some(crate::memory::types::MemoryType::parse(&memory_type)?)
                    }
                    None => None,
                },
                limit,
                caller: crate::daemon::current_caller_context(),
            };
            match super::daemon_runtime::send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                crate::daemon::DaemonResponse::Ok { data: None } => {
                    println!("No results");
                }
                crate::daemon::DaemonResponse::Error { message } => {
                    eprintln!("error: {message}");
                }
            }
        }
        MemoryAction::Stats => {
            let request = crate::daemon::DaemonRequest::MemoryStats;
            match super::daemon_runtime::send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                crate::daemon::DaemonResponse::Ok { data: None } => {
                    eprintln!("nsh: no memory stats available");
                }
                crate::daemon::DaemonResponse::Error { message } => {
                    eprintln!("nsh: memory stats failed: {message}");
                }
            }
        }
        MemoryAction::Core => {
            let request = crate::daemon::DaemonRequest::MemoryGetCore {
                caller: crate::daemon::current_caller_context(),
            };
            match super::daemon_runtime::send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                crate::daemon::DaemonResponse::Ok { data: None } => {
                    eprintln!("nsh: no core memory blocks found");
                }
                crate::daemon::DaemonResponse::Error { message } => {
                    eprintln!("nsh: core memory read failed: {message}");
                }
            }
        }
        MemoryAction::Maintain => {
            eprintln!("Queueing memory decay...");
            if let Err(e) = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryRunDecay,
            ) {
                eprintln!("nsh: failed to queue decay: {e}");
            }
            eprintln!("Queueing memory reflection...");
            if let Err(e) = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryRunReflection,
            ) {
                eprintln!("nsh: failed to queue reflection: {e}");
            }
            eprintln!("Memory maintenance queued.");
        }
        MemoryAction::Bootstrap => {
            eprintln!("Queueing memory bootstrap scan...");
            if let Err(e) = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryBootstrapScan,
            ) {
                eprintln!("nsh: failed to queue bootstrap: {e}");
            }
            eprintln!("Bootstrap scan queued.");
        }
        MemoryAction::Clear { r#type } => {
            if let Some(ref memory_type) = r#type {
                let parsed_type = match crate::memory::types::MemoryType::parse(memory_type) {
                    Ok(memory_type) => memory_type,
                    Err(_) => {
                        eprintln!(
                            "Unknown memory type '{}'. Valid types: episodic, semantic, procedural, resource, knowledge, core",
                            memory_type,
                        );
                        return Ok(());
                    }
                };
                if let Err(e) = super::daemon_runtime::send_to_global_or_fallback(
                    &crate::daemon::DaemonRequest::MemoryClearByType {
                        memory_type: parsed_type,
                        confirmed: true,
                        caller: crate::daemon::current_caller_context(),
                    },
                ) {
                    eprintln!("nsh: failed to clear {memory_type} memories: {e}");
                } else {
                    eprintln!("{memory_type} memories cleared.");
                }
            } else if let Err(e) = super::daemon_runtime::send_to_global_or_fallback(
                    &crate::daemon::DaemonRequest::MemoryClearAll {
                        confirmed: true,
                        caller: crate::daemon::current_caller_context(),
                    },
                ) {
                    eprintln!("nsh: failed to clear all memories: {e}");
                } else {
                    eprintln!("All memories cleared.");
            }
        }
        MemoryAction::Decay => {
            if let Err(e) = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryRunDecay,
            ) {
                eprintln!("nsh: failed to queue decay: {e}");
            } else {
                eprintln!("Memory decay queued.");
            }
        }
        MemoryAction::Reflect => {
            if let Err(e) = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryRunReflection,
            ) {
                eprintln!("nsh: failed to queue reflection: {e}");
            } else {
                eprintln!("Memory reflection queued.");
            }
        }
        MemoryAction::Export { format: _ } => {
            let request = crate::daemon::DaemonRequest::MemoryExportAll;
            match super::daemon_runtime::send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                crate::daemon::DaemonResponse::Ok { data: None } => {
                    eprintln!("nsh: no memory data to export");
                }
                crate::daemon::DaemonResponse::Error { message } => {
                    eprintln!("nsh: memory export failed: {message}");
                }
            }
        }
        MemoryAction::Telemetry => {
            let request = crate::daemon::DaemonRequest::MemoryStats;
            match super::daemon_runtime::global_daemon_payload::<
                crate::daemon::MemoryTelemetryPayload,
            >(&request)
            {
                Ok(telemetry) => println!("{}", serde_json::to_string_pretty(&telemetry)?),
                Err(error) => eprintln!("error: {error}"),
            }
        }
    }
    Ok(())
}
