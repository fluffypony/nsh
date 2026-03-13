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
                response => eprintln!("{response:?}"),
            }
        }
        MemoryAction::Core => {
            let request = crate::daemon::DaemonRequest::MemoryGetCore;
            match super::daemon_runtime::send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                response => eprintln!("{response:?}"),
            }
        }
        MemoryAction::Maintain => {
            eprintln!("Running memory decay...");
            let _ = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryRunDecay,
            );
            eprintln!("Running memory reflection...");
            let _ = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryRunReflection,
            );
            eprintln!("Memory maintenance complete.");
        }
        MemoryAction::Bootstrap => {
            eprintln!("Running memory bootstrap scan...");
            let _ = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryBootstrapScan,
            );
            eprintln!("Bootstrap scan complete.");
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
                let _ = super::daemon_runtime::send_to_global_or_fallback(
                    &crate::daemon::DaemonRequest::MemoryClearByType {
                        memory_type: parsed_type,
                        confirmed: true,
                        caller: crate::daemon::current_caller_context(),
                    },
                );
                eprintln!("{memory_type} memories cleared.");
            } else {
                let _ = super::daemon_runtime::send_to_global_or_fallback(
                    &crate::daemon::DaemonRequest::MemoryClearAll {
                        confirmed: true,
                        caller: crate::daemon::current_caller_context(),
                    },
                );
                eprintln!("All memories cleared.");
            }
        }
        MemoryAction::Decay => {
            let _ = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryRunDecay,
            );
            eprintln!("Memory decay complete.");
        }
        MemoryAction::Reflect => {
            let _ = super::daemon_runtime::send_to_global_or_fallback(
                &crate::daemon::DaemonRequest::MemoryRunReflection,
            );
            eprintln!("Memory reflection complete.");
        }
        MemoryAction::Export { format: _ } => {
            let request = crate::daemon::DaemonRequest::MemoryExportAll;
            match super::daemon_runtime::send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                response => eprintln!("{response:?}"),
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
