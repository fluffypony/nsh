use crate::cli::ProviderAction;

pub(super) async fn handle_provider_command(action: ProviderAction) -> anyhow::Result<()> {
    match action {
        ProviderAction::ListLocal => {
            let base_url = crate::config::Config::load()
                .ok()
                .and_then(|config| {
                    config
                        .provider
                        .ollama
                        .as_ref()
                        .and_then(|ollama| ollama.base_url.clone())
                })
                .unwrap_or_else(|| "http://localhost:11434".into());
            let url = format!("{}/api/tags", base_url.trim_end_matches("/v1"));
            match reqwest::get(&url).await {
                Ok(response) if response.status().is_success() => {
                    let json: serde_json::Value = response.json().await?;
                    if let Some(models) = json["models"].as_array() {
                        if models.is_empty() {
                            eprintln!("No models found. Pull one with: ollama pull <model>");
                        } else {
                            eprintln!("Available Ollama models:");
                            for model in models {
                                let name = model["name"].as_str().unwrap_or("?");
                                let size = model["size"].as_u64().unwrap_or(0);
                                let size_gb = size as f64 / 1_073_741_824.0;
                                eprintln!("  {name} ({size_gb:.1} GB)");
                            }
                        }
                    }
                }
                Ok(response) => {
                    eprintln!("Ollama API error: {}", response.status());
                }
                Err(_) => {
                    eprintln!("Could not connect to Ollama at {url}");
                    eprintln!("Is Ollama running? Start it with: ollama serve");
                }
            }
        }
    }
    Ok(())
}
