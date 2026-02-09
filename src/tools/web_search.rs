use crate::config::Config;
use reqwest::Client;
use serde_json::json;

pub async fn execute(
    query: &str,
    config: &Config,
) -> anyhow::Result<String> {
    let auth = config
        .provider
        .openrouter
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "OpenRouter not configured (needed for web search)"
            )
        })?;
    let api_key = auth.resolve_api_key("openrouter")?;
    let base_url = auth
        .base_url
        .as_deref()
        .unwrap_or("https://openrouter.ai/api/v1");

    let body = json!({
        "model": config.provider.web_search_model,
        "messages": [
            {
                "role": "system",
                "content": "Provide a concise factual answer with sources. Be brief."
            },
            {
                "role": "user",
                "content": query
            }
        ],
        "max_tokens": 1024,
        "stream": false
    });

    let client = Client::new();
    let resp = client
        .post(format!("{base_url}/chat/completions"))
        .header("Authorization", format!("Bearer {}", &*api_key))
        .header("HTTP-Referer", "https://github.com/fluffypony/nsh")
        .header("X-Title", "nsh")
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Web search error ({status}): {text}");
    }

    let json: serde_json::Value = resp.json().await?;

    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("No results returned.");

    Ok(content.to_string())
}
