use crate::config::Config;
use crate::provider::{self, ChatRequest, ContentBlock, Message, Role, ToolChoice};

pub async fn execute(query: &str, config: &Config) -> anyhow::Result<String> {
    let ws_provider_name = &config.web_search.provider;
    let ws_model = &config.web_search.model;

    let provider = match provider::create_provider(ws_provider_name, config) {
        Ok(p) => p,
        Err(e) => {
            if ws_provider_name == "ollama" {
                anyhow::bail!(
                    "Web search not available with provider ollama. \
                     Configure [web_search] provider to use openrouter or another search-capable provider."
                );
            }
            return Err(e);
        }
    };

    let request = ChatRequest {
        model: ws_model.clone(),
        system: "Provide a concise factual answer with sources. Be brief.".into(),
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: query.to_string(),
            }],
        }],
        tools: vec![],
        tool_choice: ToolChoice::None,
        max_tokens: 1024,
        stream: false,
        extra_body: None,
    };

    let response = provider.complete(request).await?;

    let text = response
        .content
        .iter()
        .filter_map(|b| {
            if let ContentBlock::Text { text } = b {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    if text.is_empty() {
        Ok("No results returned.".into())
    } else {
        Ok(text)
    }
}
