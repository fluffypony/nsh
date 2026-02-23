//! GitHub repository access tool — uses the public REST API.
//!
//! Actions:
//!   - `fetch_readme`    — Fetch README, optionally summarize for a goal
//!   - `fetch_tree`      — Recursive file listing with depth limit
//!   - `fetch_file`      — Fetch a single file by path
//!
//! Public repos need no authentication (60 req/hr per IP).
//! If `GITHUB_TOKEN` env var is set, it's used opportunistically (5000 req/hr).

use crate::config::Config;
use crate::provider::{self, ChatRequest, ContentBlock, Message, Role, ToolChoice};
use reqwest::Url;
use std::time::Duration;

/// Parse `owner/repo` from either "owner/repo" or a full GitHub URL like
/// "https://github.com/owner/repo" or "https://github.com/owner/repo/blob/main/path".
/// Returns `(owner, repo, optional_path)`.
fn parse_repo_spec(input: &str) -> anyhow::Result<(String, String, Option<String>)> {
    let input = input.trim().trim_end_matches('/');

    // Full URL
    if input.starts_with("http://") || input.starts_with("https://") {
        if let Ok(url) = Url::parse(input) {
            let segments: Vec<&str> = url
                .path_segments()
                .map(|c| c.collect())
                .unwrap_or_default();
            if segments.len() >= 2 {
                let owner = segments[0].to_string();
                let repo = segments[1].trim_end_matches(".git").to_string();
                let path = if segments.len() > 3 {
                    // skip "blob"/"tree" + branch
                    Some(segments[3..].join("/"))
                } else {
                    None
                };
                return Ok((owner, repo, path));
            }
        }
        anyhow::bail!("Could not parse GitHub URL: {input}");
    }

    // owner/repo format
    let parts: Vec<&str> = input.splitn(2, '/').collect();
    if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        Ok((parts[0].to_string(), parts[1].to_string(), None))
    } else {
        anyhow::bail!(
            "Invalid repo format '{input}'. Expected 'owner/repo' or a full GitHub URL."
        )
    }
}

/// Build a reqwest client with the required User-Agent header.
/// Optionally attaches `Authorization: Bearer <token>` if GITHUB_TOKEN is set.
fn build_client() -> anyhow::Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static("nsh-github-tool"),
    );
    headers.insert(
        "X-GitHub-Api-Version",
        reqwest::header::HeaderValue::from_static("2022-11-28"),
    );

    // Opportunistically use GITHUB_TOKEN if available (raises rate limit to 5000/hr)
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(reqwest::header::AUTHORIZATION, val);
            }
        }
    }

    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .build()?)
}

/// Check rate-limit headers and emit a warning if running low.
fn check_rate_limit(headers: &reqwest::header::HeaderMap) {
    if let Some(remaining) = headers.get("x-ratelimit-remaining") {
        if let Ok(s) = remaining.to_str() {
            if let Ok(n) = s.parse::<u32>() {
                if n <= 5 {
                    let th = crate::tui::theme::current_theme();
                    eprintln!(
                        "  {}⚠ GitHub API rate limit nearly exhausted ({} remaining){}",
                        th.warning,
                        n,
                        th.reset
                    );
                }
            }
        }
    }
}

/// Main tool entry point — dispatches on `action`.
pub async fn execute(input: &serde_json::Value, config: &Config) -> anyhow::Result<String> {
    let action = input["action"].as_str().unwrap_or("");
    let repo_spec = input["repo"].as_str().unwrap_or("");

    if repo_spec.is_empty() {
        anyhow::bail!("github: 'repo' is required (owner/repo or full URL)");
    }

    let (owner, repo, url_path) = parse_repo_spec(repo_spec)?;
    let client = build_client()?;

    match action {
        "fetch_readme" => {
            let goal = input["goal"].as_str().unwrap_or("");
            fetch_readme(&client, &owner, &repo, goal, config).await
        }
        "fetch_tree" => {
            let depth = input["depth"].as_u64().unwrap_or(2).min(5) as usize;
            fetch_tree(&client, &owner, &repo, depth).await
        }
        "fetch_file" => {
            // Use path from input, or fall back to path parsed from URL
            let path = input["path"]
                .as_str()
                .map(String::from)
                .or(url_path)
                .unwrap_or_default();
            if path.is_empty() {
                anyhow::bail!("github: 'path' is required for fetch_file");
            }
            fetch_file(&client, &owner, &repo, &path).await
        }
        _ => anyhow::bail!(
            "github: unknown action '{action}'. Use fetch_readme, fetch_tree, or fetch_file."
        ),
    }
}

// ─── fetch_readme ────────────────────────────────────────────────────

async fn fetch_readme(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    goal: &str,
    config: &Config,
) -> anyhow::Result<String> {
    // Use the GitHub API endpoint which auto-detects README variants
    let url = format!("https://api.github.com/repos/{owner}/{repo}/readme");
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github.v3.raw")
        .send()
        .await?;

    if !resp.status().is_success() {
        // Fallback: try raw.githubusercontent.com
        let fallback = format!("https://raw.githubusercontent.com/{owner}/{repo}/HEAD/README.md");
        let resp2 = client.get(&fallback).send().await?;
        if !resp2.status().is_success() {
            anyhow::bail!(
                "Failed to fetch README for {}/{}: HTTP {}",
                owner,
                repo,
                resp.status()
            );
        }
        let content = resp2.text().await?;
        return process_readme_content(&content, goal, config).await;
    }

    check_rate_limit(resp.headers());
    let content = resp.text().await?;
    process_readme_content(&content, goal, config).await
}

async fn process_readme_content(
    content: &str,
    goal: &str,
    config: &Config,
) -> anyhow::Result<String> {
    if goal.trim().is_empty() {
        // No goal — return truncated raw content
        return Ok(crate::util::truncate(content, 8000).to_string());
    }

    // Feed through fast LLM to extract only goal-relevant information
    let provider = provider::create_provider(&config.provider.default, config)?;
    let model = config
        .models
        .fast
        .first()
        .cloned()
        .unwrap_or_else(|| config.provider.model.clone());

    let prompt = format!(
        "Extract information from the following README to answer this goal.\n\n\
         Goal: {}\n\n\
         README:\n{}",
        goal,
        crate::util::truncate(content, 60000)
    );

    let request = ChatRequest {
        model,
        system: "You are a concise extraction assistant. Extract exactly what is needed \
                 to satisfy the goal. Omit unnecessary details. If the README doesn't \
                 contain the answer, say so clearly."
            .into(),
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text { text: prompt }],
        }],
        tools: vec![],
        tool_choice: ToolChoice::None,
        max_tokens: 2000,
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

    Ok(text)
}

// ─── fetch_tree ──────────────────────────────────────────────────────

async fn fetch_tree(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    depth: usize,
) -> anyhow::Result<String> {
    // First, detect the default branch
    let repo_url = format!("https://api.github.com/repos/{owner}/{repo}");
    let repo_resp = client.get(&repo_url).send().await?;
    check_rate_limit(repo_resp.headers());

    let default_branch = if repo_resp.status().is_success() {
        let repo_json: serde_json::Value = repo_resp.json().await?;
        repo_json["default_branch"]
            .as_str()
            .unwrap_or("main")
            .to_string()
    } else {
        "main".to_string()
    };

    // Fetch the full recursive tree
    let tree_url = format!(
        "https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1"
    );
    let resp = client.get(&tree_url).send().await?;
    check_rate_limit(resp.headers());

    if !resp.status().is_success() {
        anyhow::bail!(
            "Failed to fetch tree for {}/{}: HTTP {}",
            owner,
            repo,
            resp.status()
        );
    }

    let json: serde_json::Value = resp.json().await?;
    let mut paths = Vec::new();

    if let Some(tree) = json["tree"].as_array() {
        for item in tree {
            if let Some(path) = item["path"].as_str() {
                // Filter by depth: count slashes
                let slashes = path.chars().filter(|c| *c == '/').count();
                if slashes < depth {
                    let item_type = item["type"].as_str().unwrap_or("blob");
                    let prefix = if item_type == "tree" { "dir " } else { "file" };
                    paths.push(format!("{prefix} {path}"));
                }
            }
        }
    }

    if paths.is_empty() {
        Ok("No files found or repository is empty.".into())
    } else {
        let out = paths.join("\n");
        Ok(crate::util::truncate(&out, 8000).to_string())
    }
}

// ─── fetch_file ──────────────────────────────────────────────────────

async fn fetch_file(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
    path: &str,
) -> anyhow::Result<String> {
    // Try raw.githubusercontent.com first (doesn't consume API rate limit)
    for branch in &["HEAD", "main", "master"] {
        let url = format!(
            "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    );
        let resp = client.get(&url).send().await?;
        if resp.status().is_success() {
            let content = resp.text().await?;
            return Ok(crate::util::truncate(&content, 32000).to_string());
        }
    }

    // Fallback to API
    let url = format!("https://api.github.com/repos/{owner}/{repo}/contents/{path}");
    let resp = client
        .get(&url)
        .header("Accept", "application/vnd.github.v3.raw")
        .send()
        .await?;

    check_rate_limit(resp.headers());

    if !resp.status().is_success() {
        anyhow::bail!(
            "Failed to fetch file {}/{}/{}: HTTP {}",
            owner,
            repo,
            path,
            resp.status()
        );
    }

    let content = resp.text().await?;
    Ok(crate::util::truncate(&content, 32000).to_string())
}
