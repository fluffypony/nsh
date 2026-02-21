use crate::memory::llm_adapter::MemoryLlmClient;
use crate::memory::types::{InteractionMode, MemoryQueryContext};

pub async fn extract(
    ctx: &MemoryQueryContext,
    llm: Option<&dyn MemoryLlmClient>,
) -> Vec<String> {
    // Try fast path first (handles 60-70% of cases)
    let fast = extract_fast(ctx);
    if !fast.is_empty() {
        return fast;
    }

    // LLM fallback for complex NL queries
    if let Some(llm) = llm {
        if let Ok(keywords) = extract_with_llm(&ctx.query, llm).await {
            if !keywords.is_empty() {
                return keywords;
            }
        }
    }

    // Last resort: basic keyword extraction
    extract_keywords_basic(&ctx.query)
}

fn extract_fast(ctx: &MemoryQueryContext) -> Vec<String> {
    let mut keywords = Vec::new();

    // Error context keywords
    if let Some(ref err) = ctx.error_context {
        keywords.extend(extract_error_keywords(err.stderr.as_deref()));
        let cmd_word = err.command.split_whitespace().next().unwrap_or("");
        if !cmd_word.is_empty() {
            keywords.push(cmd_word.to_string());
        }
    }

    // Command suggestion mode: extract from query directly
    if ctx.interaction_mode == InteractionMode::CommandSuggestion {
        keywords.extend(extract_keywords_basic(&ctx.query));
        return keywords;
    }

    // Temporal expressions
    if let Some(temporal) = extract_temporal_expression(&ctx.query) {
        keywords.push(temporal);
    }

    // Project detection from CWD
    if let Some(ref cwd) = ctx.cwd {
        if let Some(project) = detect_project_from_cwd(cwd) {
            keywords.push(project);
        }
    }

    // Direct noun extraction for short queries
    if ctx.query.split_whitespace().count() <= 5 {
        keywords.extend(extract_keywords_basic(&ctx.query));
    }

    keywords
}

async fn extract_with_llm(input: &str, llm: &dyn MemoryLlmClient) -> anyhow::Result<Vec<String>> {
    let prompt = format!(
        "Extract 3-5 search keywords from this query for memory retrieval. \
         Return ONLY a JSON array of strings, no other text.\n\nQuery: {input}"
    );
    let response = llm.complete_json(&prompt).await?;
    let trimmed = response.trim();
    if let Ok(keywords) = serde_json::from_str::<Vec<String>>(trimmed) {
        Ok(keywords)
    } else {
        Ok(extract_keywords_basic(input))
    }
}

pub fn extract_keywords_basic(input: &str) -> Vec<String> {
    const STOP_WORDS: &[&str] = &[
        "the", "a", "an", "is", "was", "are", "were", "be", "been",
        "have", "has", "had", "do", "does", "did", "will", "would",
        "could", "should", "can", "to", "of", "in", "for", "on",
        "with", "at", "by", "from", "as", "and", "but", "or",
        "not", "no", "so", "if", "than", "that", "this", "it",
        "how", "what", "when", "where", "why", "which", "who",
        "i", "me", "my", "we", "you", "your", "he", "she", "they",
    ];

    input
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|w| w.len() > 2 && !STOP_WORDS.contains(&w.to_lowercase().as_str()))
        .map(|w| w.to_string())
        .take(8)
        .collect()
}

pub fn extract_error_keywords(stderr: Option<&str>) -> Vec<String> {
    let Some(stderr) = stderr else {
        return vec![];
    };

    let mut keywords = Vec::new();
    for line in stderr.lines().take(5) {
        let lower = line.to_lowercase();
        if lower.contains("error") || lower.contains("not found") || lower.contains("failed") {
            for word in line
                .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-' && c != '.')
                .filter(|w| w.len() > 2)
            {
                if keywords.len() < 5 && !keywords.contains(&word.to_string()) {
                    keywords.push(word.to_string());
                }
            }
        }
    }
    keywords
}

fn extract_temporal_expression(input: &str) -> Option<String> {
    let lower = input.to_lowercase();
    let temporal_terms = [
        "yesterday", "today", "last week", "this week",
        "this morning", "this afternoon", "last month",
        "last hour", "recently", "earlier", "two days ago",
    ];
    for term in &temporal_terms {
        if lower.contains(term) {
            return Some(term.to_string());
        }
    }
    None
}

fn detect_project_from_cwd(cwd: &str) -> Option<String> {
    let path = std::path::Path::new(cwd);

    // Check for project manifest files
    let manifests = ["Cargo.toml", "package.json", "go.mod", "pyproject.toml"];
    for manifest in &manifests {
        if path.join(manifest).exists() {
            return path.file_name().map(|n| n.to_string_lossy().to_string());
        }
    }

    // Fall back to directory name if it looks like a project
    if path.join(".git").exists() {
        return path.file_name().map(|n| n.to_string_lossy().to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_keywords_basic_filters() {
        let kw = extract_keywords_basic("how do I build the project with cargo");
        assert!(kw.contains(&"build".to_string()));
        assert!(kw.contains(&"project".to_string()));
        assert!(kw.contains(&"cargo".to_string()));
        assert!(!kw.contains(&"how".to_string()));
        assert!(!kw.contains(&"the".to_string()));
    }

    #[test]
    fn extract_error_keywords_from_stderr() {
        let stderr = "error[E0433]: failed to resolve: could not find `foo` in `bar`";
        let kw = extract_error_keywords(Some(stderr));
        assert!(!kw.is_empty());
    }

    #[test]
    fn extract_temporal_expression_finds() {
        assert_eq!(
            extract_temporal_expression("what did I do yesterday"),
            Some("yesterday".to_string())
        );
        assert_eq!(
            extract_temporal_expression("show me last week commands"),
            Some("last week".to_string())
        );
        assert_eq!(
            extract_temporal_expression("how to build rust"),
            None
        );
    }

    #[test]
    fn extract_error_keywords_empty_stderr() {
        let kw = extract_error_keywords(None);
        assert!(kw.is_empty());
    }

    #[test]
    fn extract_error_keywords_no_error_lines() {
        let kw = extract_error_keywords(Some("all good\nno problems\neverything fine"));
        assert!(kw.is_empty(), "should only extract from error-containing lines");
    }

    #[test]
    fn extract_error_keywords_not_found() {
        let kw = extract_error_keywords(Some("command not found: foobar"));
        assert!(!kw.is_empty());
        assert!(kw.iter().any(|k| k.contains("foobar") || k.contains("found")));
    }

    #[test]
    fn extract_error_keywords_max_5() {
        let stderr = "error: failed to compile very long message with many words in it that should be limited";
        let kw = extract_error_keywords(Some(stderr));
        assert!(kw.len() <= 5, "should limit to 5 keywords");
    }

    #[test]
    fn extract_keywords_basic_empty() {
        let kw = extract_keywords_basic("");
        assert!(kw.is_empty());
    }

    #[test]
    fn extract_keywords_basic_all_stop_words() {
        let kw = extract_keywords_basic("how do I the is and or");
        assert!(kw.is_empty(), "all stop words should be filtered");
    }

    #[test]
    fn extract_keywords_basic_max_8() {
        let text = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10";
        let kw = extract_keywords_basic(text);
        assert!(kw.len() <= 8, "should take at most 8 keywords");
    }

    #[test]
    fn extract_temporal_expression_all_terms() {
        let terms = [
            "yesterday", "today", "last week", "this week",
            "this morning", "this afternoon", "last month",
            "last hour", "recently", "earlier", "two days ago",
        ];
        for term in &terms {
            assert!(extract_temporal_expression(term).is_some(), "should detect: {term}");
        }
    }
}
