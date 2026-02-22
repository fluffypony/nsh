pub fn truncate_output(output: &str, exit_code: Option<i32>, budget_chars: usize) -> String {
    if output.len() <= budget_chars {
        return output.to_string();
    }

    let lines: Vec<&str> = output.lines().collect();
    let is_error = exit_code.is_some_and(|c| c != 0);

    let (head_count, tail_count) = if is_error { (30, 20) } else { (20, 10) };

    if lines.len() <= head_count + tail_count {
        return output.to_string();
    }

    let head: Vec<&str> = lines[..head_count].to_vec();
    let tail: Vec<&str> = lines[lines.len() - tail_count..].to_vec();

    let omitted = &lines[head_count..lines.len() - tail_count];
    let important = extract_important_lines(omitted);

    let mut result = head.join("\n");
    result.push_str(&format!("\n\n[... {} lines omitted ...]\n", omitted.len()));

    if !important.is_empty() {
        result.push_str("[Key lines from omitted section:]\n");
        for line in &important {
            result.push_str(line);
            result.push('\n');
        }
        result.push('\n');
    }

    result.push_str(&tail.join("\n"));

    if result.len() > budget_chars {
        result.truncate(budget_chars);
        result.push_str("\n[truncated]");
    }

    result
}

fn extract_important_lines(lines: &[&str]) -> Vec<String> {
    let important_patterns = [
        "error",
        "warning",
        "failed",
        "deprecated",
        "built",
        "compiled",
        "installed",
        "created",
        "fatal",
        "panic",
        "exception",
        "traceback",
    ];

    let mut result = Vec::new();
    for line in lines {
        let lower = line.to_lowercase();
        if important_patterns.iter().any(|p| lower.contains(p)) {
            result.push(line.to_string());
            if result.len() >= 10 {
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_output_unchanged() {
        let output = "hello world";
        assert_eq!(truncate_output(output, Some(0), 1000), output);
    }

    #[test]
    fn truncates_long_output() {
        let lines: Vec<String> = (0..200)
            .map(|i| format!("line {i}: {}", "x".repeat(50)))
            .collect();
        let output = lines.join("\n");
        let result = truncate_output(&output, Some(0), 2000);
        assert!(result.contains("lines omitted"));
        assert!(result.len() <= 2100);
    }

    #[test]
    fn error_output_preserves_more_head() {
        let lines: Vec<String> = (0..200)
            .map(|i| format!("line {i}: {}", "x".repeat(50)))
            .collect();
        let output = lines.join("\n");
        let result = truncate_output(&output, Some(1), 3000);
        assert!(result.contains("lines omitted"));
    }

    #[test]
    fn extracts_important_lines() {
        let lines = vec![
            "normal line 1",
            "error: compilation failed",
            "normal line 2",
            "warning: unused variable",
            "normal line 3",
        ];
        let important = extract_important_lines(&lines);
        assert_eq!(important.len(), 2);
        assert!(important[0].contains("error"));
        assert!(important[1].contains("warning"));
    }

    #[test]
    fn important_lines_max_10() {
        let lines: Vec<&str> = (0..20).map(|_| "error: something went wrong").collect();
        let important = extract_important_lines(&lines);
        assert!(important.len() <= 10, "should cap at 10 important lines");
    }

    #[test]
    fn truncate_preserves_all_if_few_lines() {
        let output = (0..25)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let result = truncate_output(&output, Some(0), 100000);
        // 25 lines < head(20) + tail(10), so should not truncate
        assert!(!result.contains("omitted"));
    }

    #[test]
    fn truncate_includes_error_lines() {
        let mut lines: Vec<String> = (0..100)
            .map(|i| format!("line {i}: normal output"))
            .collect();
        lines[50] = "error: compilation failed".into();
        lines[60] = "warning: unused variable".into();
        let output = lines.join("\n");
        let result = truncate_output(&output, Some(1), 5000);
        assert!(result.contains("error: compilation failed") || result.contains("Key lines"));
    }

    #[test]
    fn truncate_hard_budget() {
        let lines: Vec<String> = (0..500)
            .map(|i| format!("line {i}: {}", "x".repeat(100)))
            .collect();
        let output = lines.join("\n");
        let result = truncate_output(&output, Some(0), 1000);
        assert!(
            result.len() <= 1100,
            "should respect budget with small overhead"
        );
    }

    #[test]
    fn important_lines_all_types() {
        let lines = vec![
            "error: failed to compile",
            "warning: deprecated function",
            "fatal: not a git repository",
            "panic: runtime error",
            "Traceback (most recent call last):",
            "exception: division by zero",
            "compiled successfully",
            "installed 5 packages",
            "created new file",
            "built target release",
        ];
        let important = extract_important_lines(&lines);
        assert_eq!(
            important.len(),
            10,
            "all lines should be considered important"
        );
    }
}
