use std::process::Command;

pub fn execute(cmd: &str, section: Option<u8>) -> anyhow::Result<String> {
    let mut args = vec![];
    if let Some(s) = section {
        args.push(s.to_string());
    }
    args.push(cmd.to_string());

    let output = Command::new("man")
        .args(&args)
        .env("MANPAGER", "cat")
        .env("COLUMNS", "80")
        .output()?;

    if !output.status.success() {
        return Ok(format!("No man page found for '{cmd}'"));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let truncated = crate::util::truncate(&text, 4000);
    Ok(format!("[OS: {}] {}", std::env::consts::OS, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_man_page_ls() {
        let result = execute("ls", None).unwrap();
        assert!(result.contains("ls") || result.contains("No man page"));
    }

    #[test]
    fn test_man_page_nonexistent() {
        let result = execute("nonexistent_command_xyz_12345", None).unwrap();
        assert!(result.contains("No man page found"));
    }

    #[test]
    fn test_man_page_with_section() {
        let result = execute("ls", Some(1)).unwrap();
        assert!(!result.is_empty());
    }
}
