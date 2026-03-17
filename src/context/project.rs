use std::time::{Duration, Instant};

use crate::config::Config;
use super::{CwdListingEntry, FileEntry, GitCommit, ProjectInfo};
use super::system_info::format_size;

pub(crate) fn detect_project_info(cwd: &str, config: &Config) -> ProjectInfo {
    let project_type = detect_project_type(cwd);

    let project_root = if project_type != "unknown" {
        find_project_root(cwd)
    } else {
        None
    };

    let root = project_root
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());

    let (git_branch, git_status, git_commits) = detect_git_info(cwd, config.context.git_commits);

    let files = if let Some(ref root_path) = project_root {
        let root_str = root_path.to_string_lossy();
        list_project_files(&root_str, config.context.project_files_limit)
    } else {
        Vec::new()
    };

    ProjectInfo {
        root,
        project_type,
        git_branch,
        git_status,
        git_commits,
        files,
    }
}

pub(crate) fn find_project_root(cwd: &str) -> Option<std::path::PathBuf> {
    let git_root = run_git_with_timeout(&["rev-parse", "--show-toplevel"], cwd);
    if let Some(root) = git_root {
        return Some(std::path::PathBuf::from(root));
    }
    Some(std::path::PathBuf::from(cwd))
}

pub(crate) fn detect_project_type(cwd: &str) -> String {
    let mut types = Vec::new();
    let mut dir = std::path::PathBuf::from(cwd);

    loop {
        check_project_markers(&dir, &mut types);
        if dir.join(".git").exists() {
            break;
        }
        if !dir.pop() {
            break;
        }
    }

    types.dedup();
    if types.is_empty() {
        "unknown".into()
    } else {
        types.join(", ")
    }
}

pub(crate) fn check_project_markers(dir: &std::path::Path, types: &mut Vec<&'static str>) {
    if dir.join("Cargo.toml").exists() {
        types.push("Rust/Cargo");
    }
    if dir.join("package.json").exists() {
        types.push("Node.js");
    }
    if dir.join("pyproject.toml").exists() || dir.join("setup.py").exists() {
        types.push("Python");
    }
    if dir.join("go.mod").exists() {
        types.push("Go");
    }
    if dir.join("Makefile").exists() {
        types.push("Make");
    }
    if dir.join("Dockerfile").exists()
        || dir.join("docker-compose.yml").exists()
        || dir.join("compose.yml").exists()
    {
        types.push("Docker");
    }
    if dir.join("Gemfile").exists() {
        types.push("Ruby");
    }
    if dir.join("pom.xml").exists()
        || dir.join("build.gradle").exists()
        || dir.join("build.gradle.kts").exists()
    {
        types.push("Java");
    }
    if dir.join("CMakeLists.txt").exists() {
        types.push("C/C++ (CMake)");
    }
    if dir.join("flake.nix").exists() || dir.join("shell.nix").exists() {
        types.push("Nix");
    }
}

pub(crate) fn run_git_with_timeout(args: &[&str], cwd: &str) -> Option<String> {
    let mut child = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let timeout = Duration::from_secs(2);
    let args_display = args.join(" ");
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                let output = child.wait_with_output().ok()?;
                if !output.status.success() {
                    return None;
                }
                return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    tracing::warn!("git command timed out: git {args_display}");
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

pub(crate) fn detect_git_info(
    cwd: &str,
    max_commits: usize,
) -> (Option<String>, Option<String>, Vec<GitCommit>) {
    // Check if we're inside a git work tree
    let check = run_git_with_timeout(&["rev-parse", "--is-inside-work-tree"], cwd);
    if check.as_deref() != Some("true") {
        return (None, None, Vec::new());
    }

    let branch = run_git_with_timeout(&["rev-parse", "--abbrev-ref", "HEAD"], cwd);
    if branch.is_none() {
        return (None, None, Vec::new());
    }

    let status = run_git_with_timeout(&["status", "--porcelain"], cwd).map(|output| {
        let count = output.lines().count();
        if count == 0 {
            "clean".to_string()
        } else {
            format!("{count} changed files")
        }
    });

    let limit_arg = format!("-{max_commits}");
    let commits = run_git_with_timeout(
        &[
            "log",
            "--oneline",
            "--no-decorate",
            &limit_arg,
            "--format=%h|%s|%cr",
        ],
        cwd,
    )
    .map(|output| {
        output
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.splitn(3, '|').collect();
                if parts.len() == 3 {
                    Some(GitCommit {
                        hash: parts[0].to_string(),
                        message: parts[1].to_string(),
                        relative_time: parts[2].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect()
    })
    .unwrap_or_default();

    (branch, status, commits)
}

pub(crate) fn list_project_files(cwd: &str, limit: usize) -> Vec<FileEntry> {
    let path = std::path::Path::new(cwd);

    // Try using ignore crate for .gitignore-aware walking
    if let Some(entries) = list_project_files_with_ignore(path, limit) {
        return entries;
    }

    // Fallback: manual BFS with hardcoded skip list
    list_project_files_fallback(path, limit)
}

pub(crate) fn list_project_files_with_ignore(
    cwd: &std::path::Path,
    max_files: usize,
) -> Option<Vec<FileEntry>> {
    use ignore::WalkBuilder;

    let walker = WalkBuilder::new(cwd)
        .max_depth(Some(5))
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .sort_by_file_name(|a, b| a.cmp(b))
        .build();

    let mut entries = Vec::new();
    let mut had_errors = false;
    for result in walker {
        if entries.len() >= max_files {
            break;
        }
        let entry = match result {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("file walk error: {e}");
                had_errors = true;
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let rel = entry.path().strip_prefix(cwd).unwrap_or(entry.path());
        let ft = entry.file_type();
        let is_dir = ft.as_ref().is_some_and(|ft| ft.is_dir());
        let is_symlink = ft.as_ref().is_some_and(|ft| ft.is_symlink());
        let kind = if is_symlink {
            "symlink"
        } else if is_dir {
            "dir"
        } else {
            "file"
        };
        let size = if is_dir || is_symlink {
            String::new()
        } else {
            entry
                .metadata()
                .map(|m| format_size(m.len()))
                .unwrap_or_default()
        };
        entries.push(FileEntry {
            path: rel.to_string_lossy().to_string(),
            kind: kind.into(),
            size,
        });
    }

    if entries.is_empty() && had_errors {
        return None;
    }

    Some(entries)
}

pub(crate) fn list_project_files_fallback(cwd: &std::path::Path, max_files: usize) -> Vec<FileEntry> {
    const SKIP_DIRS: &[&str] = &[
        ".git",
        "target",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".next",
        ".cache",
        "vendor",
    ];

    let mut entries = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((cwd.to_path_buf(), 0_usize));

    while let Some((dir, depth)) = queue.pop_front() {
        if depth > 5 || entries.len() >= max_files {
            break;
        }
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut children: Vec<_> = read_dir.flatten().collect();
        children.sort_by_key(|e| e.file_name());

        for entry in children {
            if entries.len() >= max_files {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let meta = match entry.path().symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let is_symlink = meta.file_type().is_symlink();
            let is_dir = meta.file_type().is_dir();

            if is_dir && SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }

            let rel = entry
                .path()
                .strip_prefix(cwd)
                .unwrap_or(&entry.path())
                .to_path_buf();
            let kind = if is_symlink {
                "symlink"
            } else if is_dir {
                "dir"
            } else {
                "file"
            };
            let size = if is_dir || is_symlink {
                String::new()
            } else {
                format_size(meta.len())
            };
            entries.push(FileEntry {
                path: rel.to_string_lossy().to_string(),
                kind: kind.into(),
                size,
            });

            if is_dir && !is_symlink {
                queue.push_back((entry.path(), depth + 1));
            }
        }
    }

    entries
}

pub(crate) fn collect_cwd_listing(cwd: &str, max_entries: usize) -> Vec<CwdListingEntry> {
    let root = std::path::Path::new(cwd);
    let mut out = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root.to_path_buf());

    while let Some(dir) = queue.pop_front() {
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };

        let mut batch = Vec::new();
        for entry in read_dir.flatten() {
            batch.push(entry);
        }
        batch.sort_by_key(|entry| entry.file_name());

        for entry in batch {
            if out.len() >= max_entries {
                return out;
            }

            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| path.to_string_lossy().to_string());
            if rel.is_empty() {
                continue;
            }

            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let (kind, recurse) = if meta.is_dir() {
                ("dir", true)
            } else if meta.is_symlink() {
                ("link", false)
            } else {
                ("file", false)
            };

            out.push(CwdListingEntry {
                path: rel,
                kind: kind.to_string(),
            });

            if recurse {
                queue.push_back(path);
            }
        }
    }

    out
}

