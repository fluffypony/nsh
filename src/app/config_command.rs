use crate::cli::ConfigAction;

pub(super) fn handle_config_command(action: Option<ConfigAction>) -> anyhow::Result<()> {
    match action {
        Some(ConfigAction::Path) | None => {
            println!("{}", crate::config::Config::path().display());
        }
        Some(ConfigAction::Show { raw }) => {
            let path = crate::config::Config::path();
            if path.exists() {
                let content = std::fs::read_to_string(&path)?;
                if raw {
                    print!("{content}");
                } else {
                    match content.parse::<toml::Value>() {
                        Ok(mut value) => {
                            redact_config_keys(&mut value);
                            print!("{}", toml::to_string_pretty(&value)?);
                        }
                        Err(_) => print!("{content}"),
                    }
                }
            } else {
                eprintln!("No config file found at {}", path.display());
                eprintln!("Run with defaults or create one.");
            }
        }
        Some(ConfigAction::Edit) => {
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
            let path = crate::config::Config::path();
            let dir = path.parent().unwrap();
            std::fs::create_dir_all(dir)?;
            std::process::Command::new(&editor).arg(&path).status()?;
        }
    }
    Ok(())
}

fn redact_config_keys(value: &mut toml::Value) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table.iter_mut() {
                if key == "api_key" {
                    if let toml::Value::String(string) = child {
                        if string.chars().count() > 8 {
                            let prefix: String = string.chars().take(4).collect();
                            let suffix: String = string
                                .chars()
                                .rev()
                                .take(4)
                                .collect::<String>()
                                .chars()
                                .rev()
                                .collect();
                            *string = format!("{prefix}...{suffix}");
                        } else {
                            *string = "****".into();
                        }
                    }
                } else {
                    redact_config_keys(child);
                }
            }
        }
        toml::Value::Array(array) => {
            for child in array {
                redact_config_keys(child);
            }
        }
        _ => {}
    }
}
