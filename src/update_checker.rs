//! Generic GitHub release checker used for polling latest releases
//! for sidecar and future self-update checks.

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct GitHubReleaseChecker {
    pub repo: String,
    pub current_version: Option<String>,
    pub platform_asset_fragment: Option<String>,
    pub check_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub version: String,
    pub download_url: String,
    pub asset_name: String,
}

impl GitHubReleaseChecker {
    pub fn new(repo: &str) -> Self {
        Self {
            repo: repo.into(),
            current_version: None,
            platform_asset_fragment: None,
            check_interval: Duration::from_secs(3600),
        }
    }

    pub fn with_current_version(mut self, v: Option<String>) -> Self {
        self.current_version = v;
        self
    }

    pub fn with_platform(mut self, fragment: Option<String>) -> Self {
        self.platform_asset_fragment = fragment;
        self
    }

    pub async fn check_latest(&self) -> Result<Option<ReleaseInfo>> {
        let url = format!("https://api.github.com/repos/{}/releases/latest", self.repo);
        let client = reqwest::Client::builder()
            .user_agent("nsh-daemon")
            .timeout(Duration::from_secs(30))
            .build()?;
        let resp = client.get(&url).send().await?.json::<serde_json::Value>().await?;

        let tag = resp["tag_name"].as_str().unwrap_or("").to_string();
        if tag.is_empty() { return Ok(None); }
        if let Some(cur) = &self.current_version {
            if cur.trim() == tag.trim() { return Ok(None); }
        }
        let empty: Vec<serde_json::Value> = Vec::new();
        let assets = resp["assets"].as_array().unwrap_or(&empty);
        if let Some(fragment) = &self.platform_asset_fragment {
            if let Some(asset) = assets.iter().find(|a| a["name"].as_str().unwrap_or("").contains(fragment)) {
                return Ok(Some(ReleaseInfo {
                    version: tag,
                    download_url: asset["browser_download_url"].as_str().unwrap_or("").to_string(),
                    asset_name: asset["name"].as_str().unwrap_or("").to_string(),
                }));
            }
            return Ok(None);
        }
        Ok(Some(ReleaseInfo { version: tag, download_url: String::new(), asset_name: String::new() }))
    }

    pub async fn download_to(&self, release: &ReleaseInfo, dest: &Path) -> Result<PathBuf> {
        let client = reqwest::Client::builder()
            .user_agent("nsh-daemon")
            .timeout(Duration::from_secs(120))
            .build()?;
        let bytes = client.get(&release.download_url).send().await?.bytes().await?;
        let tmp = dest.with_extension("download-tmp");
        std::fs::write(&tmp, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        }
        std::fs::rename(&tmp, dest)?;
        Ok(dest.to_path_buf())
    }
}
