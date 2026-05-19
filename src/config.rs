use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct VpnProfile {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub save_password: bool,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub trusted_cert: Option<String>,
    #[serde(default)]
    pub use_sudo_password: bool,
    #[serde(default)]
    pub sudo_password: String,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Config {
    pub profiles: Vec<VpnProfile>,
    pub selected_profile: Option<String>,
}

impl Config {
    fn config_path() -> Option<PathBuf> {
        ProjectDirs::from("id", "fortivpn", "fortivpn-tui")
            .map(|d| d.config_dir().join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = match Self::config_path() {
            Some(p) => p,
            None => return Ok(Self::default()),
        };
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Gagal membaca file konfigurasi {}", path.display()))?;
        toml::from_str(&content)
            .with_context(|| format!("Format konfigurasi tidak valid di {}", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        let path = match Self::config_path() {
            Some(p) => p,
            None => anyhow::bail!("Tidak dapat menemukan direktori konfigurasi"),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let to_save = Config {
            profiles: self
                .profiles
                .iter()
                .map(|p| {
                    if p.save_password {
                        p.clone()
                    } else {
                        VpnProfile {
                            password: String::new(),
                            sudo_password: String::new(),
                            ..p.clone()
                        }
                    }
                })
                .collect(),
            selected_profile: self.selected_profile.clone(),
        };

        std::fs::write(&path, toml::to_string_pretty(&to_save)?)?;
        Ok(())
    }

    pub fn add_profile(&mut self, profile: VpnProfile) {
        self.profiles.push(profile);
    }

    pub fn delete_profile(&mut self, name: &str) {
        self.profiles.retain(|p| p.name != name);
        if self.selected_profile.as_deref() == Some(name) {
            self.selected_profile = None;
        }
    }
}
