//! Global configuration and per-project configuration.

use crate::util::now_rfc3339;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub current_project: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub editor: Option<String>,
    #[serde(default)]
    pub default_timeout_ms: Option<u64>,
    #[serde(default)]
    pub default_concurrency: Option<usize>,
    #[serde(default)]
    pub projects: Vec<ProjectRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectRef {
    pub name: String,
    pub path: String,
}

pub fn home_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("BURPCLI_HOME") {
        return PathBuf::from(dir);
    }
    let base = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(".burpcli")
}

pub fn config_path() -> PathBuf {
    home_dir().join("config.toml")
}

pub fn load_global() -> Result<GlobalConfig> {
    let path = config_path();
    if !path.exists() {
        return Ok(GlobalConfig::default());
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read config '{}'", path.display()))?;
    if text.trim().is_empty() {
        return Ok(GlobalConfig::default());
    }
    toml::from_str(&text).with_context(|| format!("cannot parse config '{}'", path.display()))
}

pub fn save_global(config: &GlobalConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create config directory '{}'", parent.display()))?;
    }
    let text = toml::to_string_pretty(config)?;
    atomic_write(&path, text.as_bytes())
}

pub fn editor() -> String {
    std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".to_string()
            } else {
                "vi".to_string()
            }
        })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectConfig {
    pub name: String,
    #[serde(default = "now_rfc3339")]
    pub created: String,
    #[serde(default)]
    pub scope: ScopeSettings,
    #[serde(default)]
    pub scan: ScanSettings,
    #[serde(default)]
    pub proxy: ProxySettings,
    #[serde(default)]
    pub session: SessionSettings,
    #[serde(default)]
    pub plugins: PluginSettings,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: "default".into(),
            created: now_rfc3339(),
            scope: ScopeSettings::default(),
            scan: ScanSettings::default(),
            proxy: ProxySettings::default(),
            session: SessionSettings::default(),
            plugins: PluginSettings::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ScopeSettings {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanSettings {
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default = "default_max_body")]
    pub max_body: usize,
    #[serde(default)]
    pub follow_redirects: usize,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub timing_checks: bool,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub skip_checks: Vec<String>,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            concurrency: default_concurrency(),
            timeout_ms: default_timeout_ms(),
            delay_ms: 0,
            max_body: default_max_body(),
            follow_redirects: 0,
            insecure: false,
            user_agent: None,
            timing_checks: false,
            checks: Vec::new(),
            skip_checks: Vec::new(),
        }
    }
}

fn default_concurrency() -> usize {
    10
}
fn default_timeout_ms() -> u64 {
    15_000
}
fn default_max_body() -> usize {
    10 * 1024 * 1024
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxySettings {
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default)]
    pub intercept_requests: bool,
    #[serde(default)]
    pub intercept_responses: bool,
    #[serde(default)]
    pub only_in_scope: bool,
    #[serde(default = "default_proxy_entries")]
    pub max_entries: usize,
    #[serde(default)]
    pub mitm: bool,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_proxy_port(),
            intercept_requests: false,
            intercept_responses: false,
            only_in_scope: false,
            max_entries: default_proxy_entries(),
            mitm: false,
        }
    }
}

fn default_bind() -> String {
    "127.0.0.1".into()
}
fn default_proxy_port() -> u16 {
    8080
}
fn default_proxy_entries() -> usize {
    10_000
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionSettings {
    /// Extra headers applied to every request unless already present.
    #[serde(default)]
    pub headers: Vec<String>,
    /// Match/replace rules applied to outgoing requests.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Request files executed by `burpcli session login`.
    #[serde(default)]
    pub macros: Vec<String>,
    #[serde(default = "default_true")]
    pub auto_apply: bool,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            headers: Vec::new(),
            rules: Vec::new(),
            macros: Vec::new(),
            auto_apply: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    /// TOML key is `match`.
    #[serde(rename = "match")]
    pub pattern: String,
    pub replace: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub enabled: bool,
    /// `request`, `response` or `both`.
    #[serde(default = "default_direction")]
    pub direction: String,
}

fn default_direction() -> String {
    "request".into()
}

impl Rule {
    pub fn applies_to(&self, direction: &str) -> bool {
        self.enabled
            && (self.direction.eq_ignore_ascii_case("both")
                || self.direction.eq_ignore_ascii_case(direction))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_plugin_dir")]
    pub dir: String,
    #[serde(default = "default_plugin_timeout")]
    pub timeout_ms: u64,
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_plugin_dir(),
            timeout_ms: default_plugin_timeout(),
        }
    }
}

fn default_plugin_dir() -> String {
    "plugins".into()
}
fn default_plugin_timeout() -> u64 {
    5_000
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("burpcli")
    ));
    std::fs::write(&tmp, bytes).with_context(|| format!("cannot write '{}'", tmp.display()))?;
    if path.exists() {
        std::fs::remove_file(path).ok();
    }
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace '{}'", path.display()))?;
    Ok(())
}
