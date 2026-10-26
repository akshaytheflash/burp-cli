//! External plugin support.
//!
//! Plugins are ordinary programs that speak a line-delimited JSON protocol on
//! stdin/stdout. For every hook the plugin process is started, receives one
//! JSON object, and must print one JSON object. This keeps plugins
//! language-agnostic (Python, Node, Go, shell wrappers, ...) and isolates
//! crashes from the proxy.
//!
//! Request message:
//! ```json
//! {"hook":"request","request":{"method":"GET","target":"/","version":"HTTP/1.1",
//!  "headers":[{"name":"Host","value":"example.com"}],"body_b64":"","scheme":"https"}}
//! ```
//! Response message adds `"response"`. The plugin returns an object with any of
//! `action` (`continue`/`drop`), `request`, `response` and an `issues` array.
//!
//! See `docs/plugins.md` for a complete reference and examples.

use crate::http::message::Header;
use crate::http::{Request, Response};
use crate::scanner::issue::{Confidence, Issue, Severity};
use crate::storage::Project;
use crate::util::{b64_decode, b64_encode, split_command};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Command line used to start the plugin, e.g. `python3 plugin.py`.
    pub command: String,
    #[serde(default = "default_hooks")]
    pub hooks: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn default_hooks() -> Vec<String> {
    vec!["request".into(), "response".into(), "passive".into()]
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug)]
pub struct Plugin {
    pub manifest: PluginManifest,
    pub dir: PathBuf,
    pub timeout: Duration,
}

impl Plugin {
    pub fn accepts(&self, hook: &str) -> bool {
        self.manifest.enabled
            && self
                .manifest
                .hooks
                .iter()
                .any(|h| h.eq_ignore_ascii_case(hook))
    }

    /// Path of the manifest that describes this plugin.
    pub fn manifest_path(&self) -> PathBuf {
        self.dir.join("plugin.toml")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireRequest {
    pub method: String,
    pub target: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body_b64: String,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

fn default_version() -> String {
    "HTTP/1.1".into()
}

impl WireRequest {
    pub fn from_request(request: &Request) -> Self {
        Self {
            method: request.method.clone(),
            target: request.target.clone(),
            version: request.version.clone(),
            headers: request.headers.clone(),
            body_b64: b64_encode(&request.body),
            scheme: request.scheme.clone(),
            url: request.url().ok().map(|u| u.to_string()),
        }
    }

    pub fn to_request(&self) -> Result<Request> {
        let body = if self.body_b64.is_empty() {
            Vec::new()
        } else {
            b64_decode(&self.body_b64).context("plugin returned invalid body_b64")?
        };
        Ok(Request {
            method: self.method.clone(),
            target: self.target.clone(),
            version: self.version.clone(),
            headers: self.headers.clone(),
            body,
            scheme: self.scheme.clone(),
            connect_to: None,
            tls_server_name: None,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireResponse {
    #[serde(default = "default_version")]
    pub version: String,
    pub status: u16,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body_b64: String,
}

impl WireResponse {
    pub fn from_response(response: &Response) -> Self {
        Self {
            version: response.version.clone(),
            status: response.status,
            reason: response.reason.clone(),
            headers: response.headers.clone(),
            body_b64: b64_encode(&response.body),
        }
    }

    pub fn to_response(&self) -> Result<Response> {
        let body = if self.body_b64.is_empty() {
            Vec::new()
        } else {
            b64_decode(&self.body_b64).context("plugin returned invalid body_b64")?
        };
        Ok(Response {
            version: self.version.clone(),
            status: self.status,
            reason: self.reason.clone(),
            headers: self.headers.clone(),
            body,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PluginInput {
    pub hook: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<WireRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<WireResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PluginIssue {
    #[serde(default)]
    pub check: Option<String>,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub parameter: Option<String>,
    #[serde(default)]
    pub cwe: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PluginOutput {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub request: Option<WireRequest>,
    #[serde(default)]
    pub response: Option<WireResponse>,
    #[serde(default)]
    pub issues: Vec<PluginIssue>,
}

impl PluginIssue {
    pub fn severity(&self) -> Severity {
        match self
            .severity
            .as_deref()
            .unwrap_or("info")
            .to_ascii_lowercase()
            .as_str()
        {
            "high" | "critical" => Severity::High,
            "medium" | "med" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn confidence(&self) -> Confidence {
        match self
            .confidence
            .as_deref()
            .unwrap_or("firm")
            .to_ascii_lowercase()
            .as_str()
        {
            "certain" => Confidence::Certain,
            "tentative" => Confidence::Tentative,
            _ => Confidence::Firm,
        }
    }

    pub fn to_issue(&self, plugin: &str, request: &Request) -> Issue {
        let title = if self.title.trim().is_empty() {
            "Plugin finding"
        } else {
            self.title.trim()
        };
        let mut builder = Issue::builder(
            self.check.as_deref().unwrap_or(plugin),
            title,
            self.severity(),
        )
        .request(request, true)
        .confidence(self.confidence());
        if let Some(detail) = &self.detail {
            builder = builder.detail(detail.clone());
        }
        if let Some(evidence) = &self.evidence {
            builder = builder.evidence(evidence.clone());
        }
        if let Some(remediation) = &self.remediation {
            builder = builder.remediation(remediation.clone());
        }
        if let Some(parameter) = &self.parameter {
            builder = builder.parameter(parameter.clone());
        }
        if let Some(cwe) = self.cwe {
            builder = builder.cwe(cwe);
        }
        builder.build()
    }
}

pub struct PluginManager {
    plugins: Vec<Plugin>,
    project_name: Option<String>,
}

#[derive(Default)]
pub struct PluginEffects {
    pub dropped: bool,
    pub issues: Vec<Issue>,
    pub errors: Vec<String>,
}

impl PluginManager {
    pub fn new(plugins: Vec<Plugin>, project_name: Option<String>) -> Self {
        Self {
            plugins,
            project_name,
        }
    }

    pub fn empty() -> Self {
        Self::new(Vec::new(), None)
    }

    /// Load every `plugin.toml` below `dir` (non-recursive).
    pub fn load(dir: &Path, default_timeout: Duration) -> Result<Self> {
        let mut plugins = Vec::new();
        if !dir.exists() {
            return Ok(Self::empty());
        }
        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("cannot read plugin directory '{}'", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let manifest_path = if path.is_dir() {
                path.join("plugin.toml")
            } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                path.clone()
            } else {
                continue;
            };
            if !manifest_path.exists() {
                continue;
            }
            let text = std::fs::read_to_string(&manifest_path)
                .with_context(|| format!("cannot read '{}'", manifest_path.display()))?;
            let manifest: PluginManifest = toml::from_str(&text).with_context(|| {
                format!("invalid plugin manifest '{}'", manifest_path.display())
            })?;
            if manifest.name.trim().is_empty() || manifest.command.trim().is_empty() {
                bail!(
                    "plugin manifest '{}' needs a name and command",
                    manifest_path.display()
                );
            }
            let plugin_dir = manifest_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| dir.to_path_buf());
            plugins.push(Plugin {
                timeout: Duration::from_millis(
                    manifest
                        .timeout_ms
                        .unwrap_or(default_timeout.as_millis() as u64),
                ),
                manifest,
                dir: plugin_dir,
            });
        }
        plugins.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
        Ok(Self::new(plugins, None))
    }

    pub fn from_project(project: &Project) -> Result<Self> {
        let default_timeout = Duration::from_millis(project.config.plugins.timeout_ms);
        let mut manager = Self::load(&project.plugins_dir(), default_timeout)?;
        manager.project_name = Some(project.config.name.clone());
        Ok(manager)
    }

    pub fn plugins(&self) -> &[Plugin] {
        &self.plugins
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    fn input(
        &self,
        hook: &str,
        request: Option<&Request>,
        response: Option<&Response>,
    ) -> PluginInput {
        PluginInput {
            hook: hook.to_string(),
            request: request.map(WireRequest::from_request),
            response: response.map(WireResponse::from_response),
            project: self.project_name.clone(),
        }
    }

    fn invoke(&self, plugin: &Plugin, input: &PluginInput) -> Result<PluginOutput> {
        let argv = split_command(&plugin.manifest.command);
        if argv.is_empty() {
            bail!("plugin '{}' has an empty command", plugin.manifest.name);
        }
        let mut command = std::process::Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir(&plugin.dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let mut child = command.spawn().with_context(|| {
            format!(
                "cannot start plugin '{}' ({})",
                plugin.manifest.name, plugin.manifest.command
            )
        })?;
        let payload = serde_json::to_vec(input)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("plugin stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("plugin stdout unavailable"))?;
        let mut stderr = child.stderr.take();

        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&payload);
            let _ = stdin.write_all(b"\n");
            stdin.flush().ok();
            drop(stdin);
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let result = reader.read_line(&mut line);
            let _ = sender.send((line, result.is_ok()));
        });

        let received = receiver.recv_timeout(plugin.timeout);
        let output = match received {
            Ok((line, _)) => {
                let _ = child.kill();
                let _ = child.wait();
                if line.trim().is_empty() {
                    let mut error_text = String::new();
                    if let Some(mut err) = stderr.take() {
                        err.read_to_string(&mut error_text).ok();
                    }
                    bail!(
                        "plugin '{}' returned no output{}",
                        plugin.manifest.name,
                        if error_text.trim().is_empty() {
                            String::new()
                        } else {
                            format!(": {}", error_text.trim())
                        }
                    );
                }
                serde_json::from_str::<PluginOutput>(line.trim()).with_context(|| {
                    format!(
                        "plugin '{}' returned invalid JSON: {}",
                        plugin.manifest.name,
                        crate::util::truncate(line.trim(), 300)
                    )
                })?
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "plugin '{}' timed out after {}",
                    plugin.manifest.name,
                    crate::util::format_duration(plugin.timeout)
                );
            }
        };
        Ok(output)
    }

    /// Run request hooks. Returns whether the request was dropped and any issues.
    pub fn apply_request(&self, request: &mut Request) -> PluginEffects {
        let mut effects = PluginEffects::default();
        for plugin in self.plugins.iter().filter(|p| p.accepts("request")) {
            let input = self.input("request", Some(request), None);
            match self.invoke(plugin, &input) {
                Ok(output) => {
                    if output.action.as_deref() == Some("drop") {
                        effects.dropped = true;
                    }
                    if let Some(wire) = output.request {
                        match wire.to_request() {
                            Ok(replacement) => *request = replacement,
                            Err(error) => effects.errors.push(format!(
                                "plugin '{}' returned an invalid request: {error}",
                                plugin.manifest.name
                            )),
                        }
                    }
                    for issue in output.issues {
                        effects
                            .issues
                            .push(issue.to_issue(&plugin.manifest.name, request));
                    }
                }
                Err(error) => effects.errors.push(format!("{error:#}")),
            }
            if effects.dropped {
                break;
            }
        }
        effects
    }

    /// Run response hooks (passive checks usually live here as well).
    pub fn apply_response(&self, request: &Request, response: &mut Response) -> PluginEffects {
        let mut effects = PluginEffects::default();
        for plugin in self.plugins.iter().filter(|p| p.accepts("response")) {
            let input = self.input("response", Some(request), Some(response));
            match self.invoke(plugin, &input) {
                Ok(output) => {
                    if output.action.as_deref() == Some("drop") {
                        effects.dropped = true;
                    }
                    if let Some(wire) = output.response {
                        match wire.to_response() {
                            Ok(replacement) => *response = replacement,
                            Err(error) => effects.errors.push(format!(
                                "plugin '{}' returned an invalid response: {error}",
                                plugin.manifest.name
                            )),
                        }
                    }
                    for issue in output.issues {
                        effects
                            .issues
                            .push(issue.to_issue(&plugin.manifest.name, request));
                    }
                }
                Err(error) => effects.errors.push(format!("{error:#}")),
            }
            if effects.dropped {
                break;
            }
        }
        effects
    }

    /// Run passive hooks that need both sides of an exchange.
    pub fn passive(&self, request: &Request, response: &Response) -> PluginEffects {
        let mut effects = PluginEffects::default();
        for plugin in self.plugins.iter().filter(|p| p.accepts("passive")) {
            let input = self.input("passive", Some(request), Some(response));
            match self.invoke(plugin, &input) {
                Ok(output) => {
                    for issue in output.issues {
                        effects
                            .issues
                            .push(issue.to_issue(&plugin.manifest.name, request));
                    }
                }
                Err(error) => effects.errors.push(format!("{error:#}")),
            }
        }
        effects
    }

    /// Merge plugin issues into a scan (deduplicating on the issue key).
    pub fn scan_pages<'a>(
        &self,
        pages: impl IntoIterator<Item = (&'a Request, &'a Response)>,
    ) -> PluginEffects {
        let mut combined = PluginEffects::default();
        let mut seen = std::collections::HashSet::new();
        for (request, response) in pages {
            let effects = self.passive(request, response);
            combined.errors.extend(effects.errors);
            for issue in effects.issues {
                if seen.insert(issue.dedupe_key()) {
                    combined.issues.push(issue);
                }
            }
        }
        combined
    }
}

/// Write a manifest for the built-in demo plugin.
pub fn install_demo(project: &Project) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot locate burpcli executable")?;
    let dir = project.plugins_dir().join("demo");
    std::fs::create_dir_all(&dir)?;
    // Windows paths contain backslashes, which a TOML basic string would read
    // as escapes, and they may contain spaces. A TOML literal string keeps the
    // path verbatim and the quotes keep `split_command` from breaking it up.
    let exe = exe.display();
    let manifest = format!(
        "# burpcli demo plugin\nname = \"demo\"\ndescription = \"Adds a response header and a sample finding\"\ncommand = '\"{exe}\" __plugin-demo'\nhooks = [\"response\", \"passive\"]\nenabled = true\ntimeout_ms = 3000\n"
    );
    let path = dir.join("plugin.toml");
    std::fs::write(&path, manifest)?;
    Ok(path)
}

pub fn remove_plugin(dir: &Path, name: &str) -> Result<bool> {
    let mut removed = false;
    if !dir.exists() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        let manifest_path = if path.is_dir() {
            path.join("plugin.toml")
        } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            path.clone()
        } else {
            continue;
        };
        if !manifest_path.exists() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        let Ok(manifest) = toml::from_str::<PluginManifest>(&text) else {
            continue;
        };
        if manifest.name == name {
            if path.is_dir() {
                std::fs::remove_dir_all(&path)?;
            } else {
                std::fs::remove_file(&path)?;
            }
            removed = true;
        }
    }
    Ok(removed)
}

/// The hidden `__plugin-demo` command. Reads JSON lines from stdin and replies
/// with a response header plus a low-severity finding. It is intentionally
/// tiny; it doubles as executable protocol documentation.
pub fn demo_plugin() -> Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let input: serde_json::Value = serde_json::from_str(&line)?;
        let hook = input.get("hook").and_then(|h| h.as_str()).unwrap_or("");
        let mut output = serde_json::Map::new();
        output.insert(
            "action".into(),
            serde_json::Value::String("continue".into()),
        );
        if let Some(response) = input.get("response").and_then(|r| r.as_object()) {
            let mut response = response.clone();
            let headers = response
                .entry("headers")
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(array) = headers.as_array_mut() {
                array.push(serde_json::json!({"name":"X-Burpcli-Plugin","value":"demo"}));
            }
            output.insert("response".into(), serde_json::Value::Object(response));
        }
        let body_hint = input
            .get("response")
            .and_then(|r| r.get("body_b64"))
            .and_then(|b| b.as_str())
            .and_then(|b| b64_decode(b).ok())
            .map(|b| String::from_utf8_lossy(&b).to_string())
            .unwrap_or_default();
        if body_hint.to_ascii_lowercase().contains("plugin-demo") {
            output.insert(
                "issues".into(),
                serde_json::json!([{
                    "check": "plugin-demo",
                    "title": "Demo plugin finding",
                    "severity": "low",
                    "confidence": "certain",
                    "detail": "The demo plugin saw the marker `plugin-demo` in the response body.",
                    "evidence": "plugin-demo",
                    "remediation": "This is only a demonstration; disable the demo plugin."
                }]),
            );
        }
        output.insert(
            "hook_seen".into(),
            serde_json::Value::String(hook.to_string()),
        );
        writeln!(stdout, "{}", serde_json::Value::Object(output))?;
        stdout.flush()?;
    }
    Ok(())
}

/// Validate that all enabled plugins can be started and answer a ping. Used by
/// `burpcli plugin test`.
pub fn test_plugin(plugin: &Plugin) -> Result<PluginOutput> {
    let manager = PluginManager::new(vec![plugin.clone()], None);
    let request = Request::parse(b"GET /plugin-test HTTP/1.1\r\nHost: burpcli.invalid\r\n\r\n")
        .context("cannot build plugin test request")?;
    let input = manager.input("request", Some(&request), None);
    manager.invoke(plugin, &input)
}

pub fn plugin_dirs(project: &Project) -> Vec<PathBuf> {
    vec![project.plugins_dir()]
}

impl PluginManager {
    /// Convenience for the CLI: an `Arc` only when plugins are enabled for the
    /// project and at least one plugin is installed.
    pub fn optional_from_project(project: &Project) -> Result<Option<Arc<Self>>> {
        if !project.config.plugins.enabled {
            return Ok(None);
        }
        let manager = Self::from_project(project)?;
        if manager.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Arc::new(manager)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let plugin_dir = dir.path().join("hello");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("plugin.toml"),
            "name = \"hello\"\ncommand = \"echo {}\"\nhooks = [\"response\"]\n",
        )
        .unwrap();
        let manager = PluginManager::load(dir.path(), Duration::from_secs(2)).unwrap();
        assert_eq!(manager.plugins().len(), 1);
        assert!(manager.plugins()[0].accepts("response"));
        assert!(!manager.plugins()[0].accepts("request"));
    }

    #[test]
    fn wire_request_roundtrip() {
        let mut request =
            Request::parse(b"POST /x HTTP/1.1\r\nHost: example.com\r\n\r\nbody").unwrap();
        request.scheme = Some("http".into());
        let wire = WireRequest::from_request(&request);
        let back = wire.to_request().unwrap();
        assert_eq!(back.method, request.method);
        assert_eq!(back.body, request.body);
        assert_eq!(back.header("Host"), Some("example.com"));
    }

    #[test]
    fn plugin_issue_conversion() {
        let request = Request::parse(b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        let issue = PluginIssue {
            check: Some("custom".into()),
            title: "Custom finding".into(),
            severity: Some("high".into()),
            confidence: Some("certain".into()),
            detail: Some("detail".into()),
            evidence: None,
            remediation: None,
            parameter: Some("q".into()),
            cwe: Some(79),
        }
        .to_issue("demo", &request);
        assert_eq!(issue.severity, Severity::High);
        assert_eq!(issue.confidence, Confidence::Certain);
        assert_eq!(issue.check, "custom");
        assert_eq!(issue.cwe, Some(79));
        assert_eq!(issue.url, "http://example.com/x");
    }
}
