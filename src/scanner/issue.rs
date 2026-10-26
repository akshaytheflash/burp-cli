//! Issue model and persistent, de-duplicating issue store.

use crate::http::{Request, Response};
use crate::storage;
use crate::util::{now_rfc3339, truncate};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn rank(&self) -> u8 {
        match self {
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Severity::High => "31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl FromStr for Severity {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "high" => Ok(Self::High),
            "medium" | "med" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" | "information" => Ok(Self::Info),
            other => anyhow::bail!("unknown severity '{other}'"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Certain,
    Firm,
    Tentative,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Certain => "Certain",
            Confidence::Firm => "Firm",
            Confidence::Tentative => "Tentative",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Issue {
    pub id: String,
    pub check: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub url: String,
    pub method: String,
    #[serde(default)]
    pub parameter: Option<String>,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub cwe: Option<u32>,
    #[serde(default)]
    pub references: Vec<String>,
    pub ts: String,
    /// Base64 raw request evidence (optional).
    #[serde(default)]
    pub request: Option<String>,
    /// Base64 raw response evidence (optional).
    #[serde(default)]
    pub response: Option<String>,
}

impl Issue {
    pub fn builder(check: &str, title: &str, severity: Severity) -> IssueBuilder {
        IssueBuilder {
            issue: Issue {
                id: String::new(),
                check: check.to_string(),
                title: title.to_string(),
                severity,
                confidence: Confidence::Firm,
                url: String::new(),
                method: "GET".into(),
                parameter: None,
                payload: None,
                evidence: String::new(),
                detail: String::new(),
                remediation: String::new(),
                cwe: None,
                references: Vec::new(),
                ts: now_rfc3339(),
                request: None,
                response: None,
            },
        }
    }

    pub fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.check,
            self.method,
            self.url,
            self.parameter.clone().unwrap_or_default()
        )
    }

    pub fn compute_id(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.dedupe_key().as_bytes());
        self.id = hex::encode(&hasher.finalize()[..8]);
    }

    pub fn title_with_location(&self) -> String {
        match &self.parameter {
            Some(param) => format!("{} (parameter: {})", self.title, param),
            None => self.title.clone(),
        }
    }
}

pub struct IssueBuilder {
    issue: Issue,
}

impl IssueBuilder {
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.issue.confidence = confidence;
        self
    }

    pub fn request(mut self, request: &Request, save_evidence: bool) -> Self {
        self.issue.method = request.method.clone();
        self.issue.url = request
            .url()
            .map(|u| u.to_string())
            .unwrap_or_else(|_| request.target.clone());
        if save_evidence {
            self.issue.request = Some(request.to_b64());
        }
        self
    }

    pub fn response(mut self, response: &Response, save_evidence: bool) -> Self {
        if save_evidence {
            self.issue.response = Some(response.to_b64());
        }
        self
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.issue.url = url.into();
        self
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.issue.method = method.into();
        self
    }

    pub fn parameter(mut self, parameter: impl Into<String>) -> Self {
        self.issue.parameter = Some(parameter.into());
        self
    }

    pub fn payload(mut self, payload: impl Into<String>) -> Self {
        self.issue.payload = Some(payload.into());
        self
    }

    pub fn evidence(mut self, evidence: impl Into<String>) -> Self {
        self.issue.evidence = truncate(evidence.into().trim(), 500);
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.issue.detail = detail.into();
        self
    }

    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.issue.remediation = remediation.into();
        self
    }

    pub fn cwe(mut self, cwe: u32) -> Self {
        self.issue.cwe = Some(cwe);
        self
    }

    pub fn reference(mut self, reference: impl Into<String>) -> Self {
        self.issue.references.push(reference.into());
        self
    }

    pub fn build(mut self) -> Issue {
        if self.issue.url.is_empty() {
            self.issue.url = "unknown".into();
        }
        self.issue.compute_id();
        self.issue
    }
}

pub struct IssueStore {
    path: PathBuf,
    seen: Mutex<HashSet<String>>,
}

impl IssueStore {
    pub fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if !path.exists() {
            std::fs::File::create(&path)?;
        }
        let mut seen = HashSet::new();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for line in text.lines() {
            if let Ok(issue) = serde_json::from_str::<Issue>(line) {
                seen.insert(issue.dedupe_key());
            }
        }
        Ok(Self {
            path,
            seen: Mutex::new(seen),
        })
    }

    /// Returns true when the issue was new and written to disk.
    pub fn append(&self, issue: &Issue) -> Result<bool> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if !seen.insert(issue.dedupe_key()) {
            return Ok(false);
        }
        let _lock = storage::acquire_lock(&self.path)?;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .with_context(|| format!("cannot append issue to '{}'", self.path.display()))?;
        use std::io::Write;
        serde_json::to_writer(&mut file, issue)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(true)
    }

    pub fn list(&self) -> Result<Vec<Issue>> {
        let mut issues = Vec::new();
        if !self.path.exists() {
            return Ok(issues);
        }
        let text = std::fs::read_to_string(&self.path)?;
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Issue>(line) {
                Ok(issue) => issues.push(issue),
                Err(_) => continue,
            }
        }
        Ok(issues)
    }

    pub fn clear(&self) -> Result<()> {
        let _lock = storage::acquire_lock(&self.path)?;
        std::fs::File::create(&self.path)?;
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clear();
        Ok(())
    }

    pub fn count(&self) -> Result<usize> {
        Ok(self.list()?.len())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable_and_dedupe() {
        let request = Request::parse(b"GET /x?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        let issue = Issue::builder("xss", "Reflected XSS", Severity::High)
            .request(&request, false)
            .parameter("id")
            .build();
        assert_eq!(issue.id.len(), 16);
        let duplicate = Issue::builder("xss", "Other title", Severity::High)
            .request(&request, false)
            .parameter("id")
            .build();
        assert_eq!(issue.id, duplicate.id);
    }

    #[test]
    fn store_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        let store = IssueStore::open(dir.path().join("issues.jsonl")).unwrap();
        let issue = Issue::builder("test", "Test", Severity::Low)
            .url("http://x/")
            .build();
        assert!(store.append(&issue).unwrap());
        assert!(!store.append(&issue).unwrap());
        assert_eq!(store.count().unwrap(), 1);
    }
}
