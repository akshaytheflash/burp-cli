//! Target scope: include/exclude patterns with Burp-style wildcard matching.

use crate::util::{glob_match, glob_to_regex};
use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scope {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(skip)]
    include_regex: Vec<Regex>,
    #[serde(skip)]
    exclude_regex: Vec<Regex>,
}

impl Scope {
    pub fn new(include: &[String], exclude: &[String]) -> Result<Self> {
        let mut scope = Self {
            include: include.to_vec(),
            exclude: exclude.to_vec(),
            ..Default::default()
        };
        scope.compile()?;
        Ok(scope)
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn compile(&mut self) -> Result<()> {
        self.include_regex.clear();
        self.exclude_regex.clear();
        for pattern in &self.include {
            self.include_regex.push(compile_pattern(pattern)?);
        }
        for pattern in &self.exclude {
            self.exclude_regex.push(compile_pattern(pattern)?);
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    /// An empty include list means "everything"; excludes always win.
    pub fn allows(&self, url: &Url) -> bool {
        let text = url.as_str().to_ascii_lowercase();
        let host = url.host_str().unwrap_or("").to_ascii_lowercase();
        let host_port = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let included = self.include.is_empty()
            || self
                .include
                .iter()
                .zip(&self.include_regex)
                .any(|(pattern, regex)| pattern_matches(pattern, regex, &text, &host, &host_port));
        if !included {
            return false;
        }
        !self
            .exclude
            .iter()
            .zip(&self.exclude_regex)
            .any(|(pattern, regex)| pattern_matches(pattern, regex, &text, &host, &host_port))
    }

    pub fn allows_str(&self, url: &str) -> bool {
        match Url::parse(url) {
            Ok(url) => self.allows(&url),
            Err(_) => false,
        }
    }

    pub fn add_include(&mut self, pattern: &str) -> Result<()> {
        if !self.include.iter().any(|p| p == pattern) {
            self.include.push(pattern.to_string());
            self.compile()?;
        }
        Ok(())
    }

    pub fn add_exclude(&mut self, pattern: &str) -> Result<()> {
        if !self.exclude.iter().any(|p| p == pattern) {
            self.exclude.push(pattern.to_string());
            self.compile()?;
        }
        Ok(())
    }

    pub fn remove(&mut self, pattern: &str) -> Result<bool> {
        let before = self.include.len() + self.exclude.len();
        self.include.retain(|p| p != pattern);
        self.exclude.retain(|p| p != pattern);
        self.compile()?;
        Ok(before != self.include.len() + self.exclude.len())
    }

    pub fn clear(&mut self) {
        self.include.clear();
        self.exclude.clear();
        self.include_regex.clear();
        self.exclude_regex.clear();
    }
}

/// Scope patterns can be:
///   * full URLs with wildcards: `https://example.com/api/*`
///   * URLs without wildcards (prefix match): `https://example.com`
///   * hosts / host wildcards: `example.com`, `*.example.com:8443`
fn compile_pattern(pattern: &str) -> Result<Regex> {
    if pattern.contains("://") {
        return glob_to_regex(&pattern.to_ascii_lowercase());
    }
    let host_pattern = pattern.to_ascii_lowercase();
    if host_pattern.contains('*') || host_pattern.contains('?') {
        glob_to_regex(&host_pattern)
    } else {
        // Exact host: match host and any path, or a URL prefix.
        Regex::new(&format!(
            "^(https?://)?{}($|[:/].*)?$",
            regex::escape(&host_pattern)
        ))
        .with_context(|| format!("invalid scope pattern '{pattern}'"))
    }
}

fn pattern_matches(raw: &str, regex: &Regex, url: &str, host: &str, host_port: &str) -> bool {
    if raw.contains("://") {
        if raw.contains('*') || raw.contains('?') {
            regex.is_match(url)
        } else {
            url.starts_with(&raw.to_ascii_lowercase())
        }
    } else if raw.contains('*') || raw.contains('?') {
        glob_match(&raw.to_ascii_lowercase(), host)
            || glob_match(&raw.to_ascii_lowercase(), host_port)
    } else {
        regex.is_match(host)
            || regex.is_match(host_port)
            || url.starts_with(&raw.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_url_patterns() {
        let scope = Scope::new(
            &["https://example.com/*".into(), "*.internal.test".into()],
            &["https://example.com/logout".into()],
        )
        .unwrap();
        assert!(scope.allows_str("https://example.com/app"));
        assert!(!scope.allows_str("https://example.com/logout"));
        assert!(scope.allows_str("http://api.internal.test/x"));
        assert!(!scope.allows_str("https://evil.test/"));
    }

    #[test]
    fn empty_scope_allows_all() {
        let scope = Scope::empty();
        assert!(scope.allows_str("https://anything.test/"));
    }

    #[test]
    fn exact_host_matches_subdomains_only_with_wildcard() {
        let scope = Scope::new(&["example.com".into()], &[]).unwrap();
        assert!(scope.allows_str("https://example.com/a"));
        assert!(scope.allows_str("https://example.com:8443/a"));
        assert!(!scope.allows_str("https://api.example.com/a"));
    }
}
