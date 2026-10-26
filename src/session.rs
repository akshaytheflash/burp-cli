//! Session handling: cookie jar, static headers and match/replace rules.

use crate::config::{ProjectConfig, Rule};
use crate::http::message::Header;
use crate::http::{CookieJar, Request, Response};
use crate::storage::Project;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SessionState {
    #[serde(default)]
    pub cookies: CookieJar,
    #[serde(default)]
    pub updated: String,
}

impl SessionState {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read session '{}'", path.display()))?;
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(&text)
            .with_context(|| format!("cannot parse session '{}'", path.display()))
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.updated = crate::util::now_rfc3339();
        let text = serde_json::to_string_pretty(self)?;
        crate::config::atomic_write(path, text.as_bytes())
    }

    pub fn from_project(project: &Project) -> Result<Self> {
        Self::load(&project.session_path())
    }

    pub fn save_to_project(&mut self, project: &Project) -> Result<()> {
        self.save(&project.session_path())
    }
}

/// Expand `${ENV:NAME}` and `${FILE:path}` placeholders in a header value or
/// rule replacement. Unknown placeholders are left untouched.
pub fn expand_placeholders(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}') {
            let token = &after[..end];
            if let Some(name) = token.strip_prefix("ENV:") {
                match std::env::var(name) {
                    Ok(value) => out.push_str(&value),
                    Err(_) => out.push_str(&rest[start..start + 2 + end + 1]),
                }
            } else if let Some(path) = token.strip_prefix("FILE:") {
                match std::fs::read_to_string(path) {
                    Ok(value) => out.push_str(value.trim_end()),
                    Err(_) => out.push_str(&rest[start..start + 2 + end + 1]),
                }
            } else {
                out.push_str(&rest[start..start + 2 + end + 1]);
            }
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out
}

/// Apply configured headers that are not already present.
pub fn apply_headers(request: &mut Request, headers: &[String]) -> usize {
    let mut applied = 0;
    for raw in headers {
        if let Some((name, value)) = raw.split_once(':') {
            let name = name.trim();
            if name.is_empty() || request.header(name).is_some() {
                continue;
            }
            request.set_header(name, expand_placeholders(value.trim()));
            applied += 1;
        }
    }
    applied
}

/// Add cookies from the jar that are not already present in the Cookie header.
pub fn apply_cookies(request: &mut Request, jar: &CookieJar) -> usize {
    let url = match request.url() {
        Ok(url) => url,
        Err(_) => return 0,
    };
    let Some(jar_header) = jar.header_for(&url) else {
        return 0;
    };
    let mut pairs: Vec<(String, String)> = request
        .header("Cookie")
        .map(parse_cookie_header)
        .unwrap_or_default();
    let before = pairs.len();
    for (name, value) in parse_cookie_header(&jar_header) {
        if !pairs.iter().any(|(n, _)| n == &name) {
            pairs.push((name, value));
        }
    }
    if pairs.len() != before {
        let merged = pairs
            .into_iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        request.set_header("Cookie", merged);
        return 1;
    }
    0
}

pub fn parse_cookie_header(header: &str) -> Vec<(String, String)> {
    header
        .split(';')
        .filter_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn replace_text(input: &str, pattern: &str, replacement: &str, regex: bool) -> Result<String> {
    if regex {
        let re = regex::Regex::new(pattern)
            .with_context(|| format!("invalid match/replace regex '{pattern}'"))?;
        Ok(re.replace_all(input, replacement).into_owned())
    } else {
        Ok(input.replace(pattern, replacement))
    }
}

fn apply_rules_to(
    headers: &mut [Header],
    body: &mut Vec<u8>,
    rules: &[Rule],
    direction: &str,
) -> Result<usize> {
    let mut changes = 0;
    for rule in rules.iter().filter(|r| r.applies_to(direction)) {
        for header in headers.iter_mut() {
            let line = format!("{}: {}", header.name, header.value);
            let replaced = replace_text(&line, &rule.pattern, &rule.replace, rule.regex)?;
            if replaced != line {
                if let Some((name, value)) = replaced.split_once(':') {
                    header.name = name.trim().to_string();
                    header.value = value.trim().to_string();
                    changes += 1;
                }
            }
        }
        if let Ok(text) = std::str::from_utf8(body) {
            let replaced = replace_text(text, &rule.pattern, &rule.replace, rule.regex)?;
            if replaced != text {
                *body = replaced.into_bytes();
                changes += 1;
            }
        }
    }
    Ok(changes)
}

pub fn apply_request_rules(request: &mut Request, rules: &[Rule]) -> Result<usize> {
    let mut changes = 0;
    for rule in rules.iter().filter(|r| r.applies_to("request")) {
        let replaced = replace_text(&request.target, &rule.pattern, &rule.replace, rule.regex)?;
        if replaced != request.target {
            request.target = replaced;
            changes += 1;
        }
    }
    changes += apply_rules_to(&mut request.headers, &mut request.body, rules, "request")?;
    Ok(changes)
}

pub fn apply_response_rules(response: &mut Response, rules: &[Rule]) -> Result<usize> {
    apply_rules_to(&mut response.headers, &mut response.body, rules, "response")
}

/// Apply the full session (headers, cookies, rules) to an outgoing request.
pub fn apply_session(
    request: &mut Request,
    config: &ProjectConfig,
    state: &SessionState,
) -> Result<usize> {
    if !config.session.auto_apply {
        return Ok(0);
    }
    let mut changes = apply_headers(request, &config.session.headers);
    changes += apply_cookies(request, &state.cookies);
    changes += apply_request_rules(request, &config.session.rules)?;
    Ok(changes)
}

pub fn set_cookie(state: &mut SessionState, name: &str, value: &str, domain: &str, secure: bool) {
    state.cookies.add(name, value, domain, secure);
}

pub fn clear_session(state: &mut SessionState) {
    state.cookies.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request::parse(b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: a=1\r\n\r\n").unwrap()
    }

    #[test]
    fn placeholders_expand() {
        std::env::set_var("BURPCLI_TEST_TOKEN", "secret");
        assert_eq!(
            expand_placeholders("Bearer ${ENV:BURPCLI_TEST_TOKEN}"),
            "Bearer secret"
        );
        assert_eq!(expand_placeholders("${NOPE:x}"), "${NOPE:x}");
    }

    #[test]
    fn cookies_merge_without_duplicates() {
        let mut jar = CookieJar::new();
        jar.add("a", "2", "example.com", false);
        jar.add("b", "3", "example.com", false);
        let mut req = request();
        apply_cookies(&mut req, &jar);
        assert_eq!(req.header("Cookie").unwrap(), "a=1; b=3");
    }

    #[test]
    fn rules_apply_to_headers_body_and_target() {
        let mut req = request();
        req.method = "POST".into();
        req.body = b"csrf=old".to_vec();
        let rules = vec![
            Rule {
                pattern: "a=1".into(),
                replace: "a=2".into(),
                regex: false,
                enabled: true,
                direction: "request".into(),
            },
            Rule {
                pattern: r"csrf=\w+".into(),
                replace: "csrf=new".into(),
                regex: true,
                enabled: true,
                direction: "request".into(),
            },
        ];
        apply_request_rules(&mut req, &rules).unwrap();
        assert_eq!(req.header("Cookie").unwrap(), "a=2");
        assert_eq!(req.body, b"csrf=new");
    }

    #[test]
    fn direction_filter() {
        let rule = Rule {
            pattern: "x".into(),
            replace: "y".into(),
            regex: false,
            enabled: true,
            direction: "response".into(),
        };
        assert!(!rule.applies_to("request"));
        assert!(rule.applies_to("response"));
    }
}
