//! Active checks and insertion-point handling.

use super::issue::{Confidence, Issue, IssueBuilder, Severity};
use super::RateLimiter;
use crate::http::client::{self, ClientOptions, HttpResponse};
use crate::http::{Request, Response};
use crate::oob::OobProvider;
use crate::util::{body_similarity, random_token};
use anyhow::{anyhow, Context, Result};
use percent_encoding::{percent_decode_str, utf8_percent_encode};
use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const ALL_CHECKS: &[&str] = &[
    "xss",
    "sqli",
    "ssti",
    "lfi",
    "redirect",
    "cmdi",
    "crlf",
    "nosql",
    "ssrf",
    "xxe",
    "cors",
    "host-header",
    "jwt",
];

pub const POINT_CHECKS: &[&str] = &[
    "xss", "sqli", "ssti", "lfi", "redirect", "cmdi", "crlf", "nosql", "ssrf",
];

pub const REQUEST_CHECKS: &[&str] = &["xxe", "cors", "host-header", "jwt"];

pub fn check_description(name: &str) -> &'static str {
    match name {
        "xss" => "Reflected cross-site scripting",
        "sqli" => "SQL injection (error, boolean and optional time based)",
        "ssti" => "Server-side template injection",
        "lfi" => "Local file inclusion / path traversal",
        "redirect" => "Open redirect",
        "cmdi" => "OS command injection (echo and optional time based)",
        "crlf" => "CRLF / HTTP response header injection",
        "nosql" => "NoSQL injection",
        "ssrf" => "Server-side request forgery (requires OOB)",
        "xxe" => "XML external entity injection (requires OOB)",
        "cors" => "CORS origin reflection with credentials",
        "host-header" => "Host header injection / reflection",
        "jwt" => "JWT alg=none acceptance",
        _ => "Unknown check",
    }
}

pub struct CheckContext<'a> {
    pub client: &'a ClientOptions,
    pub limiter: &'a RateLimiter,
    pub baseline_duration: Duration,
    pub timing: bool,
    pub oob: Option<&'a dyn OobProvider>,
    pub save_evidence: bool,
    pub request_count: &'a AtomicUsize,
}

#[derive(Default)]
pub struct CheckOutcome {
    pub issues: Vec<Issue>,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointKind {
    Query,
    Form,
    Json,
    Cookie,
    Header,
    Path,
}

impl PointKind {
    pub fn label(&self) -> &'static str {
        match self {
            PointKind::Query => "query",
            PointKind::Form => "form",
            PointKind::Json => "json",
            PointKind::Cookie => "cookie",
            PointKind::Header => "header",
            PointKind::Path => "path",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "query" | "get" => Some(Self::Query),
            "form" | "body" | "post" => Some(Self::Form),
            "json" => Some(Self::Json),
            "cookie" | "cookies" => Some(Self::Cookie),
            "header" | "headers" => Some(Self::Header),
            "path" => Some(Self::Path),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InsertionPoint {
    pub kind: PointKind,
    pub name: String,
    pub original: String,
    pub path_index: usize,
}

impl InsertionPoint {
    pub fn label(&self) -> String {
        format!("{}:{}", self.kind.label(), self.name)
    }

    pub fn inject(&self, request: &Request, payload: &str) -> Result<Request> {
        let mut out = request.clone();
        match self.kind {
            PointKind::Query => {
                out.target = replace_query(&request.target, &self.name, payload)?;
            }
            PointKind::Form => {
                let body = String::from_utf8_lossy(&request.body);
                let new_body = replace_form(&body, &self.name, payload);
                out.body = new_body.into_bytes();
                out.set_header("Content-Length", out.body.len().to_string());
            }
            PointKind::Json => {
                let mut value: Value = serde_json::from_slice(&request.body)
                    .context("request body is not valid JSON")?;
                let pointer = &self.name;
                let target = value
                    .pointer_mut(pointer)
                    .ok_or_else(|| anyhow!("JSON pointer '{pointer}' no longer exists"))?;
                *target = Value::String(payload.to_string());
                out.body = serde_json::to_vec(&value)?;
                out.set_header("Content-Length", out.body.len().to_string());
            }
            PointKind::Cookie => {
                let header = request.header("Cookie").unwrap_or("");
                let pairs: Vec<String> = header
                    .split(';')
                    .map(|part| {
                        let trimmed = part.trim();
                        match trimmed.split_once('=') {
                            Some((name, _)) if name == self.name => {
                                format!("{}={}", self.name, cookie_encode(payload))
                            }
                            _ => trimmed.to_string(),
                        }
                    })
                    .filter(|p| !p.is_empty())
                    .collect();
                let mut pairs = pairs;
                if !pairs
                    .iter()
                    .any(|p| p.starts_with(&format!("{}=", self.name)))
                {
                    pairs.push(format!("{}={}", self.name, cookie_encode(payload)));
                }
                out.set_header("Cookie", pairs.join("; "));
            }
            PointKind::Header => {
                out.set_header(&self.name, payload);
            }
            PointKind::Path => {
                let (path, query) = match request.target.split_once('?') {
                    Some((p, q)) => (p.to_string(), Some(q.to_string())),
                    None => (request.target.clone(), None),
                };
                let mut segments: Vec<String> = path.split('/').map(|s| s.to_string()).collect();
                if self.path_index < segments.len() {
                    segments[self.path_index] = encode_component(payload);
                }
                let mut new_target = segments.join("/");
                if let Some(query) = query {
                    new_target.push('?');
                    new_target.push_str(&query);
                }
                out.target = new_target;
            }
        }
        Ok(out)
    }
}

fn encode_component(value: &str) -> String {
    const PATH_SAFE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'<')
        .add(b'>')
        .add(b'`')
        .add(b'#')
        .add(b'?')
        .add(b'{')
        .add(b'}')
        .add(b'/')
        .add(b'\\')
        .add(b';')
        .add(b'%')
        .add(b'&')
        .add(b'=');
    utf8_percent_encode(value, PATH_SAFE).to_string()
}

fn cookie_encode(value: &str) -> String {
    value
        .replace(';', "%3B")
        .replace(' ', "%20")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn replace_query(target: &str, name: &str, payload: &str) -> Result<String> {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q.to_string()),
        None => (target, String::new()),
    };
    let encoded = encode_component(payload);
    let mut found = false;
    let mut pairs = Vec::new();
    if !query.is_empty() {
        for pair in query.split('&') {
            let (key, _) = pair.split_once('=').unwrap_or((pair, ""));
            let decoded = percent_decode_str(key).decode_utf8_lossy();
            if decoded == name {
                pairs.push(format!("{key}={encoded}"));
                found = true;
            } else {
                pairs.push(pair.to_string());
            }
        }
    }
    if !found {
        pairs.push(format!("{}={}", encode_component(name), encoded));
    }
    Ok(format!("{path}?{}", pairs.join("&")))
}

fn replace_form(body: &str, name: &str, payload: &str) -> String {
    let encoded = encode_component(payload);
    let mut found = false;
    let mut pairs = Vec::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, _) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded = percent_decode_str(key).decode_utf8_lossy();
        if decoded == name {
            pairs.push(format!("{key}={encoded}"));
            found = true;
        } else {
            pairs.push(pair.to_string());
        }
    }
    if !found {
        pairs.push(format!("{}={}", encode_component(name), encoded));
    }
    pairs.join("&")
}

pub fn insertion_points(request: &Request) -> Vec<InsertionPoint> {
    let mut points = Vec::new();
    let mut seen = HashSet::new();

    // Query string.
    if let Some(query) = request.target.split_once('?').map(|(_, q)| q) {
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let name = name.to_string();
            if seen.insert(format!("query:{name}")) {
                points.push(InsertionPoint {
                    kind: PointKind::Query,
                    name,
                    original: value.to_string(),
                    path_index: 0,
                });
            }
        }
    }

    // Form body.
    if request.is_form() {
        let body = String::from_utf8_lossy(&request.body);
        for (name, value) in url::form_urlencoded::parse(body.as_bytes()) {
            let name = name.to_string();
            if seen.insert(format!("form:{name}")) {
                points.push(InsertionPoint {
                    kind: PointKind::Form,
                    name,
                    original: value.to_string(),
                    path_index: 0,
                });
            }
        }
    }

    // JSON string values.
    if request.is_json() {
        if let Ok(value) = serde_json::from_slice::<Value>(&request.body) {
            let mut collected = Vec::new();
            collect_json_strings(&value, "", 0, &mut collected);
            for (pointer, original) in collected {
                if seen.insert(format!("json:{pointer}")) {
                    points.push(InsertionPoint {
                        kind: PointKind::Json,
                        name: pointer,
                        original,
                        path_index: 0,
                    });
                }
            }
        }
    }

    // Cookies.
    if let Some(cookie) = request.header("Cookie") {
        for (name, value) in crate::session::parse_cookie_header(cookie) {
            if seen.insert(format!("cookie:{name}")) {
                points.push(InsertionPoint {
                    kind: PointKind::Cookie,
                    name,
                    original: value,
                    path_index: 0,
                });
            }
        }
    }

    // Headers commonly used by applications and caches.
    for name in [
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "Origin",
    ] {
        let original = request.header(name).unwrap_or("").to_string();
        points.push(InsertionPoint {
            kind: PointKind::Header,
            name: name.to_string(),
            original,
            path_index: 0,
        });
    }

    // Path segments (skip the leading empty segment).
    let path = request
        .target
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(&request.target);
    for (index, segment) in path.split('/').enumerate() {
        if segment.is_empty() {
            continue;
        }
        points.push(InsertionPoint {
            kind: PointKind::Path,
            name: format!("/segment/{index}"),
            original: segment.to_string(),
            path_index: index,
        });
    }

    points
}

fn collect_json_strings(
    value: &Value,
    prefix: &str,
    depth: usize,
    out: &mut Vec<(String, String)>,
) {
    if depth > 8 {
        return;
    }
    match value {
        Value::String(s) => out.push((prefix.to_string(), s.clone())),
        Value::Object(map) => {
            for (key, child) in map {
                let pointer = format!("{}/{}", prefix, key.replace('~', "~0").replace('/', "~1"));
                collect_json_strings(child, &pointer, depth + 1, out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let pointer = format!("{prefix}/{index}");
                collect_json_strings(child, &pointer, depth + 1, out);
            }
        }
        _ => {}
    }
}

pub fn run_point_checks(
    names: &[String],
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
    ctx: &CheckContext,
) -> CheckOutcome {
    let mut outcome = CheckOutcome::default();
    for name in names {
        let result = match name.as_str() {
            "xss" => check_xss(ctx, request, point, baseline),
            "sqli" => check_sqli(ctx, request, point, baseline),
            "ssti" => check_ssti(ctx, request, point, baseline),
            "lfi" => check_lfi(ctx, request, point, baseline),
            "redirect" => check_redirect(ctx, request, point, baseline),
            "cmdi" => check_cmdi(ctx, request, point, baseline),
            "crlf" => check_crlf(ctx, request, point, baseline),
            "nosql" => check_nosql(ctx, request, point, baseline),
            "ssrf" => check_ssrf(ctx, request, point, baseline),
            _ => continue,
        };
        match result {
            Ok(issues) => outcome.issues.extend(issues),
            Err(error) => outcome
                .errors
                .push(format!("{name} {}: {error}", point.label())),
        }
    }
    outcome
}

pub fn run_request_checks(
    names: &[String],
    request: &Request,
    baseline: &Response,
    ctx: &CheckContext,
) -> CheckOutcome {
    let mut outcome = CheckOutcome::default();
    for name in names {
        let result = match name.as_str() {
            "cors" => check_cors(ctx, request),
            "host-header" => check_host_header(ctx, request),
            "xxe" => check_xxe(ctx, request),
            "jwt" => check_jwt(ctx, request, baseline),
            _ => continue,
        };
        match result {
            Ok(issues) => outcome.issues.extend(issues),
            Err(error) => outcome.errors.push(format!("{name}: {error}")),
        }
    }
    outcome
}

fn send_probe(ctx: &CheckContext, request: &Request) -> Result<HttpResponse> {
    ctx.limiter.wait();
    ctx.request_count.fetch_add(1, Ordering::Relaxed);
    client::send(request, ctx.client)
}

fn issue_builder(
    request: &Request,
    response: Option<&Response>,
    ctx: &CheckContext,
    check: &str,
    title: &str,
    severity: Severity,
) -> IssueBuilder {
    let mut builder = Issue::builder(check, title, severity).request(request, ctx.save_evidence);
    if let Some(response) = response {
        builder = builder.response(response, ctx.save_evidence);
    }
    builder
}

fn response_text(response: &Response) -> String {
    response.body_text()
}

fn snippet(text: &str, needle: &str, max: usize) -> String {
    match text.find(needle) {
        Some(pos) => {
            let start = pos.saturating_sub(max / 2);
            let end = (pos + needle.len() + max / 2).min(text.len());
            let mut start = start;
            while start < text.len() && !text.is_char_boundary(start) {
                start += 1;
            }
            let mut end = end;
            while end > start && !text.is_char_boundary(end) {
                end -= 1;
            }
            text[start..end].replace(['\r', '\n'], " ")
        }
        None => text.chars().take(max).collect(),
    }
}

fn check_xss(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
) -> Result<Vec<Issue>> {
    let marker = random_token(6);
    let payload = format!("<svg/onload=alert('{marker}')>");
    let injected = point.inject(request, &payload)?;
    let response = send_probe(ctx, &injected)?.response;
    let body = response_text(&response);
    let baseline_body = response_text(baseline);
    if response.is_html() && body.contains(&payload) && !baseline_body.contains(&payload) {
        return Ok(vec![issue_builder(
            request,
            Some(&response),
            ctx,
            "xss",
            "Reflected cross-site scripting",
            Severity::High,
        )
        .confidence(Confidence::Firm)
        .parameter(point.label())
        .payload(&payload)
        .evidence(snippet(&body, &payload, 160))
        .detail("The payload is reflected unencoded in an HTML response.")
        .remediation("Context-aware output encoding and a restrictive CSP.")
        .cwe(79)
        .build()]);
    }
    Ok(Vec::new())
}

fn check_sqli(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
) -> Result<Vec<Issue>> {
    let baseline_body = response_text(baseline);
    for payload in ["'", "\"", "')", "1'"] {
        let injected = point.inject(request, payload)?;
        let response = send_probe(ctx, &injected)?.response;
        let body = response_text(&response);
        if let Some(matched) = sql_error_regex().find(&body) {
            if !sql_error_regex().is_match(&baseline_body) {
                return Ok(vec![issue_builder(
                    request,
                    Some(&response),
                    ctx,
                    "sqli",
                    "SQL injection (error based)",
                    Severity::High,
                )
                .confidence(Confidence::Certain)
                .parameter(point.label())
                .payload(payload)
                .evidence(snippet(&body, matched.as_str(), 160))
                .detail("A database error was triggered by a crafted quote payload.")
                .remediation("Use parameterised queries and suppress database errors.")
                .cwe(89)
                .build()]);
            }
        }
    }

    // Boolean-based differential test.
    for (true_payload, false_payload) in [
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
    ] {
        let true_response = send_probe(ctx, &point.inject(request, true_payload)?)?.response;
        let false_response = send_probe(ctx, &point.inject(request, false_payload)?)?.response;
        if true_response.status == false_response.status && true_response.status < 500 {
            let true_similarity = body_similarity(&baseline.body, &true_response.body);
            let false_similarity = body_similarity(&baseline.body, &false_response.body);
            if true_similarity > 0.92
                && false_similarity < 0.85
                && true_similarity - false_similarity > 0.12
            {
                return Ok(vec![issue_builder(
                    request,
                    Some(&true_response),
                    ctx,
                    "sqli",
                    "SQL injection (boolean based)",
                    Severity::Medium,
                )
                .confidence(Confidence::Firm)
                .parameter(point.label())
                .payload(true_payload)
                .evidence(format!(
                    "true payload similarity {:.2}, false payload similarity {:.2}",
                    true_similarity, false_similarity
                ))
                .detail("A true/false condition pair produced materially different responses.")
                .remediation("Use parameterised queries.")
                .cwe(89)
                .build()]);
            }
        }
    }

    if ctx.timing && ctx.baseline_duration < Duration::from_secs(3) {
        for payload in [
            "' AND SLEEP(5)-- -",
            "'||pg_sleep(5)--",
            "';WAITFOR DELAY '0:0:5'--",
        ] {
            let started = Instant::now();
            let response = send_probe(ctx, &point.inject(request, payload)?)?.response;
            let elapsed = started.elapsed();
            if elapsed > Duration::from_secs(4) && response.status < 500 {
                return Ok(vec![issue_builder(
                    request,
                    Some(&response),
                    ctx,
                    "sqli",
                    "SQL injection (time based)",
                    Severity::High,
                )
                .confidence(Confidence::Firm)
                .parameter(point.label())
                .payload(payload)
                .evidence(format!("response delayed by {:.1}s", elapsed.as_secs_f64()))
                .detail("A database sleep function caused a measurable delay.")
                .remediation("Use parameterised queries.")
                .cwe(89)
                .build()]);
            }
        }
    }
    Ok(Vec::new())
}

fn sql_error_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(you have an error in your sql syntax|warning:\s*mysql|mysql_fetch|mysqli?_|SQLSTATE\[|ORA-\d{5}|postgresql.*error|pg_query|sqlite3?::|sqlite_error|unclosed quotation mark|quoted string not properly terminated|microsoft OLE DB|syntax error at or near|unterminated string literal|invalid input syntax for)",
        )
        .unwrap()
    })
}

fn check_ssti(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
) -> Result<Vec<Issue>> {
    let expected = "62710561"; // 7919 * 7919
    let baseline_body = response_text(baseline);
    for payload in [
        "{{7919*7919}}",
        "${7919*7919}",
        "<%= 7919*7919 %>",
        "#{7919*7919}",
    ] {
        let response = send_probe(ctx, &point.inject(request, payload)?)?.response;
        let body = response_text(&response);
        if body.contains(expected) && !body.contains(payload) && !baseline_body.contains(expected) {
            return Ok(vec![issue_builder(
                request,
                Some(&response),
                ctx,
                "ssti",
                "Server-side template injection",
                Severity::High,
            )
            .confidence(Confidence::Firm)
            .parameter(point.label())
            .payload(payload)
            .evidence(snippet(&body, expected, 140))
            .detail("A template expression was evaluated by the server.")
            .remediation("Do not render user input as templates; use sandboxed templates.")
            .cwe(1336)
            .build()]);
        }
    }
    Ok(Vec::new())
}

fn check_lfi(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
) -> Result<Vec<Issue>> {
    let baseline_body = response_text(baseline);
    let payloads = [
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
    ];
    let signatures = ["root:x:0:0:", "[extensions]", "for 16-bit app support"];
    for payload in payloads {
        let response = send_probe(ctx, &point.inject(request, payload)?)?.response;
        let body = response_text(&response);
        if let Some(signature) = signatures
            .iter()
            .find(|s| body.contains(*s) && !baseline_body.contains(*s))
        {
            return Ok(vec![issue_builder(
                request,
                Some(&response),
                ctx,
                "lfi",
                "Local file inclusion / path traversal",
                Severity::High,
            )
            .confidence(Confidence::Certain)
            .parameter(point.label())
            .payload(payload)
            .evidence(snippet(&body, signature, 160))
            .detail("A known system file signature was returned by the server.")
            .remediation("Validate file paths against an allow-list and disable traversal.")
            .cwe(22)
            .build()]);
        }
    }
    Ok(Vec::new())
}

fn check_redirect(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
) -> Result<Vec<Issue>> {
    for payload in [
        "https://burpcli.invalid/redirect",
        "//burpcli.invalid/redirect",
    ] {
        let response = send_probe(ctx, &point.inject(request, payload)?)?.response;
        if let Some(location) = response.header("location") {
            if location.contains("burpcli.invalid")
                && !baseline
                    .header("location")
                    .unwrap_or("")
                    .contains("burpcli.invalid")
            {
                return Ok(vec![issue_builder(
                    request,
                    Some(&response),
                    ctx,
                    "redirect",
                    "Open redirect",
                    Severity::Medium,
                )
                .confidence(Confidence::Firm)
                .parameter(point.label())
                .payload(payload)
                .evidence(format!("Location: {location}"))
                .detail("User-controlled input is used in a redirect without validation.")
                .remediation("Only redirect to allow-listed destinations or relative paths.")
                .cwe(601)
                .build()]);
            }
        }
    }
    Ok(Vec::new())
}

fn check_cmdi(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
) -> Result<Vec<Issue>> {
    let marker = random_token(10);
    let payloads = [
        format!(";echo {marker}"),
        format!("|echo {marker}"),
        format!("$(echo {marker})"),
        format!("`echo {marker}`"),
        format!("& echo {marker}"),
    ];
    let baseline_body = response_text(baseline);
    for payload in payloads {
        let response = send_probe(ctx, &point.inject(request, &payload)?)?.response;
        let body = response_text(&response);
        if body.contains(&marker) && !body.contains(&payload) && !baseline_body.contains(&marker) {
            return Ok(vec![issue_builder(
                request,
                Some(&response),
                ctx,
                "cmdi",
                "OS command injection",
                Severity::High,
            )
            .confidence(Confidence::Certain)
            .parameter(point.label())
            .payload(&payload)
            .evidence(snippet(&body, &marker, 160))
            .detail("A shell command produced output in the HTTP response.")
            .remediation("Avoid shell invocation; use strict allow-lists and argument arrays.")
            .cwe(78)
            .build()]);
        }
    }

    if ctx.timing && ctx.baseline_duration < Duration::from_secs(3) {
        for payload in [";sleep 5", "|sleep 5", "& ping -n 6 127.0.0.1"] {
            let started = Instant::now();
            let response = send_probe(ctx, &point.inject(request, payload)?)?.response;
            let elapsed = started.elapsed();
            if elapsed > Duration::from_secs(4) && response.status < 500 {
                return Ok(vec![issue_builder(
                    request,
                    Some(&response),
                    ctx,
                    "cmdi",
                    "OS command injection (time based)",
                    Severity::High,
                )
                .confidence(Confidence::Firm)
                .parameter(point.label())
                .payload(payload)
                .evidence(format!("response delayed by {:.1}s", elapsed.as_secs_f64()))
                .detail("A shell sleep command caused a measurable delay.")
                .remediation("Avoid shell invocation.")
                .cwe(78)
                .build()]);
            }
        }
    }
    Ok(Vec::new())
}

fn check_crlf(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
) -> Result<Vec<Issue>> {
    let marker = random_token(8);
    let payloads = [
        format!("\r\nX-Burpcli-Injected: {marker}"),
        format!("\r\nSet-Cookie: burpcli={marker}"),
        format!("%0d%0aX-Burpcli-Injected: {marker}"),
    ];
    for payload in payloads {
        let response = send_probe(ctx, &point.inject(request, &payload)?)?.response;
        let injected = response.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("x-burpcli-injected") || header.value.contains(&marker)
        });
        let baseline_injected = baseline
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("x-burpcli-injected"));
        if injected && !baseline_injected {
            return Ok(vec![issue_builder(
                request,
                Some(&response),
                ctx,
                "crlf",
                "CRLF / response header injection",
                Severity::Medium,
            )
            .confidence(Confidence::Firm)
            .parameter(point.label())
            .payload(payload.escape_debug().to_string())
            .evidence(format!(
                "injected marker {marker} appeared in response headers"
            ))
            .detail("CRLF sequences in user input reached the response header block.")
            .remediation("Strip CR/LF from user input and use framework header APIs.")
            .cwe(113)
            .build()]);
        }
    }
    Ok(Vec::new())
}

fn check_nosql(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    baseline: &Response,
) -> Result<Vec<Issue>> {
    let baseline_body = response_text(baseline);
    let error =
        Regex::new(r"(?i)(MongoError|E11000|BSON|CastError|ObjectId|MongoServerError)").unwrap();
    for payload in ["'", "{\"$ne\": null}", "' || '1'=='1"] {
        let response = send_probe(ctx, &point.inject(request, payload)?)?.response;
        let body = response_text(&response);
        if let Some(matched) = error.find(&body) {
            if !error.is_match(&baseline_body) {
                return Ok(vec![issue_builder(
                    request,
                    Some(&response),
                    ctx,
                    "nosql",
                    "NoSQL injection (error based)",
                    Severity::Medium,
                )
                .confidence(Confidence::Firm)
                .parameter(point.label())
                .payload(payload)
                .evidence(snippet(&body, matched.as_str(), 160))
                .detail("A NoSQL/database error was triggered by crafted input.")
                .remediation("Validate types and use parameterised query builders.")
                .cwe(943)
                .build()]);
            }
        }
    }

    let true_response = send_probe(ctx, &point.inject(request, "' || '1'=='1")?)?.response;
    let false_response = send_probe(ctx, &point.inject(request, "' || '1'=='2")?)?.response;
    if true_response.status == false_response.status && true_response.status < 500 {
        let true_similarity = body_similarity(&baseline.body, &true_response.body);
        let false_similarity = body_similarity(&baseline.body, &false_response.body);
        if true_similarity > 0.92 && false_similarity < 0.85 {
            return Ok(vec![issue_builder(
                request,
                Some(&true_response),
                ctx,
                "nosql",
                "NoSQL injection (boolean based)",
                Severity::Medium,
            )
            .confidence(Confidence::Firm)
            .parameter(point.label())
            .payload("' || '1'=='1")
            .evidence(format!(
                "true similarity {:.2}, false similarity {:.2}",
                true_similarity, false_similarity
            ))
            .detail("A boolean expression changed the server response.")
            .remediation("Validate types and use parameterised query builders.")
            .cwe(943)
            .build()]);
        }
    }
    Ok(Vec::new())
}

fn check_ssrf(
    ctx: &CheckContext,
    request: &Request,
    point: &InsertionPoint,
    _baseline: &Response,
) -> Result<Vec<Issue>> {
    let Some(oob) = ctx.oob else {
        return Ok(Vec::new());
    };
    let token = oob.new_token();
    let payload = oob.payload_url(&token);
    let response = send_probe(ctx, &point.inject(request, &payload)?)?.response;
    if oob.wait_for_hit(&token, Duration::from_secs(4)) {
        return Ok(vec![issue_builder(
            request,
            Some(&response),
            ctx,
            "ssrf",
            "Server-side request forgery",
            Severity::High,
        )
        .confidence(Confidence::Certain)
        .parameter(point.label())
        .payload(payload)
        .evidence(format!(
            "out-of-band interaction received for token {token}"
        ))
        .detail("The server fetched an attacker-controlled URL.")
        .remediation("Allow-list outbound destinations and block internal address ranges.")
        .cwe(918)
        .build()]);
    }
    Ok(Vec::new())
}

fn check_cors(ctx: &CheckContext, request: &Request) -> Result<Vec<Issue>> {
    let mut issues = Vec::new();
    for origin in ["https://burpcli.invalid", "null"] {
        let mut probe = request.clone();
        probe.set_header("Origin", origin);
        let response = send_probe(ctx, &probe)?.response;
        let acao = response
            .header("access-control-allow-origin")
            .unwrap_or("")
            .trim()
            .to_string();
        let credentials = response
            .header("access-control-allow-credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if acao == origin {
            issues.push(
                issue_builder(
                    request,
                    Some(&response),
                    ctx,
                    "cors",
                    if credentials {
                        "CORS reflects arbitrary origins with credentials"
                    } else {
                        "CORS reflects arbitrary origins"
                    },
                    if credentials { Severity::High } else { Severity::Medium },
                )
                .confidence(Confidence::Firm)
                .evidence(format!(
                    "Origin: {origin} -> Access-Control-Allow-Origin: {acao}; credentials: {credentials}"
                ))
                .detail("The server trusts any origin, allowing cross-origin data theft.")
                .remediation("Validate Origin against an allow-list; never reflect arbitrary origins.")
                .cwe(942)
                .build(),
            );
        }
    }
    Ok(issues)
}

fn check_host_header(ctx: &CheckContext, request: &Request) -> Result<Vec<Issue>> {
    let (host, port, _tls) = request.service()?;
    let mut issues = Vec::new();
    for header in ["Host", "X-Forwarded-Host", "X-Forwarded-For"] {
        let mut probe = request.clone();
        probe.set_header(header, "burpcli.invalid");
        if header == "Host" {
            probe.connect_to = Some(format!("{host}:{port}"));
            probe.tls_server_name = Some(host.clone());
        }
        let response = send_probe(ctx, &probe)?.response;
        let body = response_text(&response);
        let location = response.header("location").unwrap_or("");
        if body.contains("burpcli.invalid") || location.contains("burpcli.invalid") {
            issues.push(
                issue_builder(
                    request,
                    Some(&response),
                    ctx,
                    "host-header",
                    "Host header injection",
                    Severity::Medium,
                )
                .confidence(Confidence::Tentative)
                .parameter(header)
                .payload("burpcli.invalid")
                .evidence(snippet(&body, "burpcli.invalid", 160))
                .detail("The supplied host value is reflected in the response.")
                .remediation("Validate Host/X-Forwarded-* headers against configured hostnames.")
                .cwe(644)
                .build(),
            );
            break;
        }
    }
    Ok(issues)
}

fn check_xxe(ctx: &CheckContext, request: &Request) -> Result<Vec<Issue>> {
    let Some(oob) = ctx.oob else {
        return Ok(Vec::new());
    };
    if !request.is_xml() && !request.body.starts_with(b"<") {
        return Ok(Vec::new());
    }
    let token = oob.new_token();
    let url = oob.payload_url(&token);
    let body = String::from_utf8_lossy(&request.body);
    let doctype = format!("<!DOCTYPE burpcli [<!ENTITY % xxe SYSTEM \"{url}\"> %xxe;]>");
    let new_body = if let Some(pos) = body.find("?>") {
        format!("{}{}{}", &body[..pos + 2], doctype, &body[pos + 2..])
    } else {
        format!("{doctype}{body}")
    };
    let mut probe = request.clone();
    probe.body = new_body.into_bytes();
    probe.set_header("Content-Length", probe.body.len().to_string());
    let response = send_probe(ctx, &probe)?.response;
    if oob.wait_for_hit(&token, Duration::from_secs(4)) {
        return Ok(vec![issue_builder(
            request,
            Some(&response),
            ctx,
            "xxe",
            "XML external entity injection",
            Severity::High,
        )
        .confidence(Confidence::Certain)
        .payload(doctype)
        .evidence(format!(
            "out-of-band interaction received for token {token}"
        ))
        .detail("The XML parser resolved an external entity controlled by the attacker.")
        .remediation("Disable external entities and DTD processing in the XML parser.")
        .cwe(611)
        .build()]);
    }
    Ok(Vec::new())
}

fn jwt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*").unwrap()
    })
}

fn check_jwt(ctx: &CheckContext, request: &Request, baseline: &Response) -> Result<Vec<Issue>> {
    let mut token = None;
    let mut header_name = None;
    for header in &request.headers {
        if let Some(matched) = jwt_regex().find(&header.value) {
            token = Some(matched.as_str().to_string());
            header_name = Some(header.name.clone());
            break;
        }
    }
    let (Some(token), Some(header_name)) = (token, header_name) else {
        return Ok(Vec::new());
    };
    let none_token = match crate::decoder::jwt_none(&token) {
        Ok(token) => token,
        Err(_) => return Ok(Vec::new()),
    };
    let mut garbage = token.clone();
    let mut parts: Vec<&str> = garbage.split('.').collect();
    if parts.len() == 3 {
        parts[2] = "AAAAAAAAAAAAAAAAAAAAAA";
        garbage = parts.join(".");
    }

    let mut none_request = request.clone();
    none_request.set_header(&header_name, none_token.clone());
    let none_response = send_probe(ctx, &none_request)?.response;

    let mut garbage_request = request.clone();
    garbage_request.set_header(&header_name, garbage);
    let garbage_response = send_probe(ctx, &garbage_request)?.response;

    let none_similarity = body_similarity(&baseline.body, &none_response.body);
    let garbage_similarity = body_similarity(&baseline.body, &garbage_response.body);
    let none_accepted = none_response.status < 400 && none_similarity > 0.9;
    let garbage_rejected = garbage_response.status >= 400 || garbage_similarity < 0.7;
    if none_accepted && garbage_rejected {
        return Ok(vec![issue_builder(
            request,
            Some(&none_response),
            ctx,
            "jwt",
            "JWT accepts alg=none",
            Severity::High,
        )
        .confidence(Confidence::Firm)
        .parameter(header_name)
        .evidence(format!(
            "alg=none status {}, similarity {:.2}; invalid signature status {}",
            none_response.status, none_similarity, garbage_response.status
        ))
        .detail("The server accepted an unsigned token while rejecting an invalid signature.")
        .remediation("Reject alg=none and pin the expected algorithms during verification.")
        .cwe(347)
        .build()]);
    }
    Ok(Vec::new())
}

impl fmt::Display for InsertionPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request::parse(
            b"POST /api/items?id=1&name=x HTTP/1.1\r\nHost: example.com\r\nCookie: sid=abc; theme=dark\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=test&page=2",
        )
        .unwrap()
    }

    #[test]
    fn discovers_insertion_points() {
        let points = insertion_points(&request());
        let labels: Vec<String> = points.iter().map(|p| p.label()).collect();
        assert!(labels.contains(&"query:id".to_string()));
        assert!(labels.contains(&"query:name".to_string()));
        assert!(labels.contains(&"form:q".to_string()));
        assert!(labels.contains(&"form:page".to_string()));
        assert!(labels.contains(&"cookie:sid".to_string()));
        assert!(labels.contains(&"header:User-Agent".to_string()));
    }

    #[test]
    fn injects_into_query_and_form() {
        let req = request();
        let point = insertion_points(&req)
            .into_iter()
            .find(|p| p.label() == "query:id")
            .unwrap();
        let injected = point.inject(&req, "<script>").unwrap();
        assert_eq!(injected.target, "/api/items?id=%3Cscript%3E&name=x");
        let post = insertion_points(&req)
            .into_iter()
            .find(|p| p.label() == "form:page")
            .unwrap()
            .inject(&req, "x y")
            .unwrap();
        assert_eq!(post.body, b"q=test&page=x%20y");
        assert_eq!(post.header("Content-Length").unwrap(), "17");
    }

    #[test]
    fn injects_into_cookie_header_and_path() {
        let req = request();
        let point = insertion_points(&req)
            .into_iter()
            .find(|p| p.label() == "cookie:sid")
            .unwrap();
        let injected = point.inject(&req, "a;b").unwrap();
        assert!(injected.header("Cookie").unwrap().contains("sid=a%3Bb"));

        let host = insertion_points(&req)
            .into_iter()
            .find(|p| p.label() == "header:User-Agent")
            .unwrap()
            .inject(&req, "evil-agent")
            .unwrap();
        assert_eq!(host.header("User-Agent").unwrap(), "evil-agent");

        let path = insertion_points(&req)
            .into_iter()
            .find(|p| p.label() == "path:/segment/2")
            .unwrap()
            .inject(&req, "../x")
            .unwrap();
        assert!(path.target.starts_with("/api/..%2Fx?"));
    }

    #[test]
    fn json_insertion() {
        let mut req = Request::parse(
            b"POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":{\"name\":\"bob\"},\"tags\":[\"a\"]}",
        )
        .unwrap();
        req.scheme = Some("http".into());
        let points = insertion_points(&req);
        let name_point = points.iter().find(|p| p.name == "/user/name").unwrap();
        let injected = name_point.inject(&req, "x\"y").unwrap();
        let value: Value = serde_json::from_slice(&injected.body).unwrap();
        assert_eq!(value["user"]["name"], "x\"y");
    }
}
