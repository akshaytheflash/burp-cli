//! Passive checks: findings that can be made from a single request/response.

use super::issue::{Confidence, Issue, Severity};
use crate::http::{Request, Response};
use regex::Regex;
use std::sync::OnceLock;

pub fn scan(request: &Request, response: &Response, save_evidence: bool) -> Vec<Issue> {
    let mut issues = Vec::new();
    let url = request
        .url()
        .map(|u| u.to_string())
        .unwrap_or_else(|_| request.target.clone());
    let html = response.is_html();
    let https = url.starts_with("https://");
    let body = response.body_text();

    let base = |check: &str, title: &str, severity: Severity| {
        Issue::builder(check, title, severity)
            .request(request, save_evidence)
            .response(response, save_evidence)
            .url(url.clone())
    };

    if html {
        let headers = [
            (
                "strict-transport-security",
                "missing-sts",
                "Strict-Transport-Security header is missing",
                Severity::Low,
                "HSTS is not enforced, allowing protocol downgrade attacks.",
                "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.",
                319,
            ),
            (
                "content-security-policy",
                "missing-csp",
                "Content-Security-Policy header is missing",
                Severity::Low,
                "Without CSP, the impact of cross-site scripting is significantly higher.",
                "Define a restrictive Content-Security-Policy and avoid 'unsafe-inline'.",
                693,
            ),
            (
                "x-content-type-options",
                "missing-nosniff",
                "X-Content-Type-Options header is missing",
                Severity::Low,
                "Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
                "Send `X-Content-Type-Options: nosniff`.",
                16,
            ),
        ];
        for (header, check, title, severity, detail, remediation, cwe) in headers {
            if header == "strict-transport-security" && !https {
                continue;
            }
            if response.header(header).is_none() {
                issues.push(
                    base(check, title, severity)
                        .confidence(Confidence::Certain)
                        .detail(detail)
                        .remediation(remediation)
                        .cwe(cwe)
                        .build(),
                );
            }
        }

        let frame_protection = response.header("x-frame-options").is_some()
            || response
                .header("content-security-policy")
                .map(|c| c.to_ascii_lowercase().contains("frame-ancestors"))
                .unwrap_or(false);
        if !frame_protection {
            issues.push(
                base(
                    "missing-frame-protection",
                    "Clickjacking protection is missing",
                    Severity::Low,
                )
                .confidence(Confidence::Certain)
                .detail("Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed.")
                .remediation("Send `X-Frame-Options: DENY` or a CSP `frame-ancestors` directive.")
                .cwe(1021)
                .build(),
            );
        }

        if response.header("referrer-policy").is_none() {
            issues.push(
                base(
                    "missing-referrer-policy",
                    "Referrer-Policy header is missing",
                    Severity::Info,
                )
                .confidence(Confidence::Certain)
                .detail("URLs may leak to third parties through the Referer header.")
                .remediation("Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.")
                .build(),
            );
        }

        let csp = response
            .header("content-security-policy")
            .unwrap_or("")
            .to_ascii_lowercase();
        if csp.contains("unsafe-inline") || csp.contains("unsafe-eval") {
            issues.push(
                base(
                    "weak-csp",
                    "Content-Security-Policy contains unsafe directives",
                    Severity::Low,
                )
                .confidence(Confidence::Firm)
                .evidence(csp.clone())
                .detail("'unsafe-inline' or 'unsafe-eval' weakens XSS mitigation.")
                .remediation("Remove unsafe-inline/unsafe-eval and use nonces or hashes.")
                .cwe(693)
                .build(),
            );
        }

        let lower = body.to_ascii_lowercase();
        if https {
            let mixed = [
                "src=\"http://",
                "src='http://",
                "href=\"http://",
                "href='http://",
            ]
            .iter()
            .find(|needle| lower.contains(*needle));
            if let Some(needle) = mixed {
                issues.push(
                    base(
                        "mixed-content",
                        "Mixed active/passive content on an HTTPS page",
                        Severity::Low,
                    )
                    .confidence(Confidence::Firm)
                    .evidence(snippet_around(&body, needle, 120))
                    .detail("The page references HTTP resources while being served over HTTPS.")
                    .remediation(
                        "Reference all resources over HTTPS or use protocol-relative URLs.",
                    )
                    .cwe(311)
                    .build(),
                );
            }
        }

        if lower.contains("<title>index of /") || lower.contains("<title>directory listing for") {
            issues.push(
                base(
                    "directory-listing",
                    "Directory listing is enabled",
                    Severity::Low,
                )
                .confidence(Confidence::Firm)
                .detail("The server exposes a browsable directory index.")
                .remediation("Disable directory listings or restrict access.")
                .cwe(548)
                .build(),
            );
        }

        if lower.contains("type=\"password\"") || lower.contains("type=password") {
            let password_inputs = regex::Regex::new(r#"(?i)type\s*=\s*["']?password["'\s>]"#)
                .unwrap()
                .find_iter(&lower)
                .count();
            let protected =
                regex::Regex::new(r#"(?i)autocomplete\s*=\s*["']?(?:off|new-password)["'\s>]"#)
                    .unwrap()
                    .find_iter(&lower)
                    .count();
            if protected < password_inputs {
                issues.push(
                    base(
                        "password-autocomplete",
                        "Password field allows autocomplete",
                        Severity::Info,
                    )
                    .confidence(Confidence::Tentative)
                    .detail("Password inputs without autocomplete=off/new-password may be cached by browsers.")
                    .remediation("Set `autocomplete=\"new-password\"` on password fields where appropriate.")
                    .build(),
                );
            }
        }

        if lower.contains("sourcemappingurl=") {
            issues.push(
                base(
                    "source-map",
                    "JavaScript source map is referenced",
                    Severity::Info,
                )
                .confidence(Confidence::Firm)
                .detail("Source maps can disclose original source code and internal paths.")
                .remediation("Do not deploy source maps to production, or restrict access.")
                .cwe(540)
                .build(),
            );
        }
    }

    // Server banners.
    if let Some(server) = response.header("server") {
        if regex_version().is_match(server) {
            issues.push(
                base(
                    "server-banner",
                    "Server version is disclosed",
                    Severity::Info,
                )
                .confidence(Confidence::Certain)
                .evidence(server.to_string())
                .detail("Detailed server banners help attackers select exploits.")
                .remediation("Remove or generalise the Server header.")
                .cwe(200)
                .build(),
            );
        }
    }
    if let Some(powered) = response.header("x-powered-by") {
        issues.push(
            base(
                "powered-by",
                "Technology stack is disclosed via X-Powered-By",
                Severity::Info,
            )
            .confidence(Confidence::Certain)
            .evidence(powered.to_string())
            .detail("X-Powered-By reveals the framework and sometimes its version.")
            .remediation("Remove the X-Powered-By header.")
            .cwe(200)
            .build(),
        );
    }

    // Cookies.
    for set_cookie in response.headers_named("Set-Cookie") {
        let first = set_cookie.split(';').next().unwrap_or(set_cookie);
        let name = first.split('=').next().unwrap_or("cookie").trim();
        let lower = set_cookie.to_ascii_lowercase();
        let mut missing = Vec::new();
        if https && !lower.contains("secure") {
            missing.push("Secure");
        }
        if !lower.contains("httponly") {
            missing.push("HttpOnly");
        }
        if !lower.contains("samesite") {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            issues.push(
                base(
                    "cookie-flags",
                    "Cookie is missing security attributes",
                    Severity::Low,
                )
                .confidence(Confidence::Certain)
                .parameter(name)
                .evidence(truncate_cookie(set_cookie))
                .detail(format!(
                    "Cookie '{}' is missing: {}.",
                    name,
                    missing.join(", ")
                ))
                .remediation("Set Secure, HttpOnly and SameSite on session cookies.")
                .cwe(1004)
                .build(),
            );
        }
    }

    // Cache control for authenticated / cookie-setting responses.
    if response.header("set-cookie").is_some()
        && response
            .header("cache-control")
            .map(|c| !c.to_ascii_lowercase().contains("no-store"))
            .unwrap_or(true)
    {
        issues.push(
            base(
                "cache-control",
                "Sensitive response may be cached",
                Severity::Info,
            )
            .confidence(Confidence::Tentative)
            .detail("A response that sets cookies lacks Cache-Control: no-store.")
            .remediation("Send `Cache-Control: no-store` for authenticated or sensitive responses.")
            .cwe(525)
            .build(),
        );
    }

    // CORS wildcard.
    if let Some(origin) = response.header("access-control-allow-origin") {
        let credentials = response
            .header("access-control-allow-credentials")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if origin.trim() == "*" && credentials {
            issues.push(
                base(
                    "cors-wildcard",
                    "CORS allows any origin with credentials",
                    Severity::Medium,
                )
                .confidence(Confidence::Certain)
                .evidence("Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true".to_string())
                .detail("The combination is invalid in browsers, but indicates a dangerous CORS policy.")
                .remediation("Allow-list trusted origins and do not combine wildcards with credentials.")
                .cwe(942)
                .build(),
            );
        } else if origin.trim() == "*" {
            issues.push(
                base(
                    "cors-wildcard",
                    "CORS policy allows any origin",
                    Severity::Info,
                )
                .confidence(Confidence::Firm)
                .evidence("Access-Control-Allow-Origin: *".to_string())
                .detail("Any website can read public responses from this endpoint.")
                .remediation("Restrict Access-Control-Allow-Origin to trusted origins when data is sensitive.")
                .cwe(942)
                .build(),
            );
        }
    }

    // Error/stack trace leakage.
    if let Some(signature) = error_signature(&body) {
        issues.push(
            base(
                "error-disclosure",
                "Application error details are disclosed",
                Severity::Low,
            )
            .confidence(Confidence::Tentative)
            .evidence(signature)
            .detail("Verbose errors can reveal file paths, queries or framework internals.")
            .remediation("Return generic error pages and log details server-side.")
            .cwe(209)
            .build(),
        );
    }

    // Secrets in responses.
    for (name, regex, severity, cwe) in secret_patterns() {
        if let Some(matched) = regex.find(&body) {
            issues.push(
                base(
                    "secret-exposure",
                    "Potential secret is exposed in the response",
                    severity,
                )
                .confidence(Confidence::Tentative)
                .parameter(name.to_string())
                .evidence(redact(matched.as_str()))
                .detail(format!("The response contains data matching a {name} pattern."))
                .remediation("Remove secrets from responses, rotate exposed credentials and use a secret manager.")
                .cwe(cwe)
                .build(),
            );
        }
    }

    // JWT hygiene in cookies and body.
    if let Some(token) =
        find_jwt(&body).or_else(|| response.headers_named("set-cookie").find_map(find_jwt))
    {
        if let Ok(jwt) = crate::decoder::decode_jwt(&token) {
            if jwt.algorithm() == Some("none") {
                issues.push(
                    base(
                        "jwt-none",
                        "Unsigned JWT (alg=none) is used",
                        Severity::High,
                    )
                    .confidence(Confidence::Firm)
                    .evidence(redact(&token))
                    .detail("The token is not signed and can be forged by an attacker.")
                    .remediation("Reject alg=none and verify signatures server-side.")
                    .cwe(347)
                    .build(),
                );
            } else if jwt.payload.get("exp").is_none() {
                issues.push(
                    base("jwt-no-expiry", "JWT has no expiry claim", Severity::Low)
                        .confidence(Confidence::Firm)
                        .evidence(redact(&token))
                        .detail("Tokens without exp remain valid indefinitely if stolen.")
                        .remediation("Include a short exp claim and support revocation.")
                        .cwe(613)
                        .build(),
                );
            }
        }
    }

    issues
}

fn snippet_around(body: &str, needle: &str, max: usize) -> String {
    let lower = body.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let pos = lower.find(&needle_lower).unwrap_or(0);
    let start = pos.saturating_sub(max / 2);
    let end = (pos + needle.len() + max / 2).min(body.len());
    let mut start = start;
    while start < body.len() && !body.is_char_boundary(start) {
        start += 1;
    }
    let mut end = end;
    while end > start && !body.is_char_boundary(end) {
        end -= 1;
    }
    body[start..end].replace(['\r', '\n'], " ")
}

fn truncate_cookie(cookie: &str) -> String {
    if cookie.len() > 200 {
        format!("{}...", &cookie[..200])
    } else {
        cookie.to_string()
    }
}

fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 12 {
        return "***".into();
    }
    format!(
        "{}...{}",
        chars[..6].iter().collect::<String>(),
        chars[chars.len() - 4..].iter().collect::<String>()
    )
}

fn regex_version() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d+\.\d+").unwrap())
}

fn error_signature(body: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"(?i)(stack trace|traceback \(most recent call last\)|at [\w.$]+\([\w.]+:\d+\)|SQLSTATE\[|ORA-\d{5}|mysql_fetch|Microsoft OLE DB|syntax error at or near|Warning: include\(|Fatal error:|java\.lang\.\w+Exception)"
        ).unwrap()
    });
    re.find(body).map(|m| {
        let start = body[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let end = body[m.end()..]
            .find('\n')
            .map(|i| m.end() + i)
            .unwrap_or(body.len());
        body[start..end.min(start + 300)].trim().to_string()
    })
}

fn secret_patterns() -> Vec<(&'static str, Regex, Severity, u32)> {
    vec![
        (
            "AWS access key",
            Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
            Severity::High,
            798,
        ),
        (
            "private key",
            Regex::new(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
            Severity::High,
            321,
        ),
        (
            "GitHub token",
            Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36}\b").unwrap(),
            Severity::High,
            798,
        ),
        (
            "Google API key",
            Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(),
            Severity::Medium,
            798,
        ),
        (
            "Slack token",
            Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b").unwrap(),
            Severity::High,
            798,
        ),
        (
            "JSON Web Token",
            Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*").unwrap(),
            Severity::Low,
            522,
        ),
    ]
}

fn find_jwt(text: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*").unwrap()
    });
    re.find(text).map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(url: &str) -> Request {
        let parsed = url::Url::parse(url).unwrap();
        Request::from_url("GET", &parsed, Vec::new(), None)
    }

    fn response(headers: &str, body: &str) -> Response {
        Response::parse(format!("HTTP/1.1 200 OK\r\n{headers}\r\n{body}").as_bytes()).unwrap()
    }

    #[test]
    fn missing_headers_and_cookie_flags() {
        let req = request("https://example.com/");
        let res = response(
            "Content-Type: text/html\r\nSet-Cookie: sid=1; Path=/\r\nServer: nginx/1.2.3\r\n",
            "<html><title>x</title><input type=password></html>",
        );
        let issues = scan(&req, &res, false);
        let checks: Vec<&str> = issues.iter().map(|i| i.check.as_str()).collect();
        assert!(checks.contains(&"missing-sts"));
        assert!(checks.contains(&"missing-csp"));
        assert!(checks.contains(&"missing-nosniff"));
        assert!(checks.contains(&"missing-frame-protection"));
        assert!(checks.contains(&"cookie-flags"));
        assert!(checks.contains(&"server-banner"));
        assert!(checks.contains(&"password-autocomplete"));
    }

    #[test]
    fn detects_secret_and_directory_listing() {
        let req = request("http://example.com/");
        let body = "<title>Index of /</title> AKIAIOSFODNN7EXAMPLE";
        let res = response("Content-Type: text/html\r\n", body);
        let issues = scan(&req, &res, false);
        assert!(issues.iter().any(|i| i.check == "directory-listing"));
        assert!(issues
            .iter()
            .any(|i| i.check == "secret-exposure" && i.severity == Severity::High));
    }

    #[test]
    fn detects_mixed_content_and_jwt() {
        let req = request("https://example.com/");
        let body = r#"<script src="http://cdn.example/x.js"></script>
        <script>var t="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop";</script>"#;
        let res = response(
            "Content-Type: text/html\r\nContent-Security-Policy: default-src 'self'\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nStrict-Transport-Security: max-age=1\r\nReferrer-Policy: no-referrer\r\n",
            body,
        );
        let issues = scan(&req, &res, false);
        assert!(issues.iter().any(|i| i.check == "mixed-content"));
        assert!(issues.iter().any(|i| i.check == "secret-exposure"));
        assert!(issues.iter().any(|i| i.check == "jwt-no-expiry"));
    }

    #[test]
    fn clean_response_has_few_issues() {
        let req = request("https://example.com/");
        let res = response(
            "Content-Type: text/html\r\nContent-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nStrict-Transport-Security: max-age=31536000\r\nReferrer-Policy: no-referrer\r\nSet-Cookie: sid=1; Secure; HttpOnly; SameSite=Lax\r\nCache-Control: no-store\r\n",
            "<html><title>ok</title></html>",
        );
        let issues = scan(&req, &res, false);
        assert!(issues.iter().all(|i| i.check != "missing-sts"));
        assert!(issues.iter().all(|i| i.check != "cookie-flags"));
    }
}
