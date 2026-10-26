//! Minimal RFC 6265 cookie jar used by repeater, macros and the scanner.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub secure: bool,
    #[serde(default)]
    pub http_only: bool,
    #[serde(default)]
    pub same_site: Option<String>,
    #[serde(default)]
    pub expires: Option<String>,
}

fn default_path() -> String {
    "/".to_string()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CookieJar {
    #[serde(default)]
    pub cookies: Vec<Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_from_response(&mut self, url: &Url, set_cookie: &[String]) {
        let host = url.host_str().unwrap_or("").to_string();
        let now = crate::util::now_rfc3339();
        for line in set_cookie {
            if let Some(cookie) = parse_set_cookie(line, &host, &now) {
                // Remove expired cookies and previous versions of this cookie.
                let expired = cookie.expires.as_deref().map(is_expired).unwrap_or(false);
                self.cookies.retain(|c| {
                    !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path)
                });
                if !expired {
                    self.cookies.push(cookie);
                }
            }
        }
    }

    pub fn header_for(&self, url: &Url) -> Option<String> {
        let host = url.host_str()?.to_ascii_lowercase();
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        let secure = url.scheme() == "https";
        let mut parts = Vec::new();
        for cookie in &self.cookies {
            if cookie.secure && !secure {
                continue;
            }
            if !domain_matches(&host, &cookie.domain) {
                continue;
            }
            if !path_matches(path, &cookie.path) {
                continue;
            }
            if cookie.expires.as_deref().map(is_expired).unwrap_or(false) {
                continue;
            }
            parts.push(format!("{}={}", cookie.name, cookie.value));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("; "))
        }
    }

    pub fn add(&mut self, name: &str, value: &str, domain: &str, secure: bool) {
        self.cookies
            .retain(|c| !(c.name == name && c.domain == domain));
        self.cookies.push(Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: domain.to_ascii_lowercase(),
            path: "/".into(),
            secure,
            http_only: false,
            same_site: None,
            expires: None,
        });
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read cookie jar '{}'", path.display()))?;
        if data.trim().is_empty() {
            return Ok(Self::new());
        }
        serde_json::from_str(&data)
            .with_context(|| format!("cannot parse cookie jar '{}'", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)
            .with_context(|| format!("cannot write cookie jar '{}'", path.display()))
    }
}

pub fn parse_set_cookie(line: &str, default_domain: &str, now: &str) -> Option<Cookie> {
    let mut parts = line.split(';');
    let pair = parts.next()?.trim();
    let (name, value) = pair.split_once('=')?;
    if name.trim().is_empty() {
        return None;
    }
    let mut cookie = Cookie {
        name: name.trim().to_string(),
        value: value.trim().to_string(),
        domain: default_domain.to_ascii_lowercase(),
        path: "/".into(),
        secure: false,
        http_only: false,
        same_site: None,
        expires: None,
    };
    let _ = now;
    for attr in parts {
        let attr = attr.trim();
        let (key, val) = match attr.split_once('=') {
            Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
            None => (attr.to_ascii_lowercase(), ""),
        };
        match key.as_str() {
            "domain" => cookie.domain = val.trim_start_matches('.').to_ascii_lowercase(),
            "path" => {
                cookie.path = if val.is_empty() {
                    "/".into()
                } else {
                    val.to_string()
                }
            }
            "secure" => cookie.secure = true,
            "httponly" => cookie.http_only = true,
            "samesite" => cookie.same_site = Some(val.to_string()),
            "expires" => cookie.expires = Some(val.to_string()),
            "max-age" => {
                if let Ok(seconds) = val.parse::<i64>() {
                    if seconds <= 0 {
                        cookie.expires = Some("1970-01-01T00:00:00Z".into());
                    }
                }
            }
            _ => {}
        }
    }
    Some(cookie)
}

fn is_expired(value: &str) -> bool {
    // We do not depend on a full HTTP-date parser. Max-Age=0 is converted to
    // the epoch; any date in the past by year comparison is treated as expired.
    if value.starts_with("1970") {
        return true;
    }
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc2822(value) {
        return parsed.with_timezone(&chrono::Utc) < chrono::Utc::now();
    }
    false
}

fn domain_matches(host: &str, domain: &str) -> bool {
    let domain = domain.trim_start_matches('.').to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn path_matches(path: &str, cookie_path: &str) -> bool {
    if cookie_path == "/" || cookie_path.is_empty() {
        return true;
    }
    path == cookie_path || path.starts_with(&format!("{cookie_path}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_and_sends_cookies() {
        let mut jar = CookieJar::new();
        let url = Url::parse("https://example.com/app/login").unwrap();
        jar.update_from_response(
            &url,
            &[
                "session=abc; Path=/; HttpOnly; Secure; SameSite=Lax".into(),
                "other=1; Domain=example.com".into(),
            ],
        );
        let header = jar.header_for(&Url::parse("https://example.com/app/x").unwrap());
        assert_eq!(header.unwrap(), "session=abc; other=1");
        let insecure = jar.header_for(&Url::parse("http://example.com/app/x").unwrap());
        assert_eq!(insecure.unwrap(), "other=1");
    }

    #[test]
    fn max_age_zero_deletes() {
        let mut jar = CookieJar::new();
        let url = Url::parse("http://localhost/").unwrap();
        jar.update_from_response(&url, &["a=1; Path=/".into()]);
        jar.update_from_response(&url, &["a=; Max-Age=0; Path=/".into()]);
        assert!(jar.header_for(&url).is_none());
    }
}
