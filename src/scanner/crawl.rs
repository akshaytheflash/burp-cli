//! Breadth-first crawler used by `spider` and by scanning with `--crawl-depth`.

use crate::config::ProjectConfig;
use crate::http::{client, ClientOptions, Request, Response};
use crate::scope::Scope;
use crate::session::SessionState;
use std::collections::{HashSet, VecDeque};
use std::time::Duration;
use url::Url;

#[derive(Clone)]
pub struct CrawlOptions<'a> {
    pub client: &'a ClientOptions,
    pub scope: &'a Scope,
    pub config: &'a ProjectConfig,
    pub session: &'a SessionState,
    pub max_pages: usize,
    pub max_depth: usize,
    pub delay: Duration,
    pub same_host_only: bool,
}

#[derive(Clone)]
pub struct CrawlPage {
    pub url: String,
    pub depth: usize,
    pub request: Request,
    pub response: Response,
}

pub struct CrawlResult {
    pub pages: Vec<CrawlPage>,
    pub errors: Vec<String>,
}

pub fn crawl(seed: &Url, options: &CrawlOptions) -> CrawlResult {
    let mut result = CrawlResult {
        pages: Vec::new(),
        errors: Vec::new(),
    };
    let seed_host = seed.host_str().unwrap_or("").to_string();
    let mut queue: VecDeque<(Url, usize)> = VecDeque::new();
    queue.push_back((seed.clone(), 0));
    let mut visited: HashSet<String> = HashSet::new();
    let mut errors = 0usize;

    while let Some((url, depth)) = queue.pop_front() {
        if result.pages.len() >= options.max_pages {
            break;
        }
        let key = canonical(&url);
        if !visited.insert(key) {
            continue;
        }
        if !options.scope.allows(&url) {
            continue;
        }
        if options.same_host_only && url.host_str().unwrap_or("") != seed_host {
            continue;
        }

        let mut request = Request::from_url("GET", &url, Vec::new(), None);
        if let Err(error) =
            crate::session::apply_session(&mut request, options.config, options.session)
        {
            result
                .errors
                .push(format!("session error for {url}: {error}"));
            continue;
        }
        match client::send(&request, options.client) {
            Ok(response) => {
                let page = CrawlPage {
                    url: url.to_string(),
                    depth,
                    request: request.clone(),
                    response: response.response.clone(),
                };
                let is_html = response.response.is_html();
                let body = response.response.body_text();
                result.pages.push(page);
                if depth < options.max_depth && is_html {
                    for link in extract_links(&url, &body) {
                        if !visited.contains(&canonical(&link)) {
                            queue.push_back((link, depth + 1));
                        }
                    }
                }
            }
            Err(error) => {
                errors += 1;
                if errors <= 20 {
                    result.errors.push(format!("{url}: {error}"));
                }
            }
        }
        if !options.delay.is_zero() {
            std::thread::sleep(options.delay);
        }
    }
    result
}

pub fn extract_links(base: &Url, html: &str) -> Vec<Url> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let regex = RE.get_or_init(|| {
        regex::Regex::new(r#"(?is)(?:href|src|action)\s*=\s*["']([^"']+)["']"#).unwrap()
    });
    let mut links = Vec::new();
    let mut seen = HashSet::new();
    for capture in regex.captures_iter(html) {
        let raw = html_unescape(capture.get(1).map(|m| m.as_str()).unwrap_or("").trim());
        let lower = raw.to_ascii_lowercase();
        if raw.is_empty()
            || raw.starts_with('#')
            || lower.starts_with("mailto:")
            || lower.starts_with("javascript:")
            || lower.starts_with("tel:")
            || lower.starts_with("data:")
        {
            continue;
        }
        if let Ok(mut url) = base.join(&raw) {
            url.set_fragment(None);
            if url.scheme() != "http" && url.scheme() != "https" {
                continue;
            }
            let key = canonical(&url);
            if seen.insert(key) {
                links.push(url);
            }
        }
    }
    links
}

fn canonical(url: &Url) -> String {
    let mut url = url.clone();
    url.set_fragment(None);
    let mut text = url.to_string();
    if text.ends_with("/") && url.path() == "/" {
        text.pop();
    }
    text
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_resolves_links() {
        let base = Url::parse("https://example.com/dir/page").unwrap();
        let html = r#"
            <a href="/absolute">a</a>
            <a href="relative?x=1">b</a>
            <form action="/submit"><input></form>
            <script src="https://cdn.example.com/app.js"></script>
            <a href="mailto:x@example.com">mail</a>
            <a href="javascript:void(0)">js</a>
            <img src="/img.png#frag">
        "#;
        let links = extract_links(&base, html);
        let strings: Vec<String> = links.iter().map(|u| u.to_string()).collect();
        assert!(strings.contains(&"https://example.com/absolute".to_string()));
        assert!(strings.contains(&"https://example.com/dir/relative?x=1".to_string()));
        assert!(strings.contains(&"https://example.com/submit".to_string()));
        assert!(strings.contains(&"https://cdn.example.com/app.js".to_string()));
        assert!(strings.contains(&"https://example.com/img.png".to_string()));
        assert_eq!(links.len(), 5);
    }
}
