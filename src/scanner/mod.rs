//! Scanning engine: passive + active checks, crawling and issue persistence.

pub mod active;
pub mod crawl;
pub mod issue;
pub mod passive;

use crate::http::TlsOptions;
use crate::http::{client, ClientOptions, Request, Response};
use crate::oob::OobProvider;
use crate::scope::Scope;
use crate::session::{self, SessionState};
use crate::storage::Project;
use crate::util::format_duration;
use anyhow::{anyhow, bail, Context, Result};
use crawl::CrawlOptions;
pub use issue::{Confidence, Issue, IssueStore, Severity};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use url::Url;

pub use active::{
    check_description, insertion_points, run_point_checks, run_request_checks, CheckContext,
    InsertionPoint, PointKind, ALL_CHECKS, POINT_CHECKS, REQUEST_CHECKS,
};
pub use passive::scan as scan_passive;

/// Simple global rate limiter shared by all worker threads.
pub struct RateLimiter {
    interval: Duration,
    next: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(delay_ms: u64) -> Self {
        Self {
            interval: Duration::from_millis(delay_ms),
            next: Mutex::new(Instant::now()),
        }
    }

    pub fn wait(&self) {
        if self.interval.is_zero() {
            return;
        }
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if *next > now {
            std::thread::sleep(*next - now);
        }
        *next = Instant::now() + self.interval;
    }
}

#[derive(Clone)]
pub enum Target {
    Url(String),
    Request(Box<Request>),
}

pub struct ScanOptions {
    pub target: Target,
    pub checks: Vec<String>,
    pub skip_checks: Vec<String>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub delay_ms: u64,
    pub timing: bool,
    pub follow_redirects: usize,
    pub insecure: bool,
    pub crawl_depth: usize,
    pub max_urls: usize,
    pub passive_only: bool,
    pub save_evidence: bool,
    pub user_agent: Option<String>,
    pub extra_scope: Vec<String>,
    pub oob: Option<Arc<dyn OobProvider>>,
    pub quiet: bool,
    pub point_kinds: Vec<PointKind>,
    pub scheme: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            target: Target::Url("http://127.0.0.1/".into()),
            checks: Vec::new(),
            skip_checks: Vec::new(),
            concurrency: 10,
            timeout_ms: 15_000,
            delay_ms: 0,
            timing: false,
            follow_redirects: 0,
            insecure: false,
            crawl_depth: 0,
            max_urls: 100,
            passive_only: false,
            save_evidence: false,
            user_agent: None,
            extra_scope: Vec::new(),
            oob: None,
            quiet: true,
            point_kinds: Vec::new(),
            scheme: None,
        }
    }
}

pub struct ScanResult {
    pub issues: Vec<Issue>,
    pub scanned_urls: usize,
    pub requests: usize,
    pub errors: Vec<String>,
    pub duration: Duration,
}

struct Page {
    request: Request,
    response: Response,
    duration: Duration,
}

enum Job {
    Point {
        request: Request,
        point: InsertionPoint,
        baseline: Arc<Response>,
        baseline_duration: Duration,
    },
    RequestLevel {
        request: Request,
        baseline: Arc<Response>,
        baseline_duration: Duration,
    },
}

pub fn scan(project: &Project, options: &ScanOptions) -> Result<ScanResult> {
    let started = Instant::now();
    let mut errors: Vec<String> = Vec::new();

    let mut seed = match &options.target {
        Target::Url(url) => {
            let parsed = Url::parse(url).with_context(|| format!("invalid target URL '{url}'"))?;
            let mut request = Request::from_url("GET", &parsed, Vec::new(), None);
            request.scheme = Some(parsed.scheme().to_string());
            request
        }
        Target::Request(request) => {
            let mut request = (**request).clone();
            if request.scheme.is_none() {
                request.scheme = Some(options.scheme.clone().unwrap_or_else(|| {
                    let port = request
                        .header("Host")
                        .and_then(|h| crate::http::message::parse_host_header(h).1);
                    if port == Some(443) {
                        "https".into()
                    } else {
                        "http".into()
                    }
                }));
            }
            request
        }
    };
    if options.scheme.is_some() {
        seed.scheme = options.scheme.clone();
    }

    let seed_url = seed.url().context("cannot resolve target URL")?;
    let host = seed_url.host_str().unwrap_or("").to_string();
    let mut include = project.config.scope.include.clone();
    include.extend(options.extra_scope.iter().cloned());
    if include.is_empty() {
        let port = seed_url.port().map(|p| format!(":{p}")).unwrap_or_default();
        include.push(format!("{}://{}{}/*", seed_url.scheme(), host, port));
    }
    let mut scope = Scope::new(&include, &project.config.scope.exclude)?;
    scope.compile()?;
    if !scope.allows(&seed_url) {
        bail!(
            "target '{}' is outside the project scope; add it with `burpcli scope add {}://{}/*`",
            seed_url,
            seed_url.scheme(),
            host
        );
    }

    let mut session_state = SessionState::from_project(project)?;
    let jar = Arc::new(Mutex::new(session_state.cookies.clone()));
    let mut client_options = ClientOptions {
        timeout: Duration::from_millis(options.timeout_ms),
        follow_redirects: options.follow_redirects,
        tls: TlsOptions {
            insecure: options.insecure,
            ..Default::default()
        },
        max_body: project.config.scan.max_body,
        cookie_jar: Some(jar.clone()),
        user_agent: options
            .user_agent
            .clone()
            .or_else(|| project.config.scan.user_agent.clone()),
        ..ClientOptions::default()
    };
    client_options.connect_timeout = client_options.timeout.min(Duration::from_secs(10));
    session::apply_session(&mut seed, &project.config, &session_state)?;

    let started_request = Instant::now();
    let seed_response = client::send(&seed, &client_options)
        .with_context(|| format!("baseline request to {seed_url} failed"))?;
    let seed_duration = started_request.elapsed();
    session_state.cookies = jar.lock().unwrap_or_else(|e| e.into_inner()).clone();

    let mut pages: Vec<Page> = vec![Page {
        request: seed.clone(),
        response: seed_response.response.clone(),
        duration: seed_duration,
    }];
    let mut seen_pages: HashSet<String> = HashSet::new();
    seen_pages.insert(canonical_url(&seed_url));

    let mut sitemap = project
        .sitemap()
        .unwrap_or_else(|_| crate::sitemap::Sitemap::load(project.sitemap_path()).unwrap());
    record_sitemap(&mut sitemap, &seed, &seed_response.response, "scan");

    if options.crawl_depth > 0 && options.max_urls > 0 {
        let crawl_options = CrawlOptions {
            client: &client_options,
            scope: &scope,
            config: &project.config,
            session: &session_state,
            max_pages: options.max_urls,
            max_depth: options.crawl_depth,
            delay: Duration::from_millis(options.delay_ms),
            same_host_only: true,
        };
        let crawled = crawl::crawl(&seed_url, &crawl_options);
        errors.extend(crawled.errors);
        for page in crawled.pages {
            let key = match Url::parse(&page.url) {
                Ok(url) => canonical_url(&url),
                Err(_) => page.url.clone(),
            };
            if !seen_pages.insert(key) {
                continue;
            }
            record_sitemap(&mut sitemap, &page.request, &page.response, "spider");
            pages.push(Page {
                request: page.request,
                response: page.response,
                duration: Duration::from_millis(0),
            });
        }
    }
    if let Err(error) = sitemap.save() {
        errors.push(format!("cannot save sitemap: {error}"));
    }

    let mut all_issues: Vec<Issue> = Vec::new();
    let mut passive_keys: HashSet<String> = HashSet::new();
    for page in &pages {
        for issue in passive::scan(&page.request, &page.response, options.save_evidence) {
            if passive_keys.insert(issue.dedupe_key()) {
                all_issues.push(issue);
            }
        }
    }

    if let Some(plugins) = crate::plugins::PluginManager::optional_from_project(project)? {
        let effects = plugins.scan_pages(pages.iter().map(|page| (&page.request, &page.response)));
        errors.extend(effects.errors);
        for issue in effects.issues {
            if passive_keys.insert(issue.dedupe_key()) {
                all_issues.push(issue);
            }
        }
    }

    let timing = options.timing || project.config.scan.timing_checks;
    let mut selected: Vec<String> = if !options.checks.is_empty() {
        options.checks.clone()
    } else if !project.config.scan.checks.is_empty() {
        project.config.scan.checks.clone()
    } else {
        ALL_CHECKS.iter().map(|s| s.to_string()).collect()
    };
    let mut skip: HashSet<String> = options.skip_checks.iter().cloned().collect();
    skip.extend(project.config.scan.skip_checks.iter().cloned());
    selected.retain(|name| !skip.contains(name) && ALL_CHECKS.contains(&name.as_str()));
    selected.dedup();
    if options.passive_only {
        selected.clear();
    }
    let point_checks: Vec<String> = selected
        .iter()
        .filter(|name| POINT_CHECKS.contains(&name.as_str()))
        .cloned()
        .collect();
    let request_checks: Vec<String> = selected
        .iter()
        .filter(|name| REQUEST_CHECKS.contains(&name.as_str()))
        .cloned()
        .collect();

    let mut jobs: VecDeque<Job> = VecDeque::new();
    for page in &pages {
        if !is_scannable(page) {
            continue;
        }
        let baseline = Arc::new(page.response.clone());
        if !request_checks.is_empty() {
            jobs.push_back(Job::RequestLevel {
                request: page.request.clone(),
                baseline: baseline.clone(),
                baseline_duration: page.duration,
            });
        }
        if !point_checks.is_empty() {
            let mut points = insertion_points(&page.request);
            if !options.point_kinds.is_empty() {
                points.retain(|p| options.point_kinds.contains(&p.kind));
            }
            for point in points {
                jobs.push_back(Job::Point {
                    request: page.request.clone(),
                    point,
                    baseline: baseline.clone(),
                    baseline_duration: page.duration,
                });
            }
        }
    }

    let total_jobs = jobs.len();
    let queue = Arc::new(Mutex::new(jobs));
    let limiter = Arc::new(RateLimiter::new(options.delay_ms));
    let request_count = AtomicUsize::new(0);
    let workers = options.concurrency.clamp(1, 64).min(total_jobs.max(1));
    let (sender, receiver) = std::sync::mpsc::channel::<active::CheckOutcome>();
    let completed = AtomicUsize::new(0);

    if total_jobs > 0 {
        std::thread::scope(|scope_threads| {
            for _ in 0..workers {
                let queue = queue.clone();
                let sender = sender.clone();
                let limiter = limiter.clone();
                let client_options = &client_options;
                let point_checks = &point_checks;
                let request_checks = &request_checks;
                let request_count = &request_count;
                let completed = &completed;
                let quiet = options.quiet;
                let oob = options.oob.as_deref();
                let save_evidence = options.save_evidence;
                scope_threads.spawn(move || loop {
                    let job = {
                        let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
                        queue.pop_front()
                    };
                    let Some(job) = job else { break };
                    let context = CheckContext {
                        client: client_options,
                        limiter: &limiter,
                        baseline_duration: Duration::from_millis(0),
                        timing,
                        oob,
                        save_evidence,
                        request_count,
                    };
                    let outcome = match job {
                        Job::Point {
                            request,
                            point,
                            baseline,
                            baseline_duration,
                        } => {
                            let context = CheckContext {
                                baseline_duration,
                                ..context
                            };
                            run_point_checks(point_checks, &request, &point, &baseline, &context)
                        }
                        Job::RequestLevel {
                            request,
                            baseline,
                            baseline_duration,
                        } => {
                            let context = CheckContext {
                                baseline_duration,
                                ..context
                            };
                            run_request_checks(request_checks, &request, &baseline, &context)
                        }
                    };
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    if !quiet {
                        eprint!("\r[*] active checks: {done}/{total_jobs}");
                        use std::io::Write;
                        std::io::stderr().flush().ok();
                    }
                    sender.send(outcome).ok();
                });
            }
            drop(sender);
            while let Ok(outcome) = receiver.recv() {
                all_issues.extend(outcome.issues);
                errors.extend(outcome.errors);
            }
        });
        if !options.quiet {
            eprintln!();
        }
    }

    let store = IssueStore::open(project.issues_path())?;
    let mut seen_issues: HashSet<String> = HashSet::new();
    let mut unique_issues = Vec::new();
    for issue in all_issues {
        if seen_issues.insert(issue.dedupe_key()) {
            if let Err(error) = store.append(&issue) {
                errors.push(format!("cannot save issue: {error}"));
            }
            unique_issues.push(issue);
        }
    }
    unique_issues.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.url.cmp(&b.url))
    });

    session_state.cookies = jar.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Err(error) = session_state.save_to_project(project) {
        errors.push(format!("cannot save session: {error}"));
    }

    let baseline_requests = pages.len();
    Ok(ScanResult {
        issues: unique_issues,
        scanned_urls: pages.len(),
        requests: request_count.load(Ordering::Relaxed) + baseline_requests,
        errors,
        duration: started.elapsed(),
    })
}

fn is_scannable(page: &Page) -> bool {
    if page.response.status >= 500 {
        return false;
    }
    let mime = page
        .response
        .content_type()
        .unwrap_or("")
        .to_ascii_lowercase();
    page.response.is_html()
        || mime.contains("json")
        || mime.contains("xml")
        || page.request.target.contains('?')
        || !page.request.body.is_empty()
}

fn canonical_url(url: &Url) -> String {
    let mut url = url.clone();
    url.set_fragment(None);
    url.to_string()
}

fn record_sitemap(
    sitemap: &mut crate::sitemap::Sitemap,
    request: &Request,
    response: &Response,
    source: &str,
) {
    if let Ok(url) = request.url() {
        sitemap.add_response(
            url.as_str(),
            &request.method,
            response.status,
            response.content_type().unwrap_or(""),
            &response.body,
            source,
        );
    }
}

/// Format a scan summary for the console.
pub fn summary(result: &ScanResult) -> String {
    let high = result
        .issues
        .iter()
        .filter(|i| i.severity == Severity::High)
        .count();
    let medium = result
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Medium)
        .count();
    let low = result
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Low)
        .count();
    let info = result
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Info)
        .count();
    format!(
        "{} URLs, {} requests, {} findings ({} high, {} medium, {} low, {} info) in {}",
        result.scanned_urls,
        result.requests,
        result.issues.len(),
        high,
        medium,
        low,
        info,
        format_duration(result.duration)
    )
}

/// Build a default `ClientOptions` for one-off requests (repeater/intruder).
pub fn client_options(project: &Project, insecure: bool, timeout_ms: u64) -> ClientOptions {
    ClientOptions {
        timeout: Duration::from_millis(timeout_ms),
        tls: TlsOptions {
            insecure,
            ..Default::default()
        },
        max_body: project.config.scan.max_body,
        ..ClientOptions::default()
    }
}

/// Insertion point kinds for CLI parsing.
pub fn parse_point_kind(value: &str) -> Result<PointKind> {
    PointKind::parse(value).ok_or_else(|| {
        anyhow!(
            "unknown insertion point kind '{value}' (use query, form, json, cookie, header, path)"
        )
    })
}

/// Load and prepare a request file for scanning.
pub fn request_from_file(path: &std::path::Path) -> Result<Request> {
    let raw =
        std::fs::read(path).with_context(|| format!("cannot read request '{}'", path.display()))?;
    Request::parse(&raw)
}

pub fn confidence_label(confidence: Confidence) -> &'static str {
    confidence.label()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_works() {
        let limiter = RateLimiter::new(20);
        let started = Instant::now();
        limiter.wait();
        limiter.wait();
        limiter.wait();
        assert!(started.elapsed() >= Duration::from_millis(35));
    }

    #[test]
    fn scannable_heuristics() {
        let request =
            Request::from_url("GET", &Url::parse("http://x/a").unwrap(), Vec::new(), None);
        let response =
            Response::parse(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nx").unwrap();
        assert!(is_scannable(&Page {
            request,
            response,
            duration: Duration::ZERO
        }));
    }
}
