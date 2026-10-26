//! Integration tests for the scanner, passive checks and crawler.

mod common;

use burpcli::http::{ClientOptions, Request};
use burpcli::scanner::{self, crawl, ScanOptions, Target};
use burpcli::scope::Scope;
use common::{html, query_param, reflect_q, TestServer};
use std::time::Duration;

fn scan_options(url: String, checks: &[&str]) -> ScanOptions {
    ScanOptions {
        target: Target::Url(url),
        checks: checks.iter().map(|check| check.to_string()).collect(),
        concurrency: 2,
        timeout_ms: 5_000,
        save_evidence: true,
        point_kinds: vec![scanner::PointKind::Query],
        quiet: true,
        ..ScanOptions::default()
    }
}

#[test]
fn detects_reflected_xss() {
    let server = TestServer::start(reflect_q);
    let test_project = common::TestProject::new();
    let options = scan_options(server.url("/search?q=hello"), &["xss"]);
    let result = scanner::scan(&test_project.project, &options).unwrap();

    let issue = result
        .issues
        .iter()
        .find(|issue| issue.check == "xss")
        .expect("xss issue");
    assert_eq!(issue.severity.label(), "High");
    assert!(issue.parameter.as_deref().unwrap().contains("query:q"));
    assert!(issue.payload.as_deref().unwrap().contains("svg/onload"));
    assert!(issue.request.is_some());
    assert!(issue.response.is_some());
    assert_eq!(result.scanned_urls, 1);

    // The seed is recorded in the sitemap.
    let sitemap = test_project.project.sitemap().unwrap();
    assert!(sitemap
        .list()
        .iter()
        .any(|entry| entry.url.contains("/search")));

    // Issues are persisted and de-duplicated.
    let store = test_project.project.issue_store().unwrap();
    assert_eq!(store.count().unwrap(), result.issues.len());
    let saved = store.list().unwrap();
    assert!(saved.iter().any(|issue| issue.check == "xss"));
}

#[test]
fn detects_error_based_sql_injection() {
    let server = TestServer::start(|request| {
        let value = query_param(request, "id").unwrap_or_default();
        if value.contains('\'') || value.contains('"') {
            html("<html><title>error</title>You have an error in your SQL syntax near the input</html>")
        } else {
            html("<html><title>item</title>item 1</html>")
        }
    });
    let test_project = common::TestProject::new();
    let options = scan_options(server.url("/item?id=1"), &["sqli"]);
    let result = scanner::scan(&test_project.project, &options).unwrap();
    assert!(
        result.issues.iter().any(|issue| issue.check == "sqli"),
        "issues: {:?}",
        result.issues.iter().map(|i| &i.check).collect::<Vec<_>>()
    );
}

#[test]
fn passive_checks_run_on_a_single_exchange() {
    let request = Request::parse(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
    let mut response = burpcli::http::Response::new(200, "OK");
    response.set_header("Content-Type", "text/html");
    response.body = b"<html><title>test</title><input type=password></html>".to_vec();
    let issues = scanner::scan_passive(&request, &response, false);
    let checks: Vec<&str> = issues.iter().map(|issue| issue.check.as_str()).collect();
    assert!(checks.contains(&"missing-csp"), "{checks:?}");
    assert!(checks.contains(&"password-autocomplete"), "{checks:?}");
}

#[test]
fn crawler_follows_links_and_respects_depth() {
    let server = TestServer::start(|request| match request.target.as_str() {
        "/" => html("<html><title>home</title><a href=\"/a\">a</a><a href=\"/b\">b</a></html>"),
        "/a" => html("<html><title>a</title><a href=\"/deep\">deep</a></html>"),
        "/b" => html("<html><title>b</title>leaf</html>"),
        "/deep" => html("<html><title>deep</title>deep</html>"),
        _ => common::response(404, "Not Found", "text/plain", "missing"),
    });
    let test_project = common::TestProject::new();
    let seed = url::Url::parse(&server.url("/")).unwrap();
    let scope = Scope::new(&[format!("{}/*", server.url(""))], &[]).unwrap();
    let session = burpcli::session::SessionState::default();
    let options = crawl::CrawlOptions {
        client: &ClientOptions {
            timeout: Duration::from_secs(5),
            ..ClientOptions::default()
        },
        scope: &scope,
        config: &test_project.project.config,
        session: &session,
        max_pages: 10,
        max_depth: 1,
        delay: Duration::from_millis(0),
        same_host_only: true,
    };
    let result = crawl::crawl(&seed, &options);
    let urls: Vec<&str> = result.pages.iter().map(|page| page.url.as_str()).collect();
    assert!(urls.iter().any(|url| url.ends_with("/a")), "{urls:?}");
    assert!(urls.iter().any(|url| url.ends_with("/b")), "{urls:?}");
    assert!(
        !urls.iter().any(|url| url.ends_with("/deep")),
        "depth limit ignored: {urls:?}"
    );
    assert!(result.errors.is_empty(), "{:?}", result.errors);

    // A deeper crawl reaches /deep and updates the sitemap through scan().
    let options = ScanOptions {
        crawl_depth: 2,
        max_urls: 20,
        passive_only: true,
        ..scan_options(server.url("/"), &[])
    };
    let result = scanner::scan(&test_project.project, &options).unwrap();
    assert!(result.scanned_urls >= 3, "scanned {}", result.scanned_urls);
    let sitemap = test_project.project.sitemap().unwrap();
    assert!(sitemap.len() >= 3);
}

#[test]
fn scan_scope_restriction_is_enforced() {
    let server = TestServer::start(|_| html("ok"));
    let mut test_project = common::TestProject::new();
    test_project.project.config.scope.include = vec!["http://example.com/*".into()];
    test_project.project.save_config().unwrap();
    let options = scan_options(server.url("/"), &["xss"]);
    let error = match scanner::scan(&test_project.project, &options) {
        Ok(_) => panic!("scan should have been rejected by the scope"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("scope"), "{error:#}");
}
