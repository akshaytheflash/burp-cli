//! Scanning, crawling, sitemap and report commands.

use super::Context;
use crate::http::client;
use crate::oob::{OobProvider, OobServer, RemoteOob};
use crate::report::{self, ReportFormat, ReportOptions};
use crate::scanner::{
    self, parse_point_kind, scan_passive, IssueStore, ScanOptions, Severity, Target, ALL_CHECKS,
};
use crate::scope::Scope;
use crate::storage::HistoryFilter;
use crate::util::{self, format_size, truncate};
use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Target URL
    #[arg(conflicts_with = "request")]
    pub target: Option<String>,
    /// Scan a raw request file instead of a URL
    #[arg(long, value_name = "PATH")]
    pub request: Option<PathBuf>,
    /// Active check to run (repeatable; default: all)
    #[arg(long = "check", value_name = "NAME")]
    pub checks: Vec<String>,
    /// Active check to skip (repeatable)
    #[arg(long = "skip", value_name = "NAME")]
    pub skip_checks: Vec<String>,
    /// Limit insertion points (query, form, json, cookie, header, path)
    #[arg(long = "point")]
    pub point_kinds: Vec<String>,
    /// Only run passive checks
    #[arg(long)]
    pub passive: bool,
    /// Enable time-based checks (slower)
    #[arg(long)]
    pub timing: bool,
    #[arg(long, default_value_t = 10)]
    pub concurrency: usize,
    #[arg(long, default_value_t = 15_000)]
    pub timeout: u64,
    #[arg(long, default_value_t = 0)]
    pub delay: u64,
    #[arg(long, default_value_t = 0)]
    pub crawl_depth: usize,
    #[arg(long, default_value_t = 100)]
    pub max_urls: usize,
    #[arg(long, default_value_t = 0)]
    pub follow: usize,
    #[arg(long)]
    pub insecure: bool,
    #[arg(long)]
    pub save_evidence: bool,
    #[arg(long)]
    pub user_agent: Option<String>,
    /// Extra scope pattern (repeatable)
    #[arg(long = "scope", value_name = "PATTERN")]
    pub extra_scope: Vec<String>,
    /// OOB provider: "local" starts a local listener, or pass a remote base URL
    #[arg(long, value_name = "local|URL")]
    pub oob: Option<String>,
    /// Report format (table, json, html, burp-xml, sarif, markdown)
    #[arg(long)]
    pub format: Option<String>,
    /// Write the report to this file (or directory)
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    #[arg(long, default_value = "info")]
    pub min_severity: String,
    #[arg(long)]
    pub title: Option<String>,
    /// Exit with an error when a finding at or above this severity exists
    #[arg(long, value_name = "SEVERITY")]
    pub fail_on: Option<String>,
    /// List available checks and exit
    #[arg(long)]
    pub list_checks: bool,
}

pub fn scan(ctx: &Context, args: ScanArgs) -> Result<()> {
    if args.list_checks {
        println!("{:<14}DESCRIPTION", "CHECK");
        for check in ALL_CHECKS {
            println!("{:<14} {}", check, scanner::check_description(check));
        }
        return Ok(());
    }
    let project = ctx.project(true)?;
    let target = match (&args.target, &args.request) {
        (Some(url), None) => Target::Url(url.clone()),
        (None, Some(path)) => {
            let raw = std::fs::read(path)
                .with_context(|| format!("cannot read request '{}'", path.display()))?;
            Target::Request(Box::new(crate::intruder::template_from_raw(&raw)?))
        }
        (None, None) => bail!("give a target URL or --request <file>"),
        (Some(_), Some(_)) => bail!("use either a target URL or --request, not both"),
    };
    let point_kinds = args
        .point_kinds
        .iter()
        .map(|kind| parse_point_kind(kind))
        .collect::<Result<Vec<_>>>()?;

    let mut oob_servers: Vec<Arc<OobServer>> = Vec::new();
    let oob: Option<Arc<dyn OobProvider>> = match args.oob.as_deref() {
        None | Some("off") | Some("none") => None,
        Some("local") => {
            let server = Arc::new(OobServer::start(
                "127.0.0.1",
                0,
                None,
                Some(crate::oob::events_path(&project)),
            )?);
            println!("OOB listener: {}", server.base_url());
            oob_servers.push(server.clone());
            let provider: Arc<dyn OobProvider> = server;
            Some(provider)
        }
        Some(url) => Some(Arc::new(RemoteOob::new(url))),
    };

    let checks = args
        .checks
        .iter()
        .map(|check| check.to_ascii_lowercase())
        .filter(|check| check != "all")
        .collect();
    let options = ScanOptions {
        target,
        checks,
        skip_checks: args.skip_checks,
        concurrency: args.concurrency,
        timeout_ms: args.timeout,
        delay_ms: args.delay,
        timing: args.timing,
        follow_redirects: args.follow,
        insecure: args.insecure,
        crawl_depth: args.crawl_depth,
        max_urls: args.max_urls,
        passive_only: args.passive,
        save_evidence: args.save_evidence,
        user_agent: args.user_agent,
        extra_scope: args.extra_scope,
        oob,
        quiet: ctx.quiet,
        point_kinds,
        scheme: None,
    };

    if !ctx.quiet {
        eprintln!("[*] scanning...");
    }
    let result = scanner::scan(&project, &options)?;
    println!("{}", scanner::summary(&result));
    for error in result.errors.iter().take(10) {
        eprintln!("[!] {error}");
    }
    if result.errors.len() > 10 {
        eprintln!("[!] ... {} more errors", result.errors.len() - 10);
    }
    let min = parse_severity(&args.min_severity)?;
    if !result.issues.is_empty() {
        println!();
        print!("{}", report::table(&result.issues, min));
    }

    let report_options = ReportOptions {
        title: args
            .title
            .clone()
            .unwrap_or_else(|| format!("{} security report", project.config.name)),
        min_severity: min,
        include_evidence: args.save_evidence,
    };
    if args.format.is_some() || args.output.is_some() {
        let format = match &args.format {
            Some(format) => ReportFormat::parse(format)?,
            None => args
                .output
                .as_deref()
                .map(ReportFormat::from_path)
                .unwrap_or(ReportFormat::Table),
        };
        let content = report::render(
            &result.issues,
            format,
            &report_options,
            &project.config.name,
        )?;
        match &args.output {
            Some(path) => {
                let path = resolve_output(path, format, "scan");
                report::write(&path, &content)?;
                println!("report written to {} ({})", path.display(), format.label());
            }
            None => {
                print!("{content}");
                if !content.ends_with('\n') {
                    println!();
                }
            }
        }
    }

    if !oob_servers.is_empty() && !ctx.quiet {
        eprintln!("[*] OOB listeners stopped");
    }

    if let Some(threshold) = &args.fail_on {
        let threshold = parse_severity(threshold)?;
        let hits = result
            .issues
            .iter()
            .filter(|issue| issue.severity.rank() >= threshold.rank())
            .count();
        if hits > 0 {
            bail!("{hits} finding(s) at or above {}", threshold.label());
        }
    }
    Ok(())
}

#[derive(Debug, Args)]
pub struct SpiderArgs {
    /// Seed URL
    pub seed: String,
    #[arg(long, default_value_t = 100)]
    pub max_pages: usize,
    #[arg(long, default_value_t = 3)]
    pub max_depth: usize,
    #[arg(long, default_value_t = 0)]
    pub delay: u64,
    #[arg(long)]
    pub insecure: bool,
    #[arg(long)]
    pub user_agent: Option<String>,
    #[arg(long)]
    pub any_host: bool,
    /// Run passive checks on crawled pages
    #[arg(long)]
    pub passive: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long, default_value_t = 15_000)]
    pub timeout: u64,
}

pub fn spider(ctx: &Context, args: SpiderArgs) -> Result<()> {
    let project = ctx.project(true)?;
    let seed = Url::parse(&args.seed).with_context(|| format!("invalid URL '{}'", args.seed))?;
    let mut include = project.config.scope.include.clone();
    if include.is_empty() {
        let host = seed.host_str().unwrap_or("");
        let port = seed.port().map(|p| format!(":{p}")).unwrap_or_default();
        include.push(format!("{}://{}{}/*", seed.scheme(), host, port));
    }
    let mut scope = Scope::new(&include, &project.config.scope.exclude)?;
    scope.compile()?;
    let mut session = ctx.session_client(
        &project,
        args.insecure,
        args.timeout,
        0,
        args.user_agent.as_deref(),
    )?;
    let crawl_options = scanner::crawl::CrawlOptions {
        client: &session.options,
        scope: &scope,
        config: &project.config,
        session: &session.state,
        max_pages: args.max_pages,
        max_depth: args.max_depth,
        delay: Duration::from_millis(args.delay),
        same_host_only: !args.any_host,
    };
    let result = scanner::crawl::crawl(&seed, &crawl_options);
    session.snapshot_cookies();
    session.save(&project)?;

    let mut sitemap = project.sitemap()?;
    for page in &result.pages {
        sitemap.add_response(
            &page.url,
            &page.request.method,
            page.response.status,
            page.response.content_type().unwrap_or(""),
            &page.response.body,
            "spider",
        );
    }
    sitemap.save()?;

    if args.json {
        let pages: Vec<serde_json::Value> = result
            .pages
            .iter()
            .map(|page| {
                serde_json::json!({
                    "url": page.url,
                    "depth": page.depth,
                    "status": page.response.status,
                    "length": page.response.body.len(),
                    "mime": page.response.content_type().unwrap_or(""),
                    "title": crate::sitemap::extract_title(&page.response.body),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&pages)?);
    } else {
        if result.pages.is_empty() {
            println!("no pages found");
        } else {
            let rows: Vec<Vec<String>> = result
                .pages
                .iter()
                .map(|page| {
                    vec![
                        page.depth.to_string(),
                        page.response.status.to_string(),
                        page.request.method.clone(),
                        format_size(page.response.body.len()),
                        truncate(&page.url, 92),
                    ]
                })
                .collect();
            util::table(&["Depth", "Status", "Method", "Size", "URL"], &rows);
            println!("\n{} pages", result.pages.len());
            println!();
            for line in sitemap.tree() {
                println!("{line}");
            }
        }
    }
    for error in result.errors.iter().take(10) {
        eprintln!("[!] {error}");
    }
    if result.errors.len() > 10 {
        eprintln!("[!] ... {} more errors", result.errors.len() - 10);
    }

    if args.passive {
        let store = project.issue_store()?;
        let mut issues = Vec::new();
        for page in &result.pages {
            for issue in scan_passive(&page.request, &page.response, false) {
                if store.append(&issue).unwrap_or(false) {
                    issues.push(issue);
                }
            }
        }
        if issues.is_empty() {
            println!("passive scan: no new findings");
        } else {
            print!("{}", report::table(&issues, Severity::Info));
        }
    }
    Ok(())
}

#[derive(Debug, Args)]
pub struct SitemapArgs {
    #[command(subcommand)]
    pub action: SitemapAction,
}

#[derive(Debug, Subcommand)]
pub enum SitemapAction {
    /// Print the site tree
    Tree {
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
    /// List entries as a table
    List {
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
    /// Show one entry (exact URL or substring)
    Show { url: String },
    /// Remove one entry
    Remove { url: String },
    /// Remove all entries
    Clear,
    /// Fetch a URL and add it to the sitemap
    Add {
        url: String,
        #[arg(long)]
        insecure: bool,
    },
    /// Import responses from proxy history
    ImportHistory {
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
}

pub fn sitemap(ctx: &Context, args: SitemapArgs) -> Result<()> {
    let project = ctx.project(true)?;
    let mut map = project.sitemap()?;
    match args.action {
        SitemapAction::Tree { json, limit } => {
            if json {
                let mut entries: Vec<_> = map.list().into_iter().cloned().collect();
                entries.sort_by(|a, b| a.url.cmp(&b.url));
                if limit > 0 {
                    entries.truncate(limit);
                }
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if map.is_empty() {
                println!("sitemap is empty");
            } else {
                let lines = map.tree();
                let lines = if limit > 0 {
                    lines.into_iter().take(limit).collect::<Vec<_>>()
                } else {
                    lines
                };
                for line in lines {
                    println!("{line}");
                }
            }
            Ok(())
        }
        SitemapAction::List {
            search,
            json,
            limit,
        } => {
            let needle = search.map(|s| s.to_ascii_lowercase());
            let mut entries: Vec<_> = map
                .list()
                .into_iter()
                .filter(|entry| {
                    needle
                        .as_deref()
                        .map(|needle| entry.url.to_ascii_lowercase().contains(needle))
                        .unwrap_or(true)
                })
                .cloned()
                .collect();
            entries.sort_by(|a, b| a.url.cmp(&b.url));
            if limit > 0 {
                entries.truncate(limit);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("no sitemap entries match");
            } else {
                let rows: Vec<Vec<String>> = entries
                    .iter()
                    .map(|entry| {
                        vec![
                            entry.status.to_string(),
                            entry.method.clone(),
                            format_size(entry.length),
                            truncate(&entry.url, 80),
                            truncate(&entry.title, 40),
                            entry.source.clone(),
                        ]
                    })
                    .collect();
                util::table(
                    &["Status", "Method", "Size", "URL", "Title", "Source"],
                    &rows,
                );
                println!("\n{} entries", entries.len());
            }
            Ok(())
        }
        SitemapAction::Show { url } => {
            let matches: Vec<_> = map
                .list()
                .into_iter()
                .filter(|entry| entry.url == url || entry.url.contains(&url))
                .cloned()
                .collect();
            if matches.is_empty() {
                bail!("no sitemap entry matches '{url}'");
            }
            println!("{}", serde_json::to_string_pretty(&matches)?);
            Ok(())
        }
        SitemapAction::Remove { url } => {
            let before = map.len();
            map.entries.remove(&url);
            if map.len() == before {
                bail!("no sitemap entry with URL '{url}'");
            }
            map.save()?;
            println!("removed {url}");
            Ok(())
        }
        SitemapAction::Clear => {
            map.clear();
            map.save()?;
            println!("sitemap cleared");
            Ok(())
        }
        SitemapAction::Add { url, insecure } => {
            let parsed = Url::parse(&url).with_context(|| format!("invalid URL '{url}'"))?;
            let mut request = crate::http::Request::from_url("GET", &parsed, Vec::new(), None);
            request.scheme = Some(parsed.scheme().to_string());
            let options = scanner::client_options(&project, insecure, 15_000);
            let response = client::send(&request, &options)
                .with_context(|| format!("request to {url} failed"))?;
            map.add_response(
                &url,
                "GET",
                response.response.status,
                response.response.content_type().unwrap_or(""),
                &response.response.body,
                "manual",
            );
            map.save()?;
            println!(
                "added {url} [{} {}]",
                response.response.status,
                format_size(response.response.body.len())
            );
            Ok(())
        }
        SitemapAction::ImportHistory { limit } => {
            let entries = project.history()?.list(&HistoryFilter {
                limit,
                ..Default::default()
            })?;
            let mut imported = 0usize;
            for entry in entries {
                let Ok(Some(response)) = entry.response() else {
                    continue;
                };
                map.add_response(
                    &entry.url,
                    &entry.method,
                    response.status,
                    response.content_type().unwrap_or(""),
                    &response.body,
                    "history",
                );
                imported += 1;
            }
            map.save()?;
            println!("imported {imported} history entries into the sitemap");
            Ok(())
        }
    }
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    #[arg(long, default_value = "table")]
    pub format: String,
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    #[arg(long, default_value = "info")]
    pub min_severity: String,
    #[arg(long)]
    pub title: Option<String>,
    #[arg(long)]
    pub include_evidence: bool,
    /// Print statistics and exit
    #[arg(long)]
    pub stats: bool,
}

pub fn report(ctx: &Context, args: ReportArgs) -> Result<()> {
    let project = ctx.project(true)?;
    let store: IssueStore = project.issue_store()?;
    let issues = store.list()?;
    let min = parse_severity(&args.min_severity)?;
    let filtered = report::filter(&issues, min);
    if args.stats {
        let stats = report::stats(&filtered);
        println!("project : {}", project.config.name);
        println!("issues  : {}", report::summary_line(&stats));
        if stats.total > 0 {
            println!();
            println!("{:<10}Count", "Severity");
            println!("{}", "-".repeat(18));
            for (label, count) in [
                ("High", stats.high),
                ("Medium", stats.medium),
                ("Low", stats.low),
                ("Info", stats.info),
            ] {
                println!("{label:<10}{count}");
            }
            if !stats.by_check.is_empty() {
                println!();
                println!("{:<26}Count", "Check");
                println!("{}", "-".repeat(34));
                for (check, count) in &stats.by_check {
                    println!("{check:<26}{count}");
                }
            }
            println!();
        }
        println!("evidence: {}", report::evidence_size_label(&filtered));
        println!("path    : {}", store.path().display());
        return Ok(());
    }
    let format = ReportFormat::parse(&args.format)?;
    let options = ReportOptions {
        title: args
            .title
            .unwrap_or_else(|| format!("{} security report", project.config.name)),
        min_severity: min,
        include_evidence: args.include_evidence,
    };
    let content = report::render(&filtered, format, &options, &project.config.name)?;
    match args.output {
        Some(path) => {
            let path = resolve_output(&path, format, "report");
            report::write(&path, &content)?;
            println!(
                "report written to {} ({}, {} findings)",
                path.display(),
                format.label(),
                filtered.len()
            );
        }
        None => {
            print!("{content}");
            if !content.ends_with('\n') {
                println!();
            }
        }
    }
    Ok(())
}

pub fn parse_severity(value: &str) -> Result<Severity> {
    value
        .parse::<Severity>()
        .with_context(|| format!("unknown severity '{value}' (use info, low, medium or high)"))
}

fn resolve_output(path: &std::path::Path, format: ReportFormat, prefix: &str) -> PathBuf {
    if path.is_dir() {
        let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        path.join(format!("{prefix}-{stamp}.{}", format.extension()))
    } else {
        path.to_path_buf()
    }
}
