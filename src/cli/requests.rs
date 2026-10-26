//! Request-oriented commands: history, repeater and intruder.

use super::Context;
use crate::http::{client, Request};
use crate::intruder::{self, AttackType, ExtractRule, IntruderOptions, PayloadSet, Processor};
use crate::storage::HistoryFilter;
use crate::util::{self, format_duration, format_size, truncate};
use anyhow::{anyhow, bail, Context as _, Result};
use clap::{Args, Subcommand};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct HistoryArgs {
    #[command(subcommand)]
    pub action: HistoryAction,
}

#[derive(Debug, Subcommand)]
pub enum HistoryAction {
    /// List recorded requests
    List {
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        status: Option<u16>,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        search: Option<String>,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long)]
        in_scope: bool,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show a request/response by history id
    Show {
        id: u64,
        #[arg(long, conflicts_with = "response_only")]
        request_only: bool,
        #[arg(long, conflicts_with = "request_only")]
        response_only: bool,
        /// Write the raw bytes (may contain binary data)
        #[arg(long)]
        raw: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, value_name = "PATH")]
        save_request: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        save_response: Option<PathBuf>,
    },
    /// Delete one history entry
    Delete { id: u64 },
    /// Delete all history entries
    Clear {
        #[arg(long)]
        yes: bool,
    },
    /// Attach a note to an entry
    Note { id: u64, text: String },
    /// Add a tag to an entry
    Tag { id: u64, tag: String },
    /// Remove a tag from an entry
    Untag { id: u64, tag: String },
    /// Summarise hosts, status codes and traffic volume
    Stats {
        #[arg(long)]
        json: bool,
    },
}

pub fn history(ctx: &Context, args: HistoryArgs) -> Result<()> {
    let project = ctx.project(true)?;
    let store = project.history()?;
    match args.action {
        HistoryAction::List {
            method,
            status,
            host,
            search,
            tags,
            in_scope,
            limit,
            offset,
            json,
        } => {
            let scope = crate::scope::Scope::new(
                &project.config.scope.include,
                &project.config.scope.exclude,
            )?;
            let filter = HistoryFilter {
                method,
                status,
                host,
                search,
                tags,
                offset,
                limit,
                in_scope: if in_scope { Some(scope) } else { None },
            };
            let entries = store.list(&filter)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
                return Ok(());
            }
            if entries.is_empty() {
                println!("no history entries match the filter");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = entries
                .iter()
                .map(|entry| {
                    vec![
                        entry.id.to_string(),
                        entry.method.clone(),
                        entry.status.to_string(),
                        entry.host.clone(),
                        truncate(&entry.url, 76),
                        format_size(entry.size()),
                        format_duration(std::time::Duration::from_millis(entry.duration_ms)),
                        entry.tags.join(","),
                        truncate(&entry.note, 30),
                    ]
                })
                .collect();
            util::table(
                &[
                    "ID", "Method", "Status", "Host", "URL", "Size", "Time", "Tags", "Note",
                ],
                &rows,
            );
            println!("\n{} entries", entries.len());
            Ok(())
        }
        HistoryAction::Show {
            id,
            request_only,
            response_only,
            raw,
            json,
            save_request,
            save_response,
        } => {
            let Some(entry) = store.get(id)? else {
                bail!("history entry {id} not found");
            };
            if let Some(path) = &save_request {
                std::fs::write(path, entry.request_bytes()?)
                    .with_context(|| format!("cannot write '{}'", path.display()))?;
                println!("request saved to {}", path.display());
            }
            if let Some(path) = &save_response {
                match entry.response_bytes()? {
                    Some(bytes) => {
                        std::fs::write(path, bytes)
                            .with_context(|| format!("cannot write '{}'", path.display()))?;
                        println!("response saved to {}", path.display());
                    }
                    None => eprintln!("entry {id} has no response"),
                }
            }
            if save_request.is_some() || save_response.is_some() {
                return Ok(());
            }
            if json {
                let value = serde_json::json!({
                    "id": entry.id,
                    "ts": entry.ts,
                    "method": entry.method,
                    "url": entry.url,
                    "host": entry.host,
                    "port": entry.port,
                    "tls": entry.tls,
                    "status": entry.status,
                    "mime": entry.mime,
                    "duration_ms": entry.duration_ms,
                    "tags": entry.tags,
                    "note": entry.note,
                    "request": entry.request,
                    "response": entry.response,
                });
                println!("{}", serde_json::to_string_pretty(&value)?);
                return Ok(());
            }
            let request_bytes = entry.request_bytes()?;
            let response_bytes = entry.response_bytes()?;
            if raw {
                let mut stdout = std::io::stdout();
                if !response_only {
                    stdout.write_all(&request_bytes)?;
                }
                if !request_only {
                    if let Some(bytes) = &response_bytes {
                        if !response_only {
                            stdout.write_all(b"\n\n")?;
                        }
                        stdout.write_all(bytes)?;
                    }
                }
                stdout.flush()?;
                return Ok(());
            }
            if !response_only {
                println!("=== request (id {}) ===", entry.id);
                print!("{}", String::from_utf8_lossy(&request_bytes));
                if !request_bytes.ends_with(b"\n") {
                    println!();
                }
            }
            if !request_only {
                println!();
                println!("=== response ===");
                match response_bytes {
                    Some(bytes) => {
                        print!("{}", crate::util::display_bytes(&bytes));
                        if !bytes.ends_with(b"\n") {
                            println!();
                        }
                    }
                    None => println!("(no response recorded)"),
                }
            }
            Ok(())
        }
        HistoryAction::Delete { id } => {
            if store.delete(id)? {
                println!("deleted history entry {id}");
            } else {
                bail!("history entry {id} not found");
            }
            Ok(())
        }
        HistoryAction::Clear { yes } => {
            if !yes
                && std::io::stdin().is_terminal()
                && !util::confirm("Delete all history entries?", false)?
            {
                println!("cancelled");
                return Ok(());
            }
            store.clear()?;
            println!("history cleared");
            Ok(())
        }
        HistoryAction::Note { id, text } => {
            if store.add_note(id, &text)? {
                println!("note set on entry {id}");
                Ok(())
            } else {
                bail!("history entry {id} not found")
            }
        }
        HistoryAction::Tag { id, tag } => {
            if store.add_tag(id, &tag)? {
                println!("tag '{tag}' added to entry {id}");
                Ok(())
            } else {
                bail!("history entry {id} not found")
            }
        }
        HistoryAction::Untag { id, tag } => {
            if store.remove_tag(id, &tag)? {
                println!("tag '{tag}' removed from entry {id}");
                Ok(())
            } else {
                bail!("history entry {id} not found")
            }
        }
        HistoryAction::Stats { json } => {
            let entries = store.list(&HistoryFilter::default())?;
            let mut statuses: BTreeMap<u16, usize> = BTreeMap::new();
            let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
            let mut total = 0usize;
            for entry in &entries {
                *statuses.entry(entry.status).or_insert(0) += 1;
                *hosts.entry(entry.host.clone()).or_insert(0) += 1;
                total += entry.size();
            }
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "entries": entries.len(),
                        "size": total,
                        "statuses": statuses,
                        "hosts": hosts,
                    }))?
                );
                return Ok(());
            }
            println!("entries : {}", entries.len());
            println!("size    : {}", format_size(total));
            println!("statuses:");
            for (status, count) in &statuses {
                println!("  {status:>3}  {count}");
            }
            println!("hosts:");
            for (host, count) in &hosts {
                println!("  {host}  {count}");
            }
            Ok(())
        }
    }
}

#[derive(Debug, Args)]
pub struct RepeaterArgs {
    /// Request file (raw HTTP)
    #[arg(long, conflicts_with_all = ["url", "history_id"])]
    pub file: Option<PathBuf>,
    /// Build the request from a URL
    #[arg(long, conflicts_with_all = ["file", "history_id"])]
    pub url: Option<String>,
    /// Load a request from proxy history
    #[arg(long = "history", conflicts_with_all = ["file", "url"])]
    pub history_id: Option<u64>,
    #[arg(long)]
    pub method: Option<String>,
    #[arg(long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,
    #[arg(long)]
    pub data: Option<String>,
    /// Open the request in $EDITOR before sending
    #[arg(long)]
    pub edit: bool,
    /// Print raw response bytes
    #[arg(long)]
    pub raw: bool,
    #[arg(long)]
    pub headers_only: bool,
    #[arg(long)]
    pub body_only: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long, default_value_t = 1)]
    pub repeat: usize,
    #[arg(long, value_name = "PATH")]
    pub save_response: Option<PathBuf>,
    #[arg(long)]
    pub no_session: bool,
    #[arg(long)]
    pub no_save: bool,
    #[arg(long)]
    pub insecure: bool,
    #[arg(long, default_value_t = 0)]
    pub follow: usize,
    #[arg(long, default_value_t = 15_000)]
    pub timeout: u64,
    #[arg(long)]
    pub user_agent: Option<String>,
}

pub fn repeater(ctx: &Context, args: RepeaterArgs) -> Result<()> {
    let project = ctx.project(true)?;
    let session = ctx.session_client(
        &project,
        args.insecure,
        args.timeout,
        args.follow,
        args.user_agent.as_deref(),
    )?;

    let mut request = load_request(
        ctx,
        &project,
        args.file.as_deref(),
        args.url.as_deref(),
        args.history_id,
        args.method.as_deref(),
        &args.headers,
        args.data.as_deref(),
    )?;
    if !args.no_session {
        session.prepare(&mut request, &project)?;
    }
    if args.edit {
        request = edit_request(&request)?;
    }
    if request.header("Content-Length").is_some() || !request.body.is_empty() {
        request.set_header("Content-Length", request.body.len().to_string());
    }

    let history = if args.no_save {
        None
    } else {
        Some(project.history()?)
    };
    let mut results = Vec::new();
    for index in 0..args.repeat.max(1) {
        let started = std::time::Instant::now();
        let http = client::send(&request, &session.options)
            .with_context(|| format!("request to {} failed", request.target))?;
        let duration = started.elapsed();
        if let Some(history) = &history {
            history
                .record(
                    &request,
                    Some(&http.response),
                    duration,
                    vec!["repeater".into()],
                )
                .ok();
        }
        if let Some(path) = &args.save_response {
            let bytes = http.response.to_bytes();
            let path = numbered_path(path, index, args.repeat);
            std::fs::write(&path, &bytes)
                .with_context(|| format!("cannot write '{}'", path.display()))?;
        }
        if args.json {
            results.push(serde_json::json!({
                "index": index,
                "status": http.response.status,
                "reason": http.response.reason,
                "url": http.final_url,
                "duration_ms": duration.as_millis() as u64,
                "redirects": http.redirects.iter().map(|hop| serde_json::json!({
                    "status": hop.status,
                    "from": hop.from,
                    "to": hop.to,
                })).collect::<Vec<_>>(),
                "request": request.text(),
                "response": http.response.text(),
                "response_b64": http.response.to_b64(),
            }));
            continue;
        }
        if !ctx.quiet {
            eprintln!(
                "[*] {} {} -> {} {} in {}",
                index + 1,
                request.target,
                http.response.status,
                format_size(http.response.body.len()),
                format_duration(duration)
            );
        }
        if args.raw {
            let bytes = http.response.to_bytes();
            std::io::stdout().write_all(&bytes)?;
            std::io::stdout().flush()?;
        } else if args.headers_only {
            print!("{}", http.response.head_string());
        } else if args.body_only {
            print!("{}", http.response.body_text());
            if !http.response.body.ends_with(b"\n") {
                println!();
            }
        } else {
            print!("{}", http.response.text());
            if !http.response.body.ends_with(b"\n") {
                println!();
            }
        }
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    }
    session.save(&project)?;
    Ok(())
}

#[derive(Debug, Args)]
pub struct IntruderArgs {
    /// Request template file containing § markers
    #[arg(long, conflicts_with_all = ["url", "history_id"])]
    pub file: Option<PathBuf>,
    /// Build the template from a URL (use --wrap to add markers)
    #[arg(long, conflicts_with_all = ["file", "history_id"])]
    pub url: Option<String>,
    /// Load the template from proxy history
    #[arg(long = "history", conflicts_with_all = ["file", "url"])]
    pub history_id: Option<u64>,
    #[arg(long)]
    pub method: Option<String>,
    #[arg(long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,
    #[arg(long)]
    pub data: Option<String>,
    /// Wrap this substring in § markers inside the template
    #[arg(long)]
    pub wrap: Option<String>,
    #[arg(long, short = 'a', default_value = "sniper")]
    pub attack: String,
    /// Payload source: list:a,b | file:path | numbers:1-10 | hex:0a-0f | literal
    #[arg(long = "payload", short = 'p', required = true)]
    pub payloads: Vec<String>,
    /// Payload processor applied to every set (upper, url, base64, md5, ...)
    #[arg(long = "processor")]
    pub processors: Vec<String>,
    #[arg(long = "grep")]
    pub grep: Vec<String>,
    /// Extract regex: NAME=REGEX
    #[arg(long = "extract")]
    pub extract: Vec<String>,
    #[arg(long = "stop-on")]
    pub stop_on: Vec<String>,
    #[arg(long, default_value_t = 10)]
    pub concurrency: usize,
    #[arg(long, default_value_t = 0)]
    pub delay: u64,
    #[arg(long)]
    pub max_requests: Option<usize>,
    #[arg(long)]
    pub save_responses: bool,
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// Output format: table, csv or json (inferred from the output extension)
    #[arg(long, value_parser = ["table", "csv", "json"])]
    pub format: Option<String>,
    /// Number of result rows to print (0 prints all)
    #[arg(long, default_value_t = 25)]
    pub show: usize,
    #[arg(long)]
    pub insecure: bool,
    #[arg(long, default_value_t = 0)]
    pub follow: usize,
    #[arg(long, default_value_t = 15_000)]
    pub timeout: u64,
    #[arg(long)]
    pub no_session: bool,
    #[arg(long)]
    pub user_agent: Option<String>,
}

pub fn intruder(ctx: &Context, args: IntruderArgs) -> Result<()> {
    let project = ctx.project(true)?;
    let session = ctx.session_client(
        &project,
        args.insecure,
        args.timeout,
        args.follow,
        args.user_agent.as_deref(),
    )?;
    let mut template = load_request(
        ctx,
        &project,
        args.file.as_deref(),
        args.url.as_deref(),
        args.history_id,
        args.method.as_deref(),
        &args.headers,
        args.data.as_deref(),
    )?;
    if !args.no_session {
        session.prepare(&mut template, &project)?;
    }
    if let Some(needle) = &args.wrap {
        let target_matches = template.target.contains(needle);
        let body_text = String::from_utf8_lossy(&template.body).to_string();
        let body_matches = body_text.contains(needle);
        if !target_matches && !body_matches {
            bail!("--wrap substring '{needle}' was not found in the request target or body");
        }
        if target_matches {
            template.target = intruder::wrap_markers(&template.target, needle);
        }
        if body_matches {
            template.body = intruder::wrap_markers(&body_text, needle).into_bytes();
        }
    }
    if intruder::marker_count(&template) == 0 {
        bail!("the request template has no § markers; add them manually or use --wrap <substring>");
    }

    let attack = AttackType::parse(&args.attack)?;
    let processors = args
        .processors
        .iter()
        .map(|spec| Processor::parse(spec))
        .collect::<Result<Vec<_>>>()?;
    let mut sets = Vec::new();
    for spec in &args.payloads {
        sets.push(PayloadSet::parse(spec)?.with_processors(processors.clone()));
    }
    let extract = args
        .extract
        .iter()
        .map(|spec| ExtractRule::parse(spec))
        .collect::<Result<Vec<_>>>()?;
    let options = IntruderOptions {
        attack,
        payload_sets: sets,
        concurrency: args.concurrency,
        delay_ms: args.delay,
        grep: args.grep.clone(),
        extract,
        stop_on: args.stop_on.clone(),
        max_requests: args.max_requests.unwrap_or(0),
        save_responses: args.save_responses,
        quiet: ctx.quiet,
    };

    let run = intruder::run(&template, &options, &session.options)?;
    session.save(&project)?;

    let format = args
        .format
        .clone()
        .or_else(|| {
            args.output
                .as_ref()
                .map(|path| match crate::report::ReportFormat::from_path(path) {
                    crate::report::ReportFormat::Json => "json".to_string(),
                    _ => {
                        if path.extension().and_then(|e| e.to_str()) == Some("csv") {
                            "csv".to_string()
                        } else {
                            "table".to_string()
                        }
                    }
                })
        })
        .unwrap_or_else(|| "table".to_string());

    let extract_names: Vec<String> = {
        let mut names = Vec::new();
        for result in &run.results {
            for name in result.extracted.keys() {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }
        names
    };
    let rendered = match format.as_str() {
        "json" => intruder::to_json(&run.results)?,
        "csv" => intruder::to_csv(&run.results, &extract_names),
        _ => intruder_table(&run, args.show, &extract_names),
    };
    if let Some(path) = &args.output {
        crate::config::atomic_write(path, rendered.as_bytes())
            .with_context(|| format!("cannot write '{}'", path.display()))?;
        println!("results written to {}", path.display());
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }
    println!("{}", intruder::summary(&run));
    if !run.errors.is_empty() {
        for error in run.errors.iter().take(10) {
            eprintln!("[!] {error}");
        }
        if run.errors.len() > 10 {
            eprintln!("[!] ... {} more errors", run.errors.len() - 10);
        }
    }
    Ok(())
}

fn intruder_table(run: &intruder::IntruderRun, show: usize, extract_names: &[String]) -> String {
    let mut out = String::new();
    let mut headers = vec!["#", "Status", "Length", "ms", "Payloads", "Grep"];
    for name in extract_names {
        headers.push(name);
    }
    let limit = if show == 0 { run.results.len() } else { show };
    let rows: Vec<Vec<String>> = run
        .results
        .iter()
        .take(limit)
        .map(|result| {
            let mut row = vec![
                (result.index + 1).to_string(),
                if result.status == 0 {
                    "ERR".into()
                } else {
                    result.status.to_string()
                },
                result.length.to_string(),
                result.duration_ms.to_string(),
                truncate(&result.payloads.join(" | "), 60),
                truncate(&result.grep.join(","), 24),
            ];
            for name in extract_names {
                row.push(result.extracted.get(name).cloned().unwrap_or_default());
            }
            row
        })
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    let border = || {
        let mut line = String::from("+");
        for width in &widths {
            line.push_str(&"-".repeat(width + 2));
            line.push('+');
        }
        line.push('\n');
        line
    };
    out.push_str(&border());
    out.push('|');
    for (index, name) in headers.iter().enumerate() {
        out.push_str(&format!(" {:<width$} |", name, width = widths[index]));
    }
    out.push('\n');
    out.push_str(&border());
    for row in &rows {
        out.push('|');
        for (index, cell) in row.iter().enumerate() {
            out.push_str(&format!(" {:<width$} |", cell, width = widths[index]));
        }
        out.push('\n');
    }
    out.push_str(&border());
    if limit < run.results.len() {
        out.push_str(&format!(
            "showing {limit} of {} results (use --show 0 for all)\n",
            run.results.len()
        ));
    }
    out
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_request(
    ctx: &Context,
    project: &crate::storage::Project,
    file: Option<&Path>,
    url: Option<&str>,
    history_id: Option<u64>,
    method: Option<&str>,
    headers: &[String],
    data: Option<&str>,
) -> Result<Request> {
    if let Some(id) = history_id {
        let entry = project
            .history()?
            .get(id)?
            .ok_or_else(|| anyhow!("history entry {id} not found"))?;
        let mut request = entry.request()?;
        if let Some(method) = method {
            request.method = method.to_string();
        }
        for header in headers {
            let (name, value) = split_header(header)?;
            request.set_header(name, value);
        }
        if let Some(data) = data {
            request.body = data.as_bytes().to_vec();
            request.set_header("Content-Length", request.body.len().to_string());
        }
        return Ok(request);
    }
    if let Some(path) = file {
        let raw = std::fs::read(path)
            .with_context(|| format!("cannot read request '{}'", path.display()))?;
        let mut request = intruder::template_from_raw(&raw)?;
        if let Some(method) = method {
            request.method = method.to_string();
        }
        for header in headers {
            let (name, value) = split_header(header)?;
            request.set_header(name, value);
        }
        if let Some(data) = data {
            request.body = data.as_bytes().to_vec();
        }
        if request.header("Content-Length").is_some() || !request.body.is_empty() {
            request.set_header("Content-Length", request.body.len().to_string());
        }
        return Ok(request);
    }
    if let Some(url) = url {
        return request_from_url(url, method, headers, data);
    }
    if !std::io::stdin().is_terminal() {
        let mut raw = Vec::new();
        std::io::stdin().read_to_end(&mut raw)?;
        if !raw.is_empty() {
            if ctx.verbose {
                eprintln!("[*] read {} bytes from stdin", raw.len());
            }
            return intruder::template_from_raw(&raw);
        }
    }
    bail!("no request source: use --file, --url, --history or pipe a raw request to stdin")
}

pub(crate) fn request_from_url(
    url: &str,
    method: Option<&str>,
    headers: &[String],
    data: Option<&str>,
) -> Result<Request> {
    let parsed = url::Url::parse(url).with_context(|| format!("invalid URL '{url}'"))?;
    let method = method.unwrap_or(if data.is_some() { "POST" } else { "GET" });
    let body = data
        .map(|value| value.as_bytes().to_vec())
        .unwrap_or_default();
    let content_type = if data.is_some() && !body.is_empty() {
        Some("application/x-www-form-urlencoded")
    } else {
        None
    };
    let mut request = Request::from_url(method, &parsed, body, content_type);
    // `url::Url` percent-encodes non-ASCII query bytes. Intruder markers are
    // literal section signs, so restore them in the request target.
    request.target = request
        .target
        .replace("%C2%A7", "\u{a7}")
        .replace("%c2%a7", "\u{a7}");
    for header in headers {
        let (name, value) = split_header(header)?;
        request.set_header(name, value);
    }
    request.scheme = Some(parsed.scheme().to_string());
    if request.header("Content-Length").is_some() {
        request.set_header("Content-Length", request.body.len().to_string());
    }
    Ok(request)
}

fn split_header(header: &str) -> Result<(&str, &str)> {
    let (name, value) = header
        .split_once(':')
        .ok_or_else(|| anyhow!("header '{header}' must be in 'Name: value' form"))?;
    if name.trim().is_empty() {
        bail!("header name cannot be empty");
    }
    Ok((name.trim(), value.trim()))
}

fn edit_request(request: &Request) -> Result<Request> {
    let path = std::env::temp_dir().join(format!("burpcli-repeater-{}.txt", std::process::id()));
    std::fs::write(&path, request.to_bytes())?;
    let editor = crate::config::editor();
    let argv = crate::util::split_command(&editor);
    if argv.is_empty() {
        bail!("no editor configured (set $EDITOR)");
    }
    let status = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .arg(&path)
        .status()
        .with_context(|| format!("cannot start editor '{editor}'"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&path);
        bail!("editor exited with {status}");
    }
    let raw = std::fs::read(&path)?;
    let _ = std::fs::remove_file(&path);
    intruder::template_from_raw(&raw)
}

fn numbered_path(path: &Path, index: usize, total: usize) -> PathBuf {
    if total <= 1 {
        return path.to_path_buf();
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("response");
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("bin");
    path.with_file_name(format!("{stem}-{}.{extension}", index + 1))
}
