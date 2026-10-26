//! Administrative commands: proxy, CA, OOB, scope, projects, session, plugins, config.

use super::Context;
use crate::config::{self, GlobalConfig, ProjectRef, Rule};
use crate::http::client;
use crate::plugins::{self, PluginManager, PluginManifest};
use crate::proxy::{CertificateAuthority, ProxyOptions, ProxyServer};
use crate::session::{self, SessionState};
use crate::storage::Project;
use crate::util::{self, truncate};
use anyhow::{anyhow, bail, Context as _, Result};
use clap::{Args, Subcommand};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Args)]
pub struct ProxyArgs {
    #[arg(long, short = 'b')]
    pub bind: Option<String>,
    #[arg(long, short = 'p')]
    pub port: Option<u16>,
    /// Intercept TLS by issuing certificates from the project CA
    #[arg(long)]
    pub mitm: bool,
    /// Pause every request and response for review
    #[arg(long)]
    pub intercept: bool,
    #[arg(long)]
    pub intercept_requests: bool,
    #[arg(long)]
    pub intercept_responses: bool,
    /// Refuse traffic outside the project scope
    #[arg(long)]
    pub only_in_scope: bool,
    /// Verify upstream TLS certificates (off by default, like Burp)
    #[arg(long)]
    pub verify_upstream: bool,
    #[arg(long, value_name = "MS")]
    pub timeout: Option<u64>,
}

pub fn proxy(ctx: &Context, args: ProxyArgs) -> Result<()> {
    let project = ctx.project(true)?;
    let mut options = ProxyOptions::from_project(&project);
    if let Some(bind) = args.bind {
        options.bind = bind;
    }
    if let Some(port) = args.port {
        options.port = port;
    }
    options.mitm |= args.mitm;
    options.intercept_requests |= args.intercept || args.intercept_requests;
    options.intercept_responses |= args.intercept || args.intercept_responses;
    options.only_in_scope |= args.only_in_scope;
    options.insecure = !args.verify_upstream;
    if let Some(timeout) = args.timeout {
        options.timeout_ms = timeout;
    }
    options.verbose = !ctx.quiet;

    let mut server = ProxyServer::start(&project, &options)?;
    let address = server.local_addr();
    println!(
        "{} listening on http://{}",
        util::bold("burpcli proxy"),
        address
    );
    println!("project : {}", project.root.display());
    println!(
        "mode    : {}",
        if options.mitm {
            "TLS interception (MITM)"
        } else {
            "HTTP + CONNECT tunnel"
        }
    );
    if options.mitm {
        println!("CA cert : {}", project.ca_cert_path().display());
        println!("Install the CA in your browser/OS to intercept HTTPS.");
    }
    if options.intercept_requests || options.intercept_responses {
        if std::io::stdin().is_terminal() {
            println!("Intercept enabled: press Enter to forward, d to drop, e to edit.");
        } else {
            println!("Intercept requested but stdin is not a terminal; forwarding automatically.");
        }
    }
    println!("Press Ctrl+C to stop.");
    wait_for_interrupt_checked()?;
    server.stop();
    println!("\nproxy stopped");
    Ok(())
}

fn wait_for_interrupt_checked() -> Result<()> {
    super::wait_for_interrupt()
}

#[derive(Debug, Args)]
pub struct CaArgs {
    #[command(subcommand)]
    pub action: CaAction,
}

#[derive(Debug, Subcommand)]
pub enum CaAction {
    /// Print the CA certificate in PEM format
    Show,
    /// Copy the CA certificate to a file
    Export {
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Show CA paths and status
    Info,
    /// Replace the CA (invalidates previously issued certificates)
    Regenerate {
        #[arg(long)]
        force: bool,
    },
}

pub fn ca(ctx: &Context, args: CaArgs) -> Result<()> {
    let project = ctx.project(true)?;
    match args.action {
        CaAction::Show => {
            let authority = CertificateAuthority::from_project(&project)?;
            print!("{}", authority.pem());
            if !authority.pem().ends_with('\n') {
                println!();
            }
            Ok(())
        }
        CaAction::Export { output } => {
            let authority = CertificateAuthority::from_project(&project)?;
            let path = output.unwrap_or_else(|| project.reports_dir().join("burpcli-ca.pem"));
            authority.export(&path)?;
            println!("CA certificate exported to {}", path.display());
            Ok(())
        }
        CaAction::Info => {
            let cert = project.ca_cert_path();
            let key = project.ca_key_path();
            println!("cert:    {}", cert.display());
            println!("key:     {}", key.display());
            println!("exists:  {}", cert.exists() && key.exists());
            if cert.exists() && key.exists() {
                let authority = CertificateAuthority::from_project(&project)?;
                println!("sha256:  {}", short_sha256(authority.pem().as_bytes()));
            }
            Ok(())
        }
        CaAction::Regenerate { force } => {
            if !force {
                bail!("refusing to replace the CA without --force");
            }
            let cert = project.ca_cert_path();
            let key = project.ca_key_path();
            std::fs::remove_file(&cert).ok();
            std::fs::remove_file(&key).ok();
            let authority = CertificateAuthority::from_project(&project)?;
            println!("new CA written to {}", cert.display());
            println!("sha256: {}", short_sha256(authority.pem().as_bytes()));
            println!("Reinstall the CA in clients that previously trusted it.");
            Ok(())
        }
    }
}

fn short_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(&hasher.finalize()[..8])
}

#[derive(Debug, Args)]
pub struct OobArgs {
    #[command(subcommand)]
    pub action: OobAction,
}

#[derive(Debug, Subcommand)]
pub enum OobAction {
    /// Start the collaborator daemon
    Start {
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        public_url: Option<String>,
        /// Run in the foreground instead of daemonising
        #[arg(long)]
        foreground: bool,
        #[arg(long)]
        json: bool,
    },
    /// Stop the daemon
    Stop,
    /// Show daemon status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List recorded interactions
    Poll {
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Delete recorded interactions
    Clear,
    /// Generate a unique callback URL
    Payload {
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        base_url: Option<String>,
    },
    /// Print the callback base URL
    Url,
}

pub fn oob(ctx: &Context, args: OobArgs) -> Result<()> {
    let project = ctx.project(true)?;
    match args.action {
        OobAction::Start {
            bind,
            port,
            public_url,
            foreground,
            json,
        } => {
            if foreground {
                return crate::oob::serve_forever(&project, &bind, port, public_url);
            }
            let state = crate::oob::start_daemon(&project, &bind, port, public_url.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&state)?);
            } else {
                println!("OOB collaborator running");
                println!("url    : {}", state.base_url);
                println!("bind   : {}:{}", state.bind, state.port);
                println!("pid    : {}", state.pid);
                println!("control: {}", state.control);
                println!("events : {}", crate::oob::events_path(&project).display());
            }
            Ok(())
        }
        OobAction::Stop => {
            if crate::oob::stop_daemon(&project)? {
                println!("OOB daemon stopped");
            } else {
                println!("OOB daemon is not running");
            }
            Ok(())
        }
        OobAction::Status { json } => {
            let Some(state) = crate::oob::daemon_state(&project)? else {
                if json {
                    println!("{}", serde_json::json!({"running": false}));
                } else {
                    println!("OOB daemon is not running");
                }
                return Ok(());
            };
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "running": true,
                        "state": state,
                    }))?
                );
            } else {
                println!("running: true");
                println!("url    : {}", state.base_url);
                println!("bind   : {}:{}", state.bind, state.port);
                println!("pid    : {}", state.pid);
                println!("started: {}", state.started);
            }
            Ok(())
        }
        OobAction::Poll { token, json } => {
            let events = crate::oob::daemon_events(&project, token.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
                return Ok(());
            }
            if events.is_empty() {
                println!("no interactions recorded");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = events
                .iter()
                .map(|event| {
                    vec![
                        event.ts.clone(),
                        event.token.clone(),
                        event.method.clone(),
                        truncate(&event.path, 48),
                        event.remote.clone(),
                    ]
                })
                .collect();
            util::table(&["Time", "Token", "Method", "Path", "Remote"], &rows);
            println!("\n{} interactions", events.len());
            Ok(())
        }
        OobAction::Clear => {
            crate::oob::clear_daemon_events(&project)?;
            println!("OOB interactions cleared");
            Ok(())
        }
        OobAction::Payload { token, base_url } => {
            let base = callback_base(&project, base_url.as_deref())?;
            let token = token.unwrap_or_else(|| util::random_token(16));
            println!("token: {token}");
            println!("url  : {base}/oob/{token}");
            Ok(())
        }
        OobAction::Url => {
            let base = callback_base(&project, None)?;
            println!("{base}");
            Ok(())
        }
    }
}

fn callback_base(project: &Project, explicit: Option<&str>) -> Result<String> {
    if let Some(url) = explicit {
        return Ok(url.trim_end_matches('/').to_string());
    }
    let Some(state) = crate::oob::daemon_state(project)? else {
        bail!("OOB daemon is not running; start it with `burpcli oob start` or pass --base-url");
    };
    Ok(state.base_url.trim_end_matches('/').to_string())
}

#[derive(Debug, Args)]
pub struct OobServeArgs {
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    #[arg(long)]
    pub public_url: Option<String>,
}

pub fn oob_serve(ctx: &Context, args: OobServeArgs) -> Result<()> {
    let project = ctx.project(true)?;
    crate::oob::serve_forever(&project, &args.bind, args.port, args.public_url)
}

#[derive(Debug, Args)]
pub struct ScopeArgs {
    #[command(subcommand)]
    pub action: ScopeAction,
}

#[derive(Debug, Subcommand)]
pub enum ScopeAction {
    /// List include and exclude patterns
    List {
        #[arg(long)]
        json: bool,
    },
    /// Add a pattern to the scope
    Add {
        pattern: String,
        #[arg(long)]
        exclude: bool,
    },
    /// Remove a pattern
    Remove { pattern: String },
    /// Clear the scope
    Clear,
    /// Check whether a URL is in scope
    Check { url: String },
}

pub fn scope(ctx: &Context, args: ScopeArgs) -> Result<()> {
    let mut project = ctx.project(true)?;
    match args.action {
        ScopeAction::List { json } => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "include": project.config.scope.include,
                        "exclude": project.config.scope.exclude,
                    }))?
                );
            } else {
                println!("include:");
                if project.config.scope.include.is_empty() {
                    println!("  (everything)");
                }
                for pattern in &project.config.scope.include {
                    println!("  {pattern}");
                }
                println!("exclude:");
                if project.config.scope.exclude.is_empty() {
                    println!("  (none)");
                }
                for pattern in &project.config.scope.exclude {
                    println!("  {pattern}");
                }
            }
            Ok(())
        }
        ScopeAction::Add { pattern, exclude } => {
            let mut scope = crate::scope::Scope::new(
                &project.config.scope.include,
                &project.config.scope.exclude,
            )?;
            if exclude {
                scope.add_exclude(&pattern)?;
            } else {
                scope.add_include(&pattern)?;
            }
            project.config.scope.include = scope.include;
            project.config.scope.exclude = scope.exclude;
            project.save_config()?;
            println!(
                "added {} pattern '{pattern}'",
                if exclude { "exclude" } else { "include" }
            );
            Ok(())
        }
        ScopeAction::Remove { pattern } => {
            let mut scope = crate::scope::Scope::new(
                &project.config.scope.include,
                &project.config.scope.exclude,
            )?;
            if !scope.remove(&pattern)? {
                bail!("pattern '{pattern}' is not in scope");
            }
            project.config.scope.include = scope.include;
            project.config.scope.exclude = scope.exclude;
            project.save_config()?;
            println!("removed '{pattern}'");
            Ok(())
        }
        ScopeAction::Clear => {
            project.config.scope.include.clear();
            project.config.scope.exclude.clear();
            project.save_config()?;
            println!("scope cleared");
            Ok(())
        }
        ScopeAction::Check { url } => {
            let scope = crate::scope::Scope::new(
                &project.config.scope.include,
                &project.config.scope.exclude,
            )?;
            if scope.allows_str(&url) {
                println!("in scope: {url}");
            } else {
                println!("out of scope: {url}");
            }
            Ok(())
        }
    }
}

#[derive(Debug, Args)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub action: ProjectAction,
}

#[derive(Debug, Subcommand)]
pub enum ProjectAction {
    /// Create a project directory
    Create {
        path: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
        /// Allow an existing directory / project file
        #[arg(long)]
        force: bool,
    },
    /// List registered projects
    List {
        #[arg(long)]
        json: bool,
    },
    /// Select the active project
    Use { path: PathBuf },
    /// Print the active project
    Current,
    /// Show project statistics and settings
    Info {
        #[arg(long)]
        json: bool,
    },
    /// Delete a project directory
    Delete {
        path: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Print the active project directory
    Path,
}

pub fn project(ctx: &Context, args: ProjectArgs) -> Result<()> {
    match args.action {
        ProjectAction::Create { path, name, force } => {
            let root = path.unwrap_or_else(default_project_root);
            let exists = root.join(crate::storage::PROJECT_FILE).exists();
            if exists && !force {
                bail!(
                    "project already exists at '{}' (use --force to rewrite its config)",
                    root.display()
                );
            }
            let name = name.unwrap_or_else(|| {
                root.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("project")
                    .trim_start_matches('.')
                    .to_string()
            });
            let project = Project::create(&root, &name)?;
            println!(
                "created project '{}' at {}",
                project.config.name,
                project.root.display()
            );
            println!(
                "select it with: burpcli project use {}",
                project.root.display()
            );
            Ok(())
        }
        ProjectAction::List { json } => {
            let global = config::load_global().unwrap_or_default();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "current": global.current_project,
                        "projects": global.projects,
                    }))?
                );
                return Ok(());
            }
            if global.projects.is_empty() {
                println!("no projects registered (use `burpcli project create` and `project use`)");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = global
                .projects
                .iter()
                .map(|reference| {
                    let current = global
                        .current_project
                        .as_deref()
                        .map(|path| path == reference.path)
                        .unwrap_or(false);
                    let exists = std::path::Path::new(&reference.path)
                        .join(crate::storage::PROJECT_FILE)
                        .exists();
                    vec![
                        reference.name.clone(),
                        truncate(&reference.path, 70),
                        if current { "yes" } else { "" }.into(),
                        if exists { "yes" } else { "missing" }.into(),
                    ]
                })
                .collect();
            util::table(&["Name", "Path", "Current", "Exists"], &rows);
            Ok(())
        }
        ProjectAction::Use { path } => {
            let project = Project::open(&path)?;
            let mut global = config::load_global().unwrap_or_default();
            let display = project.root.display().to_string();
            global
                .projects
                .retain(|reference| reference.path != display);
            global.projects.push(ProjectRef {
                name: project.config.name.clone(),
                path: display.clone(),
            });
            global.current_project = Some(display.clone());
            config::save_global(&global)?;
            println!("active project: {} ({})", project.config.name, display);
            Ok(())
        }
        ProjectAction::Current | ProjectAction::Path => {
            let project = ctx.project(false)?;
            println!("{}", project.root.display());
            Ok(())
        }
        ProjectAction::Info { json } => {
            let project = ctx.project(false)?;
            let history = project.history()?.count()?;
            let issues = project.issue_store()?.count()?;
            let sitemap = project.sitemap()?.len();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "name": project.config.name,
                        "root": project.root,
                        "created": project.config.created,
                        "history": history,
                        "issues": issues,
                        "sitemap": sitemap,
                        "scope": project.config.scope,
                        "proxy": {
                            "bind": project.config.proxy.bind,
                            "port": project.config.proxy.port,
                            "mitm": project.config.proxy.mitm,
                        },
                        "plugins": {
                            "enabled": project.config.plugins.enabled,
                            "dir": project.plugins_dir(),
                        },
                        "ca": project.ca_cert_path(),
                    }))?
                );
                return Ok(());
            }
            util::kv_block(&[
                ("name", project.config.name.clone()),
                ("root", project.root.display().to_string()),
                ("created", project.config.created.clone()),
                ("history", history.to_string()),
                ("issues", issues.to_string()),
                ("sitemap", sitemap.to_string()),
                (
                    "scope",
                    if project.config.scope.include.is_empty() {
                        "(everything)".into()
                    } else {
                        project.config.scope.include.join(", ")
                    },
                ),
                (
                    "proxy",
                    format!(
                        "{}:{} (mitm: {})",
                        project.config.proxy.bind,
                        project.config.proxy.port,
                        project.config.proxy.mitm
                    ),
                ),
                (
                    "plugins",
                    format!(
                        "{} ({})",
                        if project.config.plugins.enabled {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        project.plugins_dir().display()
                    ),
                ),
                ("CA", project.ca_cert_path().display().to_string()),
            ]);
            Ok(())
        }
        ProjectAction::Delete { path, force } => {
            let root = match path {
                Some(path) => path,
                None => ctx.project(false)?.root,
            };
            if !force {
                if !std::io::stdin().is_terminal() {
                    bail!("refusing to delete '{}' without --force", root.display());
                }
                if !util::confirm(
                    &format!("Delete project directory '{}'?", root.display()),
                    false,
                )? {
                    println!("cancelled");
                    return Ok(());
                }
            }
            std::fs::remove_dir_all(&root)
                .with_context(|| format!("cannot delete '{}'", root.display()))?;
            println!("deleted {}", root.display());
            Ok(())
        }
    }
}

fn default_project_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".burpcli")
}

#[derive(Debug, Args)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub action: SessionAction,
}

#[derive(Debug, Subcommand)]
pub enum SessionAction {
    /// Show cookies, headers, rules and macros
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Remove all cookies
    Clear,
    /// Add or replace a cookie
    SetCookie {
        domain: String,
        name: String,
        value: String,
        #[arg(long)]
        secure: bool,
    },
    /// Remove a cookie
    RemoveCookie { domain: String, name: String },
    /// Add a static header ("Name: value")
    Header { header: String },
    /// Remove a static header by name
    RemoveHeader { name: String },
    /// List static headers
    Headers,
    /// Add a match/replace rule
    Rule {
        pattern: String,
        replace: String,
        #[arg(long)]
        regex: bool,
        #[arg(long, default_value = "request")]
        direction: String,
        #[arg(long)]
        disabled: bool,
    },
    /// List match/replace rules
    Rules,
    /// Remove a rule by its 1-based index
    RemoveRule { index: usize },
    /// Enable or disable automatic session handling (on/off)
    Auto { value: String },
    /// Replay macro requests to refresh the session
    Login {
        #[arg(long, value_name = "PATH")]
        request: Vec<PathBuf>,
        #[arg(long)]
        insecure: bool,
        #[arg(long, default_value_t = 15_000)]
        timeout: u64,
    },
    /// Register a request file as a login macro
    MacroAdd { file: PathBuf },
    /// List login macros
    MacroList,
    /// Remove all login macros
    MacroClear,
}

pub fn session(ctx: &Context, args: SessionArgs) -> Result<()> {
    let mut project = ctx.project(true)?;
    match args.action {
        SessionAction::Show { json } => {
            let state = SessionState::from_project(&project)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "cookies": state.cookies.cookies,
                        "headers": project.config.session.headers,
                        "rules": project.config.session.rules,
                        "macros": project.config.session.macros,
                        "auto_apply": project.config.session.auto_apply,
                    }))?
                );
                return Ok(());
            }
            println!("cookies:");
            if state.cookies.cookies.is_empty() {
                println!("  (none)");
            } else {
                let rows: Vec<Vec<String>> = state
                    .cookies
                    .cookies
                    .iter()
                    .map(|cookie| {
                        vec![
                            cookie.name.clone(),
                            truncate(&cookie.value, 32),
                            cookie.domain.clone(),
                            cookie.path.clone(),
                            if cookie.secure { "yes" } else { "" }.into(),
                        ]
                    })
                    .collect();
                util::table(&["Name", "Value", "Domain", "Path", "Secure"], &rows);
            }
            println!("\nheaders:");
            if project.config.session.headers.is_empty() {
                println!("  (none)");
            }
            for header in &project.config.session.headers {
                println!("  {header}");
            }
            println!("\nrules:");
            if project.config.session.rules.is_empty() {
                println!("  (none)");
            }
            for (index, rule) in project.config.session.rules.iter().enumerate() {
                println!(
                    "  {}. [{}] '{}' -> '{}'{} {}",
                    index + 1,
                    rule.direction,
                    rule.pattern,
                    rule.replace,
                    if rule.regex { " (regex)" } else { "" },
                    if rule.enabled { "" } else { "(disabled)" }
                );
            }
            println!("\nmacros:");
            if project.config.session.macros.is_empty() {
                println!("  (none)");
            }
            for macro_path in &project.config.session.macros {
                println!("  {macro_path}");
            }
            println!("\nauto apply: {}", project.config.session.auto_apply);
            Ok(())
        }
        SessionAction::Clear => {
            let mut state = SessionState::from_project(&project)?;
            session::clear_session(&mut state);
            state.save_to_project(&project)?;
            println!("session cookies cleared");
            Ok(())
        }
        SessionAction::SetCookie {
            domain,
            name,
            value,
            secure,
        } => {
            let mut state = SessionState::from_project(&project)?;
            session::set_cookie(&mut state, &name, &value, &domain, secure);
            state.save_to_project(&project)?;
            println!("cookie '{name}' set for {domain}");
            Ok(())
        }
        SessionAction::RemoveCookie { domain, name } => {
            let mut state = SessionState::from_project(&project)?;
            let before = state.cookies.cookies.len();
            state
                .cookies
                .cookies
                .retain(|cookie| !(cookie.name == name && cookie.domain == domain));
            if state.cookies.cookies.len() == before {
                bail!("cookie '{name}' for {domain} not found");
            }
            state.save_to_project(&project)?;
            println!("cookie '{name}' removed");
            Ok(())
        }
        SessionAction::Header { header } => {
            let (name, value) = header
                .split_once(':')
                .ok_or_else(|| anyhow!("header must be in 'Name: value' form"))?;
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            project.config.session.headers.retain(|existing| {
                existing
                    .split_once(':')
                    .map(|(existing_name, _)| !existing_name.trim().eq_ignore_ascii_case(&name))
                    .unwrap_or(true)
            });
            project
                .config
                .session
                .headers
                .push(format!("{name}: {value}"));
            project.save_config()?;
            println!("header '{name}' set");
            Ok(())
        }
        SessionAction::RemoveHeader { name } => {
            let before = project.config.session.headers.len();
            project.config.session.headers.retain(|existing| {
                existing
                    .split_once(':')
                    .map(|(existing_name, _)| !existing_name.trim().eq_ignore_ascii_case(&name))
                    .unwrap_or(true)
            });
            if project.config.session.headers.len() == before {
                bail!("header '{name}' not found");
            }
            project.save_config()?;
            println!("header '{name}' removed");
            Ok(())
        }
        SessionAction::Headers => {
            if project.config.session.headers.is_empty() {
                println!("no static headers configured");
            } else {
                for header in &project.config.session.headers {
                    println!("{header}");
                }
            }
            Ok(())
        }
        SessionAction::Rule {
            pattern,
            replace,
            regex,
            direction,
            disabled,
        } => {
            if regex {
                regex::Regex::new(&pattern)
                    .with_context(|| format!("invalid regex '{pattern}'"))?;
            }
            if !["request", "response", "both"].contains(&direction.to_ascii_lowercase().as_str()) {
                bail!("direction must be request, response or both");
            }
            project.config.session.rules.push(Rule {
                pattern,
                replace,
                regex,
                enabled: !disabled,
                direction: direction.to_ascii_lowercase(),
            });
            project.save_config()?;
            println!("rule added");
            Ok(())
        }
        SessionAction::Rules => {
            if project.config.session.rules.is_empty() {
                println!("no rules configured");
                return Ok(());
            }
            let rows: Vec<Vec<String>> = project
                .config
                .session
                .rules
                .iter()
                .enumerate()
                .map(|(index, rule)| {
                    vec![
                        (index + 1).to_string(),
                        rule.direction.clone(),
                        truncate(&rule.pattern, 40),
                        truncate(&rule.replace, 40),
                        if rule.regex { "yes" } else { "" }.into(),
                        if rule.enabled { "yes" } else { "no" }.into(),
                    ]
                })
                .collect();
            util::table(
                &["#", "Direction", "Match", "Replace", "Regex", "Enabled"],
                &rows,
            );
            Ok(())
        }
        SessionAction::RemoveRule { index } => {
            if index == 0 || index > project.config.session.rules.len() {
                bail!(
                    "rule {index} does not exist (1..={})",
                    project.config.session.rules.len()
                );
            }
            project.config.session.rules.remove(index - 1);
            project.save_config()?;
            println!("rule {index} removed");
            Ok(())
        }
        SessionAction::Auto { value } => {
            let enabled = match value.to_ascii_lowercase().as_str() {
                "on" | "true" | "yes" | "enable" => true,
                "off" | "false" | "no" | "disable" => false,
                other => bail!("unknown value '{other}' (use on or off)"),
            };
            project.config.session.auto_apply = enabled;
            project.save_config()?;
            println!(
                "auto session handling: {}",
                if enabled { "on" } else { "off" }
            );
            Ok(())
        }
        SessionAction::Login {
            request,
            insecure,
            timeout,
        } => {
            let mut macros = request;
            if macros.is_empty() {
                macros = project
                    .config
                    .session
                    .macros
                    .iter()
                    .map(PathBuf::from)
                    .collect();
            }
            if macros.is_empty() {
                bail!(
                    "no macros: pass --request <file> or add one with `burpcli session macro-add`"
                );
            }
            let session_client = ctx.session_client(&project, insecure, timeout, 0, None)?;
            for path in &macros {
                let raw = std::fs::read(path)
                    .with_context(|| format!("cannot read '{}'", path.display()))?;
                let mut request = crate::intruder::template_from_raw(&raw)?;
                session::apply_headers(&mut request, &project.config.session.headers);
                session::apply_request_rules(&mut request, &project.config.session.rules)?;
                let response = client::send(&request, &session_client.options)
                    .with_context(|| format!("macro '{}' failed", path.display()))?;
                println!(
                    "{} -> {} ({} bytes)",
                    path.display(),
                    response.response.status,
                    response.response.body.len()
                );
            }
            session_client.save(&project)?;
            println!("session updated");
            Ok(())
        }
        SessionAction::MacroAdd { file } => {
            if !file.exists() {
                bail!("request file '{}' does not exist", file.display());
            }
            let display = file.display().to_string();
            if !project.config.session.macros.contains(&display) {
                project.config.session.macros.push(display.clone());
                project.save_config()?;
            }
            println!("macro added: {display}");
            Ok(())
        }
        SessionAction::MacroList => {
            if project.config.session.macros.is_empty() {
                println!("no macros configured");
            } else {
                for macro_path in &project.config.session.macros {
                    println!("{macro_path}");
                }
            }
            Ok(())
        }
        SessionAction::MacroClear => {
            project.config.session.macros.clear();
            project.save_config()?;
            println!("macros cleared");
            Ok(())
        }
    }
}

#[derive(Debug, Args)]
pub struct PluginArgs {
    #[command(subcommand)]
    pub action: PluginAction,
}

#[derive(Debug, Subcommand)]
pub enum PluginAction {
    /// List installed plugins
    List {
        #[arg(long)]
        json: bool,
    },
    /// Install the built-in demo plugin
    InstallDemo,
    /// Remove a plugin by name
    Remove { name: String },
    /// Start a plugin and run a test request through it
    Test { name: Option<String> },
    /// Enable plugins for this project
    Enable,
    /// Disable plugins for this project
    Disable,
}

pub fn plugin(ctx: &Context, args: PluginArgs) -> Result<()> {
    let mut project = ctx.project(true)?;
    let timeout = Duration::from_millis(project.config.plugins.timeout_ms);
    match args.action {
        PluginAction::List { json } => {
            let manager = PluginManager::load(&project.plugins_dir(), timeout)?;
            if json {
                let manifests: Vec<&PluginManifest> = manager
                    .plugins()
                    .iter()
                    .map(|plugin| &plugin.manifest)
                    .collect();
                println!("{}", serde_json::to_string_pretty(&manifests)?);
                return Ok(());
            }
            if manager.is_empty() {
                println!(
                    "no plugins installed in {} (try `burpcli plugin install-demo`)",
                    project.plugins_dir().display()
                );
                return Ok(());
            }
            let rows: Vec<Vec<String>> = manager
                .plugins()
                .iter()
                .map(|plugin| {
                    vec![
                        plugin.manifest.name.clone(),
                        plugin.manifest.hooks.join(","),
                        if plugin.manifest.enabled { "yes" } else { "no" }.into(),
                        truncate(&plugin.manifest.command, 48),
                        truncate(&plugin.manifest.description, 40),
                    ]
                })
                .collect();
            util::table(
                &["Name", "Hooks", "Enabled", "Command", "Description"],
                &rows,
            );
            println!(
                "\nplugins globally {}; {} plugin(s) in {}",
                if project.config.plugins.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                manager.plugins().len(),
                project.plugins_dir().display()
            );
            Ok(())
        }
        PluginAction::InstallDemo => {
            let path = plugins::install_demo(&project)?;
            project.config.plugins.enabled = true;
            project.save_config()?;
            println!("demo plugin installed at {}", path.display());
            println!("plugins enabled for project '{}'", project.config.name);
            Ok(())
        }
        PluginAction::Remove { name } => {
            if plugins::remove_plugin(&project.plugins_dir(), &name)? {
                println!("plugin '{name}' removed");
            } else {
                bail!("plugin '{name}' not found");
            }
            Ok(())
        }
        PluginAction::Test { name } => {
            let manager = PluginManager::load(&project.plugins_dir(), timeout)?;
            if manager.is_empty() {
                bail!("no plugins installed");
            }
            let targets: Vec<_> = manager
                .plugins()
                .iter()
                .filter(|plugin| {
                    name.as_deref()
                        .map(|name| plugin.manifest.name == name)
                        .unwrap_or(true)
                })
                .collect();
            if targets.is_empty() {
                bail!("plugin '{}' not found", name.unwrap_or_default());
            }
            for plugin in targets {
                println!("testing {}", plugin.manifest.name);
                match plugins::test_plugin(plugin) {
                    Ok(output) => {
                        println!("  ok: {}", serde_json::to_string(&output)?);
                    }
                    Err(error) => {
                        println!("  failed: {error:#}");
                    }
                }
            }
            Ok(())
        }
        PluginAction::Enable => {
            project.config.plugins.enabled = true;
            project.save_config()?;
            println!("plugins enabled for project '{}'", project.config.name);
            Ok(())
        }
        PluginAction::Disable => {
            project.config.plugins.enabled = false;
            project.save_config()?;
            println!("plugins disabled for project '{}'", project.config.name);
            Ok(())
        }
    }
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the global configuration
    Show,
    /// Print the configuration file path
    Path,
    /// Read one key
    Get { key: String },
    /// Set one key
    Set { key: String, value: String },
    /// Remove an optional key
    Unset { key: String },
    /// Reset the global configuration
    Reset,
}

pub fn config(ctx: &Context, args: ConfigArgs) -> Result<()> {
    let _ = ctx;
    match args.action {
        ConfigAction::Show => {
            let global = config::load_global().unwrap_or_default();
            print!("{}", toml::to_string_pretty(&global)?);
            Ok(())
        }
        ConfigAction::Path => {
            println!("{}", config::config_path().display());
            Ok(())
        }
        ConfigAction::Get { key } => {
            let global = config::load_global().unwrap_or_default();
            println!("{}", get_key(&global, &key)?);
            Ok(())
        }
        ConfigAction::Set { key, value } => {
            let mut global = config::load_global().unwrap_or_default();
            set_key(&mut global, &key, &value)?;
            config::save_global(&global)?;
            println!("{key} = {value}");
            Ok(())
        }
        ConfigAction::Unset { key } => {
            let mut global = config::load_global().unwrap_or_default();
            unset_key(&mut global, &key)?;
            config::save_global(&global)?;
            println!("{key} unset");
            Ok(())
        }
        ConfigAction::Reset => {
            config::save_global(&GlobalConfig::default())?;
            println!("global configuration reset");
            Ok(())
        }
    }
}

const CONFIG_KEYS: &[&str] = &[
    "color",
    "current_project",
    "editor",
    "user_agent",
    "default_timeout_ms",
    "default_concurrency",
];

fn get_key(global: &GlobalConfig, key: &str) -> Result<String> {
    Ok(match key {
        "color" => global.color.clone().unwrap_or_default(),
        "current_project" => global.current_project.clone().unwrap_or_default(),
        "editor" => global.editor.clone().unwrap_or_default(),
        "user_agent" => global.user_agent.clone().unwrap_or_default(),
        "default_timeout_ms" => global
            .default_timeout_ms
            .map(|value| value.to_string())
            .unwrap_or_default(),
        "default_concurrency" => global
            .default_concurrency
            .map(|value| value.to_string())
            .unwrap_or_default(),
        other => bail!(
            "unknown config key '{other}' (available: {})",
            CONFIG_KEYS.join(", ")
        ),
    })
}

fn set_key(global: &mut GlobalConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "color" => {
            if !["auto", "always", "never"].contains(&value.to_ascii_lowercase().as_str()) {
                bail!("color must be auto, always or never");
            }
            global.color = Some(value.to_ascii_lowercase());
        }
        "current_project" => global.current_project = Some(value.to_string()),
        "editor" => global.editor = Some(value.to_string()),
        "user_agent" => global.user_agent = Some(value.to_string()),
        "default_timeout_ms" => {
            global.default_timeout_ms = Some(
                value
                    .parse::<u64>()
                    .with_context(|| format!("invalid timeout '{value}'"))?,
            );
        }
        "default_concurrency" => {
            global.default_concurrency = Some(
                value
                    .parse::<usize>()
                    .with_context(|| format!("invalid concurrency '{value}'"))?,
            );
        }
        other => bail!(
            "unknown config key '{other}' (available: {})",
            CONFIG_KEYS.join(", ")
        ),
    }
    Ok(())
}

fn unset_key(global: &mut GlobalConfig, key: &str) -> Result<()> {
    match key {
        "color" => global.color = None,
        "current_project" => global.current_project = None,
        "editor" => global.editor = None,
        "user_agent" => global.user_agent = None,
        "default_timeout_ms" => global.default_timeout_ms = None,
        "default_concurrency" => global.default_concurrency = None,
        other => bail!(
            "unknown config key '{other}' (available: {})",
            CONFIG_KEYS.join(", ")
        ),
    }
    Ok(())
}
