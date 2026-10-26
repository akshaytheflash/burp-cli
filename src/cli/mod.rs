//! Command-line interface.
//!
//! The CLI is split into four command groups that share a small [`Context`]:
//! request tools, scanning tools, administrative commands and encoding tools.

pub mod admin;
pub mod requests;
pub mod scanning;
pub mod tools;

use crate::http::{ClientOptions, CookieJar, TlsOptions};
use crate::session::SessionState;
use crate::storage::Project;
use crate::util;
use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "burpcli",
    version,
    about = "Burp Suite-style HTTP security testing toolkit for the terminal",
    long_about = "A self-contained HTTP interception, scanning and request-manipulation toolkit.\n\
                  Use `burpcli <command> --help` for details on any command.",
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Project directory (defaults to $BURPCLI_PROJECT, the selected project, or ./.burpcli)
    #[arg(long, global = true, env = "BURPCLI_PROJECT", value_name = "DIR")]
    pub project: Option<PathBuf>,

    /// Colour output: auto, always or never
    #[arg(long, global = true, default_value = "auto", value_parser = ["auto", "always", "never"])]
    pub color: String,

    /// Verbose diagnostics on stderr
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Suppress progress output
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the intercepting proxy
    Proxy(admin::ProxyArgs),
    /// Inspect or export the interception certificate authority
    Ca(admin::CaArgs),
    /// Browse and edit proxy history
    History(requests::HistoryArgs),
    /// Send a single request (optionally from a file or history)
    Repeater(requests::RepeaterArgs),
    /// Run an automated payload attack
    Intruder(requests::IntruderArgs),
    /// Scan a URL or saved request for vulnerabilities
    #[command(visible_alias = "scanner")]
    Scan(scanning::ScanArgs),
    /// Crawl a target and populate the sitemap
    Spider(scanning::SpiderArgs),
    /// Inspect the stored sitemap
    Sitemap(scanning::SitemapArgs),
    /// Encode, decode and analyse data
    Decoder(tools::DecoderArgs),
    /// Diff two inputs
    Comparer(tools::ComparerArgs),
    /// Analyse token randomness
    Sequencer(tools::SequencerArgs),
    /// Manage the out-of-band interaction server
    Oob(admin::OobArgs),
    /// Manage target scope
    Scope(admin::ScopeArgs),
    /// Create, select and inspect projects
    Project(admin::ProjectArgs),
    /// Manage cookies, headers and match/replace rules
    Session(admin::SessionArgs),
    /// Manage external plugins
    Plugin(admin::PluginArgs),
    /// Generate reports from stored findings
    Report(scanning::ReportArgs),
    /// Read or update global configuration
    Config(admin::ConfigArgs),

    /// Internal: run the OOB daemon in the foreground
    #[command(name = "__oob-serve", hide = true)]
    OobServe(admin::OobServeArgs),

    /// Internal: demo plugin implementing the JSON-lines protocol
    #[command(name = "__plugin-demo", hide = true)]
    PluginDemo,
}

#[derive(Clone, Debug)]
pub struct Context {
    pub project: Option<PathBuf>,
    pub verbose: bool,
    pub quiet: bool,
}

impl Context {
    pub fn project(&self, allow_create: bool) -> Result<Project> {
        Project::resolve(self.project.clone(), allow_create)
    }

    /// A client with an attached session cookie jar.
    pub fn session_client(
        &self,
        project: &Project,
        insecure: bool,
        timeout_ms: u64,
        follow: usize,
        user_agent: Option<&str>,
    ) -> Result<SessionClient> {
        SessionClient::new(project, insecure, timeout_ms, follow, user_agent)
    }

    pub fn verbose_log(&self, message: impl AsRef<str>) {
        if self.verbose {
            eprintln!("[*] {}", message.as_ref());
        }
    }
}

/// A session-aware HTTP client: static headers/rules are applied by the caller
/// while the cookie jar is shared with the HTTP client.
pub struct SessionClient {
    pub state: SessionState,
    pub jar: Arc<Mutex<CookieJar>>,
    pub options: ClientOptions,
}

impl SessionClient {
    pub fn new(
        project: &Project,
        insecure: bool,
        timeout_ms: u64,
        follow: usize,
        user_agent: Option<&str>,
    ) -> Result<Self> {
        let state = SessionState::from_project(project)?;
        let jar = Arc::new(Mutex::new(state.cookies.clone()));
        let mut options = ClientOptions {
            timeout: Duration::from_millis(timeout_ms),
            follow_redirects: follow,
            tls: TlsOptions {
                insecure,
                ..Default::default()
            },
            max_body: project.config.scan.max_body,
            cookie_jar: Some(jar.clone()),
            user_agent: user_agent
                .map(str::to_string)
                .or_else(|| project.config.scan.user_agent.clone()),
            ..ClientOptions::default()
        };
        options.connect_timeout = options.timeout.min(Duration::from_secs(10));
        Ok(Self {
            state,
            jar,
            options,
        })
    }

    /// Apply configured headers, cookies and rules to an outgoing request.
    pub fn prepare(&self, request: &mut crate::http::Request, project: &Project) -> Result<()> {
        crate::session::apply_session(request, &project.config, &self.state)?;
        Ok(())
    }

    pub fn save(mut self, project: &Project) -> Result<()> {
        self.state.cookies = self.jar.lock().unwrap_or_else(|e| e.into_inner()).clone();
        self.state.save_to_project(project)
    }

    pub fn snapshot_cookies(&mut self) {
        self.state.cookies = self.jar.lock().unwrap_or_else(|e| e.into_inner()).clone();
    }
}

/// Install a one-shot Ctrl-C handler and block until it fires.
pub fn wait_for_interrupt() -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let flag = Arc::new(AtomicBool::new(false));
    let handler_flag = flag.clone();
    ctrlc::set_handler(move || {
        handler_flag.store(true, Ordering::SeqCst);
    })
    .context("cannot install Ctrl-C handler")?;
    while !flag.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    util::init_color(&cli.color);
    let context = Context {
        project: cli.project,
        verbose: cli.verbose,
        quiet: cli.quiet,
    };
    match cli.command {
        Command::Proxy(args) => admin::proxy(&context, args),
        Command::Ca(args) => admin::ca(&context, args),
        Command::History(args) => requests::history(&context, args),
        Command::Repeater(args) => requests::repeater(&context, args),
        Command::Intruder(args) => requests::intruder(&context, args),
        Command::Scan(args) => scanning::scan(&context, args),
        Command::Spider(args) => scanning::spider(&context, args),
        Command::Sitemap(args) => scanning::sitemap(&context, args),
        Command::Decoder(args) => tools::decoder(&context, args),
        Command::Comparer(args) => tools::comparer(&context, args),
        Command::Sequencer(args) => tools::sequencer(&context, args),
        Command::Oob(args) => admin::oob(&context, args),
        Command::Scope(args) => admin::scope(&context, args),
        Command::Project(args) => admin::project(&context, args),
        Command::Session(args) => admin::session(&context, args),
        Command::Plugin(args) => admin::plugin(&context, args),
        Command::Report(args) => scanning::report(&context, args),
        Command::Config(args) => admin::config(&context, args),
        Command::OobServe(args) => admin::oob_serve(&context, args),
        Command::PluginDemo => crate::plugins::demo_plugin(),
    }
}
