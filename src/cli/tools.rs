//! Encoding, diffing and randomness tools.

use super::Context;
use crate::comparer::{self, DiffMode, DiffOptions};
use crate::decoder;
use crate::sequencer::{self, Extraction, SampleOptions};
use crate::util::{self, format_duration};
use anyhow::{anyhow, bail, Context as _, Result};
use clap::Args;
use serde_json::Value;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct DecoderArgs {
    /// Input text (use --file or --stdin for larger data)
    pub input: Option<String>,
    #[arg(long, value_name = "PATH", conflicts_with = "stdin")]
    pub file: Option<PathBuf>,
    #[arg(long, conflicts_with = "file")]
    pub stdin: bool,
    /// Codec(s) to apply in order
    #[arg(long = "codec", short = 'c')]
    pub codecs: Vec<String>,
    /// Encode instead of decode
    #[arg(long)]
    pub encode: bool,
    /// Repeatedly detect and apply common encodings
    #[arg(long)]
    pub smart: bool,
    /// Identify likely encodings without transforming the input
    #[arg(long)]
    pub identify: bool,
    /// Decode a JWT
    #[arg(long)]
    pub jwt: bool,
    /// Re-sign a JWT with HS256/HS384/HS512 (requires --secret)
    #[arg(long, value_name = "ALG")]
    pub jwt_sign: Option<String>,
    /// Convert a JWT to alg=none
    #[arg(long)]
    pub jwt_none: bool,
    #[arg(long, value_name = "SECRET")]
    pub secret: Option<String>,
    /// Set a top-level JWT claim when re-signing (repeatable, KEY=VALUE)
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub set: Vec<String>,
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
    /// List supported codecs
    #[arg(long)]
    pub list: bool,
}

pub fn decoder(ctx: &Context, args: DecoderArgs) -> Result<()> {
    let _ = ctx;
    if args.list {
        println!("{}", decoder::codec_help());
        return Ok(());
    }
    let input = read_input(args.input.as_deref(), args.file.as_deref(), args.stdin)?;

    if args.identify {
        let guesses = decoder::identify(&input);
        if guesses.is_empty() {
            println!("no common encoding detected");
        } else {
            for guess in guesses {
                println!("{guess}");
            }
        }
        return Ok(());
    }

    if args.jwt {
        let text = std::str::from_utf8(&input).context("JWT input must be UTF-8")?;
        let parts = decoder::decode_jwt(text.trim())?;
        println!("{}", parts.pretty());
        if let Some(algorithm) = parts.algorithm() {
            println!("\nalgorithm: {algorithm}");
        }
        return Ok(());
    }

    if let Some(algorithm) = &args.jwt_sign {
        let text = std::str::from_utf8(&input).context("JWT input must be UTF-8")?;
        let mut parts = decoder::decode_jwt(text.trim())?;
        let Some(object) = parts.payload.as_object_mut() else {
            bail!("JWT payload is not a JSON object");
        };
        for assignment in &args.set {
            let (key, raw) = assignment
                .split_once('=')
                .ok_or_else(|| anyhow!("--set needs KEY=VALUE"))?;
            let value = serde_json::from_str::<Value>(raw)
                .unwrap_or_else(|_| Value::String(raw.to_string()));
            object.insert(key.trim().to_string(), value);
        }
        let secret = args.secret.unwrap_or_default();
        let token = decoder::jwt_sign(&parts.header, &parts.payload, &secret, algorithm)?;
        println!("{token}");
        return Ok(());
    }

    if args.jwt_none {
        let text = std::str::from_utf8(&input).context("JWT input must be UTF-8")?;
        let token = decoder::jwt_none(text.trim())?;
        println!("{token}");
        return Ok(());
    }

    if args.smart || args.codecs.is_empty() {
        let (decoded, applied) = decoder::smart_decode(&input);
        if !applied.is_empty() {
            eprintln!("[*] applied: {}", applied.join(" -> "));
        } else {
            eprintln!("[*] no transformation applied");
        }
        emit(&decoded, args.output.as_deref())?;
        return Ok(());
    }

    if !args.encode
        && args
            .codecs
            .iter()
            .any(|codec| codec.eq_ignore_ascii_case("jwt"))
    {
        let text = std::str::from_utf8(&input).context("JWT input must be UTF-8")?;
        println!("{}", decoder::decode_jwt(text.trim())?.pretty());
        return Ok(());
    }
    let output = decoder::transform(&input, &args.codecs, args.encode)?;
    emit(&output, args.output.as_deref())?;
    Ok(())
}

fn read_input(
    input: Option<&str>,
    file: Option<&std::path::Path>,
    from_stdin: bool,
) -> Result<Vec<u8>> {
    if let Some(path) = file {
        return std::fs::read(path).with_context(|| format!("cannot read '{}'", path.display()));
    }
    if from_stdin || (!std::io::stdin().is_terminal() && input.is_none()) {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data)?;
        return Ok(data);
    }
    let Some(input) = input else {
        bail!("no input: pass text, --file <path> or --stdin");
    };
    if let Some(path) = input.strip_prefix('@') {
        return std::fs::read(path).with_context(|| format!("cannot read '{}'", path));
    }
    Ok(input.as_bytes().to_vec())
}

fn emit(data: &[u8], output: Option<&std::path::Path>) -> Result<()> {
    if let Some(path) = output {
        crate::config::atomic_write(path, data)
            .with_context(|| format!("cannot write '{}'", path.display()))?;
        println!("written {} bytes to {}", data.len(), path.display());
        return Ok(());
    }
    let mut stdout = std::io::stdout();
    if let Ok(text) = std::str::from_utf8(data) {
        if text
            .chars()
            .all(|ch| !ch.is_control() || ch == '\n' || ch == '\r' || ch == '\t')
        {
            stdout.write_all(text.as_bytes())?;
            if !text.ends_with('\n') {
                stdout.write_all(b"\n")?;
            }
            stdout.flush()?;
            return Ok(());
        }
    }
    stdout.write_all(util::display_bytes(data).as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

#[derive(Debug, Args)]
pub struct ComparerArgs {
    /// First input: text, file path or @file
    pub a: Option<String>,
    /// Second input: text, file path or @file
    pub b: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub file_a: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub file_b: Option<PathBuf>,
    #[arg(long, default_value = "lines")]
    pub mode: String,
    #[arg(long, default_value_t = 3)]
    pub context: usize,
    #[arg(long)]
    pub json: bool,
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

pub fn comparer(ctx: &Context, args: ComparerArgs) -> Result<()> {
    let _ = ctx;
    let a = match args.file_a {
        Some(path) => {
            std::fs::read(&path).with_context(|| format!("cannot read '{}'", path.display()))?
        }
        None => read_side(
            args.a
                .as_deref()
                .ok_or_else(|| anyhow!("give an input or --file-a"))?,
        )?,
    };
    let b_value = match (&args.b, &args.file_b) {
        (_, Some(_)) => None,
        (Some(value), None) => Some(value.clone()),
        (None, None) => bail!("give a second input or --file-b"),
    };
    let b = match args.file_b {
        Some(path) => {
            std::fs::read(&path).with_context(|| format!("cannot read '{}'", path.display()))?
        }
        None => read_side(b_value.as_deref().unwrap_or(""))?,
    };
    let mode = DiffMode::parse(&args.mode)?;
    let options = DiffOptions {
        mode,
        context: args.context,
        color: !args.json && util::color_enabled(),
    };
    let result = comparer::compare(&a, &b, &options);
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "added": result.added,
                "removed": result.removed,
                "unchanged": result.unchanged,
                "similarity": result.similarity,
                "first_difference": result.first_difference,
                "diff": util::strip_ansi(&result.output),
            }))?
        );
        return Ok(());
    }
    match args.output {
        Some(path) => {
            crate::config::atomic_write(&path, util::strip_ansi(&result.output).as_bytes())?;
            println!("diff written to {}", path.display());
        }
        None => comparer::print_result(&result, "input A", "input B"),
    }
    Ok(())
}

fn read_side(value: &str) -> Result<Vec<u8>> {
    if value == "-" {
        let mut data = Vec::new();
        std::io::stdin().read_to_end(&mut data)?;
        return Ok(data);
    }
    if let Some(path) = value.strip_prefix('@') {
        return std::fs::read(path).with_context(|| format!("cannot read '{path}'"));
    }
    comparer::read_input(value)
}

#[derive(Debug, Args)]
pub struct SequencerArgs {
    /// URL that issues a token
    #[arg(long, conflicts_with = "file")]
    pub url: Option<String>,
    /// File with one token per line
    #[arg(long, conflicts_with = "url")]
    pub file: Option<PathBuf>,
    #[arg(long, default_value_t = 100)]
    pub count: usize,
    /// Token extraction: cookie:NAME, header:NAME, body:REGEX or location
    #[arg(long, default_value = "cookie:session")]
    pub extract: String,
    #[arg(long, default_value_t = 0)]
    pub delay: u64,
    #[arg(long)]
    pub insecure: bool,
    #[arg(long, default_value_t = 15_000)]
    pub timeout: u64,
    #[arg(long)]
    pub user_agent: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub save_samples: Option<PathBuf>,
    #[arg(long)]
    pub json: bool,
}

pub fn sequencer(ctx: &Context, args: SequencerArgs) -> Result<()> {
    let samples = if let Some(path) = &args.file {
        std::fs::read_to_string(path)
            .with_context(|| format!("cannot read '{}'", path.display()))?
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
    } else if let Some(url) = &args.url {
        let project = ctx.project(true)?;
        let extract = Extraction::parse(&args.extract)?;
        let session = ctx.session_client(
            &project,
            args.insecure,
            args.timeout,
            0,
            args.user_agent.as_deref(),
        )?;
        let options = SampleOptions {
            url: url.clone(),
            count: args.count,
            extraction: extract,
            delay: std::time::Duration::from_millis(args.delay),
            client: session.options.clone(),
        };
        let samples = sequencer::fetch_samples(&options)?;
        session.save(&project)?;
        samples
    } else {
        bail!("use --url to sample tokens or --file with one token per line");
    };

    if samples.len() < 2 {
        bail!("need at least two samples for meaningful analysis");
    }
    if let Some(path) = &args.save_samples {
        crate::config::atomic_write(path, samples.join("\n").as_bytes())?;
        println!("samples saved to {}", path.display());
    }
    let analysis = sequencer::analyze(&samples);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&analysis)?);
        return Ok(());
    }
    println!("{}", util::bold(&analysis.verdict));
    println!();
    util::kv_block(&[
        ("samples", analysis.count.to_string()),
        ("unique", analysis.unique.to_string()),
        (
            "length",
            if analysis.min_length == analysis.max_length {
                analysis.min_length.to_string()
            } else {
                format!("{}..{}", analysis.min_length, analysis.max_length)
            },
        ),
        ("charset", analysis.charset.to_string()),
        (
            "entropy/char",
            format!("{:.3} bits", analysis.entropy_bits_per_char),
        ),
        (
            "total entropy",
            format!("{:.1} bits", analysis.total_entropy_bits),
        ),
        ("chi-square p", format!("{:.4}", analysis.chi_square_p)),
        ("monobit p", format!("{:.4}", analysis.monobit_p)),
        ("runs p", format!("{:.4}", analysis.runs_p)),
        ("longest run", analysis.longest_run.to_string()),
        (
            "serial correlation",
            format!("{:.4}", analysis.serial_correlation),
        ),
        ("sequential", analysis.sequential.to_string()),
    ]);
    if !analysis.position_entropy.is_empty() {
        let shown = analysis.position_entropy.len().min(24);
        println!();
        println!("per-position entropy (first {shown}):");
        let values: Vec<String> = analysis
            .position_entropy
            .iter()
            .take(shown)
            .map(|value| format!("{value:.2}"))
            .collect();
        println!("  {}", values.join(" "));
    }
    if !analysis.notes.is_empty() {
        println!();
        for note in &analysis.notes {
            println!("- {note}");
        }
    }
    if !args.delay.eq(&0) {
        eprintln!(
            "[*] sampling delay {}",
            format_duration(std::time::Duration::from_millis(args.delay))
        );
    }
    Ok(())
}
