//! Intruder: automated request generation with payload positions.
//!
//! Positions are marked with `§` (U+00A7) in the request target, header values
//! or body, exactly like Burp's Intruder markers:
//!
//! ```text
//! POST /login HTTP/1.1
//! Host: example.com
//!
//! user=§admin§&pass=§secret§
//! ```
//!
//! Four attack types are supported: sniper, battering ram, pitchfork and
//! cluster bomb. Results can be filtered with grep patterns and enriched with
//! regex extractions (CSRF tokens, session IDs, ...).

use crate::http::client::{self, ClientOptions};
use crate::http::{Request, Response};
use crate::util::{format_duration, wildcard_contains};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MARKER: char = '§';
const MARKER_BYTES: [u8; 2] = [0xC2, 0xA7];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackType {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

impl AttackType {
    pub fn parse(value: &str) -> Result<Self> {
        match value
            .to_ascii_lowercase()
            .replace([' ', '_'], "-")
            .as_str()
        {
            "sniper" => Ok(Self::Sniper),
            "battering-ram" | "batteringram" | "ram" => Ok(Self::BatteringRam),
            "pitchfork" => Ok(Self::Pitchfork),
            "cluster-bomb" | "clusterbomb" | "cluster" => Ok(Self::ClusterBomb),
            other => bail!(
                "unknown attack type '{other}' (use sniper, battering-ram, pitchfork or cluster-bomb)"
            ),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Sniper => "sniper",
            Self::BatteringRam => "battering-ram",
            Self::Pitchfork => "pitchfork",
            Self::ClusterBomb => "cluster-bomb",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Processor {
    Upper,
    Lower,
    Trim,
    UrlEncode,
    Base64,
    Hex,
    Md5,
    Sha1,
    Sha256,
    Prefix(String),
    Suffix(String),
    Replace(String, String),
    RegexReplace(String, String),
}

impl Processor {
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if let Some(value) = spec.strip_prefix("prefix:") {
            return Ok(Self::Prefix(value.to_string()));
        }
        if let Some(value) = spec.strip_prefix("suffix:") {
            return Ok(Self::Suffix(value.to_string()));
        }
        if let Some(value) = spec.strip_prefix("replace:") {
            let (from, to) = value
                .split_once("=>")
                .ok_or_else(|| anyhow!("replace processor needs 'from=>to'"))?;
            return Ok(Self::Replace(from.to_string(), to.to_string()));
        }
        if let Some(value) = spec.strip_prefix("regex:") {
            let (pattern, to) = value
                .split_once("=>")
                .ok_or_else(|| anyhow!("regex processor needs 'pattern=>replacement'"))?;
            regex::Regex::new(pattern)
                .with_context(|| format!("invalid processor regex '{pattern}'"))?;
            return Ok(Self::RegexReplace(pattern.to_string(), to.to_string()));
        }
        match spec.to_ascii_lowercase().as_str() {
            "upper" | "uppercase" => Ok(Self::Upper),
            "lower" | "lowercase" => Ok(Self::Lower),
            "trim" => Ok(Self::Trim),
            "url" | "urlencode" | "url-encode" => Ok(Self::UrlEncode),
            "base64" => Ok(Self::Base64),
            "hex" => Ok(Self::Hex),
            "md5" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            other => bail!("unknown payload processor '{other}'"),
        }
    }

    pub fn apply(&self, value: &str) -> Result<String> {
        Ok(match self {
            Self::Upper => value.to_uppercase(),
            Self::Lower => value.to_lowercase(),
            Self::Trim => value.trim().to_string(),
            Self::UrlEncode => {
                percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC)
                    .to_string()
            }
            Self::Base64 => crate::util::b64_encode(value.as_bytes()),
            Self::Hex => hex::encode(value.as_bytes()),
            Self::Md5 => {
                use md5::Md5;
                use sha2::Digest;
                let mut hasher = Md5::new();
                hasher.update(value.as_bytes());
                hex::encode(hasher.finalize())
            }
            Self::Sha1 => {
                use sha1::Sha1;
                use sha2::Digest;
                let mut hasher = Sha1::new();
                hasher.update(value.as_bytes());
                hex::encode(hasher.finalize())
            }
            Self::Sha256 => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(value.as_bytes());
                hex::encode(hasher.finalize())
            }
            Self::Prefix(prefix) => format!("{prefix}{value}"),
            Self::Suffix(suffix) => format!("{value}{suffix}"),
            Self::Replace(from, to) => value.replace(from, to),
            Self::RegexReplace(pattern, replacement) => {
                let re = regex::Regex::new(pattern)
                    .with_context(|| format!("invalid processor regex '{pattern}'"))?;
                re.replace_all(value, replacement.as_str()).into_owned()
            }
        })
    }
}

#[derive(Clone, Debug)]
pub enum PayloadSource {
    List(Vec<String>),
    File(PathBuf),
    Numbers {
        start: i64,
        end: i64,
        step: i64,
        width: usize,
        hex: bool,
    },
}

#[derive(Clone, Debug)]
pub struct PayloadSet {
    pub source: PayloadSource,
    pub processors: Vec<Processor>,
}

impl PayloadSet {
    pub fn new(source: PayloadSource) -> Self {
        Self {
            source,
            processors: Vec::new(),
        }
    }

    /// Parse a CLI payload specification.
    ///
    /// * `file:path`, `@path` or an existing path - one payload per line
    /// * `list:a,b,c`
    /// * `numbers:1-100`, `numbers:1-100:2`, `numbers:001-010`
    /// * anything else - a single literal payload
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if let Some(path) = spec
            .strip_prefix("file:")
            .or_else(|| spec.strip_prefix('@'))
        {
            return Ok(Self::new(PayloadSource::File(PathBuf::from(path))));
        }
        if let Some(list) = spec.strip_prefix("list:") {
            return Ok(Self::new(PayloadSource::List(
                list.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            )));
        }
        if let Some(range) = spec.strip_prefix("numbers:") {
            let (range, step) = match range.rsplit_once(':') {
                Some((range, step)) => (
                    range,
                    step.parse::<i64>()
                        .with_context(|| format!("invalid number step '{step}'"))?,
                ),
                None => (range, 1),
            };
            let (start_text, end_text) = range
                .split_once('-')
                .ok_or_else(|| anyhow!("numbers payload needs START-END"))?;
            let start: i64 = start_text
                .parse()
                .with_context(|| format!("invalid range start '{start_text}'"))?;
            let end: i64 = end_text
                .parse()
                .with_context(|| format!("invalid range end '{end_text}'"))?;
            let width = if start_text.len() > 1 && start_text.starts_with('0') {
                start_text.len()
            } else {
                0
            };
            return Ok(Self::new(PayloadSource::Numbers {
                start,
                end,
                step: if step == 0 { 1 } else { step },
                width,
                hex: false,
            }));
        }
        if let Some(hex_range) = spec.strip_prefix("hex:") {
            let (start_text, end_text) = hex_range
                .split_once('-')
                .ok_or_else(|| anyhow!("hex payload needs START-END"))?;
            let start = i64::from_str_radix(start_text.trim_start_matches("0x"), 16)?;
            let end = i64::from_str_radix(end_text.trim_start_matches("0x"), 16)?;
            return Ok(Self::new(PayloadSource::Numbers {
                start,
                end,
                step: 1,
                width: start_text.trim_start_matches("0x").len(),
                hex: true,
            }));
        }
        let path = Path::new(spec);
        if path.is_file() {
            return Ok(Self::new(PayloadSource::File(path.to_path_buf())));
        }
        Ok(Self::new(PayloadSource::List(vec![spec.to_string()])))
    }

    pub fn with_processors(mut self, processors: Vec<Processor>) -> Self {
        self.processors = processors;
        self
    }

    pub fn values(&self) -> Result<Vec<String>> {
        let raw: Vec<String> = match &self.source {
            PayloadSource::List(values) => values.clone(),
            PayloadSource::File(path) => {
                let text = std::fs::read_to_string(path)
                    .with_context(|| format!("cannot read payload file '{}'", path.display()))?;
                text.lines()
                    .map(|line| line.trim_end_matches('\r').to_string())
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .collect()
            }
            PayloadSource::Numbers {
                start,
                end,
                step,
                width,
                hex: as_hex,
            } => {
                let mut out = Vec::new();
                let mut current = *start;
                let step = if *step == 0 { 1 } else { *step };
                if step > 0 {
                    while current <= *end {
                        out.push(if *as_hex {
                            format!("{:0width$x}", current, width = (*width).max(1))
                        } else if *width > 0 {
                            format!("{:0width$}", current, width = *width)
                        } else {
                            current.to_string()
                        });
                        current += step;
                    }
                } else {
                    while current >= *end {
                        out.push(if *as_hex {
                            format!("{:0width$x}", current, width = (*width).max(1))
                        } else if *width > 0 {
                            format!("{:0width$}", current, width = *width)
                        } else {
                            current.to_string()
                        });
                        current += step;
                    }
                }
                out
            }
        };
        let mut out = Vec::with_capacity(raw.len());
        for value in raw {
            let mut current = value;
            for processor in &self.processors {
                current = processor.apply(&current)?;
            }
            out.push(current);
        }
        Ok(out)
    }

    pub fn description(&self) -> String {
        match &self.source {
            PayloadSource::List(values) => {
                if values.len() == 1 {
                    format!("literal '{}'", crate::util::truncate(&values[0], 40))
                } else {
                    format!("list ({} payloads)", values.len())
                }
            }
            PayloadSource::File(path) => format!("file {}", path.display()),
            PayloadSource::Numbers { start, end, .. } => format!("numbers {start}..{end}"),
        }
    }
}

pub fn marker_count(request: &Request) -> usize {
    let mut count = request.target.matches(MARKER).count();
    for header in &request.headers {
        count += header.value.matches(MARKER).count();
    }
    count += count_marker_bytes(&request.body);
    count / 2
}

fn count_marker_bytes(data: &[u8]) -> usize {
    data.windows(MARKER_BYTES.len())
        .filter(|window| *window == MARKER_BYTES.as_slice())
        .count()
}

fn replace_markers_in_str(text: &str, payloads: &[String], index: &mut usize) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(MARKER) {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + MARKER.len_utf8()..];
        let end = after_start
            .find(MARKER)
            .ok_or_else(|| anyhow!("unclosed insertion marker (missing closing §)"))?;
        let payload = payloads
            .get(*index)
            .ok_or_else(|| anyhow!("more insertion markers than payload values"))?;
        out.push_str(payload);
        *index += 1;
        rest = &after_start[end + MARKER.len_utf8()..];
    }
    out.push_str(rest);
    Ok(out)
}

fn replace_markers_in_bytes(
    data: &[u8],
    payloads: &[String],
    index: &mut usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut position = 0;
    while position < data.len() {
        if data[position..].starts_with(&MARKER_BYTES) {
            let inner = &data[position + MARKER_BYTES.len()..];
            let end = inner
                .windows(MARKER_BYTES.len())
                .position(|window| window == MARKER_BYTES)
                .ok_or_else(|| anyhow!("unclosed insertion marker (missing closing §)"))?;
            let payload = payloads
                .get(*index)
                .ok_or_else(|| anyhow!("more insertion markers than payload values"))?;
            out.extend_from_slice(payload.as_bytes());
            *index += 1;
            position += MARKER_BYTES.len() + end + MARKER_BYTES.len();
        } else {
            out.push(data[position]);
            position += 1;
        }
    }
    Ok(out)
}

/// Replace every `§` marker with the corresponding payload.
pub fn apply_payloads(template: &Request, payloads: &[String]) -> Result<Request> {
    let mut request = template.clone();
    let mut index = 0usize;
    request.target = replace_markers_in_str(&request.target, payloads, &mut index)?;
    for header in &mut request.headers {
        header.value = replace_markers_in_str(&header.value, payloads, &mut index)?;
    }
    request.body = replace_markers_in_bytes(&request.body, payloads, &mut index)?;
    if index != payloads.len() {
        bail!(
            "template has {index} marker(s) but {} payload value(s) were generated",
            payloads.len()
        );
    }
    if request.header("Content-Length").is_some() || !request.body.is_empty() {
        request.set_header("Content-Length", request.body.len().to_string());
    }
    Ok(request)
}

/// Attach a `Content-Length` header when the template has a body.
pub fn normalize_template(mut request: Request) -> Request {
    if request.scheme.is_none() {
        request.scheme = Some(
            if request
                .header("Host")
                .and_then(|h| crate::http::message::parse_host_header(h).1)
                == Some(443)
            {
                "https".into()
            } else {
                "http".into()
            },
        );
    }
    if !request.body.is_empty() || request.header("Content-Length").is_some() {
        request.set_header("Content-Length", request.body.len().to_string());
    }
    request
}

pub fn generate_combinations(
    attack: AttackType,
    markers: usize,
    sets: &[Vec<String>],
    limit: usize,
) -> Result<Vec<Vec<String>>> {
    if markers == 0 {
        bail!("the request template has no § markers");
    }
    if sets.is_empty() {
        bail!("no payload sets were provided");
    }
    let mut out = Vec::new();
    let push = |out: &mut Vec<Vec<String>>, value: Vec<String>| -> bool {
        if limit > 0 && out.len() >= limit {
            return false;
        }
        out.push(value);
        true
    };
    match attack {
        AttackType::Sniper => {
            let payloads = &sets[0];
            'outer: for position in 0..markers {
                for payload in payloads {
                    let mut values = vec![String::new(); markers];
                    values[position] = payload.clone();
                    if !push(&mut out, values) {
                        break 'outer;
                    }
                }
            }
        }
        AttackType::BatteringRam => {
            for payload in &sets[0] {
                if !push(&mut out, vec![payload.clone(); markers]) {
                    break;
                }
            }
        }
        AttackType::Pitchfork => {
            if sets.len() < markers {
                bail!(
                    "pitchfork needs one payload set per marker ({markers}); got {}",
                    sets.len()
                );
            }
            let length = sets.iter().take(markers).map(Vec::len).min().unwrap_or(0);
            'outer: for index in 0..length {
                let mut values = Vec::with_capacity(markers);
                for set in sets.iter().take(markers) {
                    values.push(set[index].clone());
                }
                if !push(&mut out, values) {
                    break 'outer;
                }
            }
        }
        AttackType::ClusterBomb => {
            if sets.len() < markers {
                bail!(
                    "cluster-bomb needs one payload set per marker ({markers}); got {}",
                    sets.len()
                );
            }
            // Iterative cartesian product, respecting the limit.
            let mut indices = vec![0usize; markers];
            'outer: loop {
                let values: Vec<String> = indices
                    .iter()
                    .enumerate()
                    .map(|(i, &index)| sets[i][index].clone())
                    .collect();
                if !push(&mut out, values) {
                    break;
                }
                let mut position = markers;
                loop {
                    if position == 0 {
                        break 'outer;
                    }
                    position -= 1;
                    indices[position] += 1;
                    if indices[position] < sets[position].len() {
                        break;
                    }
                    indices[position] = 0;
                }
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractRule {
    pub name: String,
    pub pattern: String,
}

impl ExtractRule {
    pub fn parse(spec: &str) -> Result<Self> {
        let (name, pattern) = spec
            .split_once('=')
            .or_else(|| spec.split_once(':'))
            .ok_or_else(|| anyhow!("extract rule needs NAME=REGEX"))?;
        if name.trim().is_empty() {
            bail!("extract rule needs a name");
        }
        regex::Regex::new(pattern).with_context(|| format!("invalid extract regex '{pattern}'"))?;
        Ok(Self {
            name: name.trim().to_string(),
            pattern: pattern.to_string(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntruderResult {
    pub index: usize,
    pub payloads: Vec<String>,
    pub status: u16,
    pub length: usize,
    pub duration_ms: u64,
    pub url: String,
    #[serde(default)]
    pub grep: Vec<String>,
    #[serde(default)]
    pub extracted: BTreeMap<String, String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub response_b64: Option<String>,
}

impl IntruderResult {
    pub fn grep_hit(&self) -> bool {
        !self.grep.is_empty()
    }
}

#[derive(Clone)]
pub struct IntruderOptions {
    pub attack: AttackType,
    pub payload_sets: Vec<PayloadSet>,
    pub concurrency: usize,
    pub delay_ms: u64,
    pub grep: Vec<String>,
    pub extract: Vec<ExtractRule>,
    pub stop_on: Vec<String>,
    pub max_requests: usize,
    pub save_responses: bool,
    pub quiet: bool,
}

impl Default for IntruderOptions {
    fn default() -> Self {
        Self {
            attack: AttackType::Sniper,
            payload_sets: Vec::new(),
            concurrency: 10,
            delay_ms: 0,
            grep: Vec::new(),
            extract: Vec::new(),
            stop_on: Vec::new(),
            max_requests: 0,
            save_responses: false,
            quiet: true,
        }
    }
}

#[derive(Debug)]
pub struct IntruderRun {
    pub results: Vec<IntruderResult>,
    pub total_positions: usize,
    pub generated: usize,
    pub stopped_early: bool,
    pub errors: Vec<String>,
    pub duration: Duration,
}

pub fn run(
    template: &Request,
    options: &IntruderOptions,
    client_options: &ClientOptions,
) -> Result<IntruderRun> {
    let started = Instant::now();
    let markers = marker_count(template);
    if markers == 0 {
        bail!("the request template has no § markers");
    }
    if options.payload_sets.is_empty() {
        bail!("no payload sets were provided");
    }
    let mut sets = Vec::with_capacity(options.payload_sets.len());
    for set in &options.payload_sets {
        sets.push(set.values()?);
    }
    let combinations = generate_combinations(options.attack, markers, &sets, options.max_requests)?;
    let generated = combinations.len();
    if generated == 0 {
        bail!("the payload configuration produced no requests");
    }

    let queue = Arc::new(Mutex::new(
        combinations
            .into_iter()
            .enumerate()
            .collect::<std::collections::VecDeque<_>>(),
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let stopped_by_match = Arc::new(AtomicBool::new(false));
    let completed = AtomicUsize::new(0);
    let (sender, receiver) = std::sync::mpsc::channel::<IntruderResult>();
    let workers = options.concurrency.clamp(1, 64).min(generated);
    let limiter = Arc::new(crate::scanner::RateLimiter::new(options.delay_ms));
    let mut results = Vec::with_capacity(generated);
    let mut errors = Vec::new();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let queue = queue.clone();
            let sender = sender.clone();
            let stop = stop.clone();
            let stopped_by_match = stopped_by_match.clone();
            let completed = &completed;
            let limiter = limiter.clone();
            scope.spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let job = {
                    let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
                    queue.pop_front()
                };
                let Some((index, payloads)) = job else {
                    break;
                };
                limiter.wait();
                let mut result = IntruderResult {
                    index,
                    payloads: payloads.clone(),
                    status: 0,
                    length: 0,
                    duration_ms: 0,
                    url: String::new(),
                    grep: Vec::new(),
                    extracted: BTreeMap::new(),
                    error: None,
                    response_b64: None,
                };
                match apply_payloads(template, &payloads).and_then(|request| {
                    let started = Instant::now();
                    client::send(&request, client_options)
                        .map(|response| (request, response, started.elapsed()))
                }) {
                    Ok((request, response, elapsed)) => {
                        let url = request
                            .url()
                            .map(|u| u.to_string())
                            .unwrap_or_else(|_| request.target.clone());
                        result.url = url;
                        result.status = response.response.status;
                        result.length = response.response.body.len();
                        result.duration_ms = elapsed.as_millis() as u64;
                        result.grep = match_patterns(&response.response, &options.grep);
                        match extract_values(&response.response, &options.extract) {
                            Ok(values) => result.extracted = values,
                            Err(error) => {
                                if result.error.is_none() {
                                    result.error = Some(error.to_string());
                                }
                            }
                        }
                        if options.save_responses {
                            result.response_b64 = Some(response.response.to_b64());
                        }
                        if !options.stop_on.is_empty()
                            && !match_patterns(&response.response, &options.stop_on).is_empty()
                        {
                            stopped_by_match.store(true, Ordering::Relaxed);
                            stop.store(true, Ordering::Relaxed);
                        }
                    }
                    Err(error) => {
                        result.error = Some(format!("{error:#}"));
                    }
                }
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if !options.quiet {
                    eprint!("\r[*] intruder: {done}/{generated}");
                    use std::io::Write;
                    std::io::stderr().flush().ok();
                }
                if sender.send(result).is_err() {
                    break;
                }
            });
        }
        drop(sender);
        while let Ok(result) = receiver.recv() {
            if result.error.is_some() {
                errors.push(format!(
                    "#{}: {}",
                    result.index,
                    result.error.as_deref().unwrap_or("error")
                ));
            }
            results.push(result);
        }
    });
    if !options.quiet {
        eprintln!();
    }
    results.sort_by_key(|result| result.index);
    Ok(IntruderRun {
        results,
        total_positions: markers,
        generated,
        stopped_early: stopped_by_match.load(Ordering::Relaxed),
        errors,
        duration: started.elapsed(),
    })
}

fn match_patterns(response: &Response, patterns: &[String]) -> Vec<String> {
    let body = response.body_text();
    let mut header_text = String::new();
    for header in &response.headers {
        header_text.push_str(&header.name);
        header_text.push_str(": ");
        header_text.push_str(&header.value);
        header_text.push('\n');
    }
    let mut matched = Vec::new();
    for pattern in patterns {
        let hit = if pattern.starts_with("status:") {
            pattern
                .trim_start_matches("status:")
                .split(',')
                .any(|code| code.trim().parse::<u16>().ok() == Some(response.status))
        } else if pattern.starts_with("size>") {
            pattern
                .trim_start_matches("size>")
                .parse::<usize>()
                .map(|size| body.len() > size)
                .unwrap_or(false)
        } else if pattern.starts_with("size<") {
            pattern
                .trim_start_matches("size<")
                .parse::<usize>()
                .map(|size| body.len() < size)
                .unwrap_or(false)
        } else {
            wildcard_contains(pattern, &body) || wildcard_contains(pattern, &header_text)
        };
        if hit {
            matched.push(pattern.clone());
        }
    }
    matched
}

fn extract_values(response: &Response, rules: &[ExtractRule]) -> Result<BTreeMap<String, String>> {
    let body = response.body_text();
    let mut values = BTreeMap::new();
    for rule in rules {
        let re = regex::Regex::new(&rule.pattern)
            .with_context(|| format!("invalid extract regex '{}'", rule.pattern))?;
        if let Some(captures) = re.captures(&body) {
            let value = captures
                .get(1)
                .or_else(|| captures.get(0))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            values.insert(rule.name.clone(), value);
        }
    }
    Ok(values)
}

/// Render results as RFC 4180 CSV (quoted fields, CRLF line endings).
pub fn to_csv(results: &[IntruderResult], extra_columns: &[String]) -> String {
    let mut out = String::new();
    let payload_columns = results
        .iter()
        .map(|result| result.payloads.len())
        .max()
        .unwrap_or(0);
    let mut header = vec![
        "index".to_string(),
        "status".to_string(),
        "length".to_string(),
        "duration_ms".to_string(),
        "url".to_string(),
    ];
    for index in 0..payload_columns {
        header.push(format!("payload{}", index + 1));
    }
    header.extend(extra_columns.iter().cloned());
    header.push("grep".into());
    header.push("error".into());
    out.push_str(&csv_row(&header));

    for result in results {
        let mut row = vec![
            result.index.to_string(),
            result.status.to_string(),
            result.length.to_string(),
            result.duration_ms.to_string(),
            result.url.clone(),
        ];
        row.extend(result.payloads.iter().cloned());
        for column in extra_columns {
            row.push(result.extracted.get(column).cloned().unwrap_or_default());
        }
        row.push(result.grep.join(";"));
        row.push(result.error.clone().unwrap_or_default());
        out.push_str(&csv_row(&row));
    }
    out
}

fn csv_row(fields: &[String]) -> String {
    let mut line = fields
        .iter()
        .map(|field| {
            if field.contains([',', '"', '\n', '\r']) {
                format!("\"{}\"", field.replace('"', "\"\""))
            } else {
                field.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

/// Render results as pretty JSON.
pub fn to_json(results: &[IntruderResult]) -> Result<String> {
    Ok(serde_json::to_string_pretty(results)?)
}

/// Mark results whose response length differs from the most common length.
pub fn length_outliers(results: &[IntruderResult]) -> usize {
    if results.len() < 3 {
        return 0;
    }
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for result in results {
        if result.status != 0 {
            *counts.entry(result.length).or_insert(0) += 1;
        }
    }
    let mode = counts
        .iter()
        .max_by_key(|(_, count)| **count)
        .map(|(length, _)| *length)
        .unwrap_or(0);
    results
        .iter()
        .filter(|result| result.status != 0 && result.length != mode)
        .count()
}

/// One-line console summary.
pub fn summary(run: &IntruderRun) -> String {
    let hits = run.results.iter().filter(|r| r.grep_hit()).count();
    format!(
        "{} requests ({} positions, generated {}) | {} grep hits | {} outliers | {} errors | {}",
        run.results.len(),
        run.total_positions,
        run.generated,
        hits,
        length_outliers(&run.results),
        run.errors.len(),
        format_duration(run.duration)
    )
}

/// Utility used by the CLI to insert markers around a parameter value.
pub fn wrap_markers(text: &str, needle: &str) -> String {
    text.replace(needle, &format!("{MARKER}{needle}{MARKER}"))
}

/// Rebuild a template from raw bytes, accepting LF-only line endings.
pub fn template_from_raw(raw: &[u8]) -> Result<Request> {
    let normalized = String::from_utf8_lossy(raw).replace("\r\n", "\n");
    let normalized = normalized.replace('\n', "\r\n");
    let request = Request::parse(normalized.as_bytes())?;
    Ok(normalize_template(request))
}

/// Load a template from a file.
pub fn template_from_file(path: &Path) -> Result<Request> {
    let raw = std::fs::read(path)
        .with_context(|| format!("cannot read template '{}'", path.display()))?;
    template_from_raw(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> Request {
        Request::parse(
            "POST /login?next=§/home§ HTTP/1.1\r\nHost: example.com\r\nX-Test: §a§\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=§admin§&pass=§x§"
                .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn counts_and_replaces_markers() {
        let request = template();
        assert_eq!(marker_count(&request), 4);
        let injected =
            apply_payloads(&request, &["n".into(), "h".into(), "u".into(), "p".into()]).unwrap();
        assert_eq!(injected.target, "/login?next=n");
        assert_eq!(injected.header("X-Test").unwrap(), "h");
        assert_eq!(injected.body, b"user=u&pass=p");
        assert_eq!(injected.header("Content-Length").unwrap(), "13");
    }

    #[test]
    fn payload_sources() {
        let list = PayloadSet::parse("list:a,b,c").unwrap();
        assert_eq!(list.values().unwrap(), vec!["a", "b", "c"]);
        let numbers = PayloadSet::parse("numbers:1-5:2").unwrap();
        assert_eq!(numbers.values().unwrap(), vec!["1", "3", "5"]);
        let padded = PayloadSet::parse("numbers:001-003").unwrap();
        assert_eq!(padded.values().unwrap(), vec!["001", "002", "003"]);
        let hex = PayloadSet::parse("hex:0a-0c").unwrap();
        assert_eq!(hex.values().unwrap(), vec!["0a", "0b", "0c"]);
        let literal = PayloadSet::parse("admin").unwrap();
        assert_eq!(literal.values().unwrap(), vec!["admin"]);
    }

    #[test]
    fn processors_chain() {
        let processors = vec![
            Processor::parse("prefix:ID-").unwrap(),
            Processor::parse("upper").unwrap(),
            Processor::parse("suffix:-X").unwrap(),
        ];
        let set = PayloadSet::parse("list:ab,cd")
            .unwrap()
            .with_processors(processors);
        assert_eq!(set.values().unwrap(), vec!["ID-AB-X", "ID-CD-X"]);
    }

    #[test]
    fn attack_combinations() {
        let sets = vec![vec!["1".to_string(), "2".to_string()]];
        let sniper = generate_combinations(AttackType::Sniper, 3, &sets, 0).unwrap();
        assert_eq!(sniper.len(), 6);
        assert_eq!(sniper[0], vec!["1", "", ""]);
        assert_eq!(sniper[1], vec!["2", "", ""]);
        assert_eq!(sniper[2], vec!["", "1", ""]);

        let ram = generate_combinations(AttackType::BatteringRam, 3, &sets, 0).unwrap();
        assert_eq!(ram.len(), 2);
        assert_eq!(ram[0], vec!["1", "1", "1"]);

        let sets = vec![
            vec!["a".to_string(), "b".to_string()],
            vec!["1".to_string(), "2".to_string(), "3".to_string()],
        ];
        let pitchfork = generate_combinations(AttackType::Pitchfork, 2, &sets, 0).unwrap();
        assert_eq!(pitchfork.len(), 2);
        assert_eq!(pitchfork[1], vec!["b", "2"]);

        let cluster = generate_combinations(AttackType::ClusterBomb, 2, &sets, 0).unwrap();
        assert_eq!(cluster.len(), 6);
        assert_eq!(cluster[0], vec!["a", "1"]);
        assert_eq!(cluster[5], vec!["b", "3"]);

        let limited = generate_combinations(AttackType::ClusterBomb, 2, &sets, 3).unwrap();
        assert_eq!(limited.len(), 3);
    }

    #[test]
    fn extraction_and_grep() {
        let response = Response::parse(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>token=abc123 welcome</html>",
        )
        .unwrap();
        let matched = match_patterns(
            &response,
            &["welcome".into(), "size>10".into(), "status:200".into()],
        );
        assert_eq!(matched.len(), 3);
        let values = extract_values(
            &response,
            &[ExtractRule {
                name: "token".into(),
                pattern: r"token=([a-z0-9]+)".into(),
            }],
        )
        .unwrap();
        assert_eq!(values.get("token").unwrap(), "abc123");
    }

    #[test]
    fn csv_escaping() {
        let result = IntruderResult {
            index: 0,
            payloads: vec!["a,\"b\"".into()],
            status: 200,
            length: 5,
            duration_ms: 1,
            url: "http://x/?q=a,b".into(),
            grep: vec![],
            extracted: BTreeMap::new(),
            error: None,
            response_b64: None,
        };
        let csv = to_csv(&[result], &[]);
        assert!(csv.contains("\"a,\"\"b\"\"\""));
        assert!(csv.contains("\"http://x/?q=a,b\""));
    }

    #[test]
    fn wraps_parameter() {
        let wrapped = wrap_markers("user=admin", "admin");
        assert_eq!(wrapped, "user=§admin§");
    }
}
