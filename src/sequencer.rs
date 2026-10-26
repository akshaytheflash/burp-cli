//! Token randomness analysis ("Sequencer").

use crate::http::client::{self, ClientOptions};
use crate::http::Response;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct TokenAnalysis {
    pub count: usize,
    pub unique: usize,
    pub min_length: usize,
    pub max_length: usize,
    pub lengths: BTreeMap<usize, usize>,
    pub charset: usize,
    pub entropy_bits_per_char: f64,
    pub total_entropy_bits: f64,
    pub position_entropy: Vec<f64>,
    pub chi_square: f64,
    pub chi_square_p: f64,
    pub monobit_p: f64,
    pub runs_p: f64,
    pub longest_run: usize,
    pub serial_correlation: f64,
    pub sequential: bool,
    pub verdict: String,
    pub notes: Vec<String>,
}

pub fn analyze(samples: &[String]) -> TokenAnalysis {
    let mut analysis = TokenAnalysis {
        count: samples.len(),
        ..Default::default()
    };
    if samples.is_empty() {
        analysis.verdict = "no samples".into();
        return analysis;
    }

    let unique: std::collections::HashSet<&String> = samples.iter().collect();
    analysis.unique = unique.len();
    analysis.min_length = samples.iter().map(String::len).min().unwrap_or(0);
    analysis.max_length = samples.iter().map(String::len).max().unwrap_or(0);
    for sample in samples {
        *analysis.lengths.entry(sample.len()).or_insert(0) += 1;
    }

    let combined: Vec<u8> = samples
        .iter()
        .flat_map(|s| s.as_bytes().iter().copied())
        .collect();
    let mut alphabet = std::collections::HashSet::new();
    for &b in &combined {
        alphabet.insert(b);
    }
    analysis.charset = alphabet.len();
    analysis.entropy_bits_per_char = shannon_entropy(&combined);
    let avg_len = combined.len() as f64 / samples.len() as f64;
    analysis.total_entropy_bits = analysis.entropy_bits_per_char * avg_len;

    let max_len = analysis.max_length;
    for position in 0..max_len {
        let mut counts: BTreeMap<u8, usize> = BTreeMap::new();
        let mut total = 0usize;
        for sample in samples {
            if let Some(b) = sample.as_bytes().get(position) {
                *counts.entry(*b).or_insert(0) += 1;
                total += 1;
            }
        }
        if total > 1 {
            let entropy = -counts
                .values()
                .map(|&count| {
                    let p = count as f64 / total as f64;
                    p * p.log2()
                })
                .sum::<f64>();
            analysis.position_entropy.push(entropy);
        }
    }

    let (chi, chi_p) = byte_chi_square(&combined);
    analysis.chi_square = chi;
    analysis.chi_square_p = chi_p;
    let (monobit_p, runs_p, longest_run) = bit_tests(&combined);
    analysis.monobit_p = monobit_p;
    analysis.runs_p = runs_p;
    analysis.longest_run = longest_run;
    analysis.serial_correlation = serial_correlation(&combined);
    analysis.sequential = looks_sequential(samples);
    analysis.verdict = verdict(&analysis);
    analysis.notes = build_notes(&analysis);
    analysis
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            p * p.log2()
        })
        .sum::<f64>()
}

fn byte_chi_square(data: &[u8]) -> (f64, f64) {
    if data.is_empty() {
        return (0.0, 1.0);
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    let chi = counts
        .iter()
        .map(|&count| {
            let diff = count as f64 - expected;
            diff * diff / expected
        })
        .sum::<f64>();
    // Wilson-Hilferty approximation of the chi-square upper tail (df = 255).
    let df = 255.0;
    let z = ((chi / df).cbrt() - (1.0 - 2.0 / (9.0 * df))) / (2.0 / (9.0 * df)).sqrt();
    let p = normal_survival(z);
    (chi, p.clamp(0.0, 1.0))
}

fn bit_tests(data: &[u8]) -> (f64, f64, usize) {
    if data.is_empty() {
        return (1.0, 1.0, 0);
    }
    let mut ones = 0usize;
    let mut runs = 1usize;
    let mut longest = 0usize;
    let mut current = 0usize;
    let mut previous: Option<bool> = None;
    for &byte in data {
        for bit in 0..8 {
            let value = (byte >> (7 - bit)) & 1 == 1;
            if value {
                ones += 1;
                current += 1;
                longest = longest.max(current);
            } else {
                current = 0;
            }
            if let Some(prev) = previous {
                if prev != value {
                    runs += 1;
                }
            }
            previous = Some(value);
        }
    }
    let n = data.len() * 8;
    let ones_f = ones as f64;
    let n_f = n as f64;
    let monobit_z = (ones_f - n_f / 2.0) / (n_f / 4.0).sqrt();
    let monobit_p = (2.0 * normal_survival(monobit_z.abs())).clamp(0.0, 1.0);

    let zeros = n - ones;
    let runs_p = if ones == 0 || zeros == 0 || n < 2 {
        1.0
    } else {
        let n1 = ones as f64;
        let n2 = zeros as f64;
        let expected = 2.0 * n1 * n2 / n_f + 1.0;
        let variance = 2.0 * n1 * n2 * (2.0 * n1 * n2 - n_f) / (n_f * n_f * (n_f - 1.0));
        if variance <= 0.0 {
            1.0
        } else {
            let z = (runs as f64 - expected) / variance.sqrt();
            (2.0 * normal_survival(z.abs())).clamp(0.0, 1.0)
        }
    };
    (monobit_p, runs_p, longest)
}

fn serial_correlation(data: &[u8]) -> f64 {
    if data.len() < 3 {
        return 0.0;
    }
    let pairs = data.len() - 1;
    let mut sum_x = 0.0;
    let mut sum_y = 0.0;
    let mut sum_xy = 0.0;
    let mut sum_x2 = 0.0;
    for window in data.windows(2) {
        let x = window[0] as f64;
        let y = window[1] as f64;
        sum_x += x;
        sum_y += y;
        sum_xy += x * y;
        sum_x2 += x * x;
    }
    let n = pairs as f64;
    let numerator = n * sum_xy - sum_x * sum_y;
    let denominator = n * sum_x2 - sum_x * sum_x;
    if denominator.abs() < f64::EPSILON {
        0.0
    } else {
        numerator / denominator
    }
}

fn looks_sequential(samples: &[String]) -> bool {
    if samples.len() < 3 {
        return false;
    }
    if samples
        .iter()
        .all(|s| s.chars().all(|c| c.is_ascii_digit()))
    {
        let numbers: Vec<u128> = samples
            .iter()
            .filter_map(|s| s.parse::<u128>().ok())
            .collect();
        if numbers.len() == samples.len() {
            return numbers
                .windows(2)
                .all(|pair| pair[1] == pair[0].wrapping_add(1));
        }
    }
    // Identical prefixes with a short changing suffix are often counters.
    let prefix = samples[0].len().saturating_sub(4);
    samples
        .iter()
        .all(|s| s.len() > prefix && s[..prefix] == samples[0][..prefix])
        && samples.windows(2).any(|pair| pair[0] != pair[1])
}

fn verdict(a: &TokenAnalysis) -> String {
    if a.count < 10 {
        return "insufficient samples (use at least 50)".into();
    }
    if a.unique == 1 {
        return "STATIC: every token is identical".into();
    }
    if a.sequential {
        return "PREDICTABLE: tokens look sequential".into();
    }
    if a.entropy_bits_per_char < 2.0 || a.charset <= 2 {
        return "WEAK: very low character entropy".into();
    }
    if (a.unique as f64 / a.count as f64) < 0.5 {
        return "WEAK: high number of duplicate tokens".into();
    }
    if a.entropy_bits_per_char >= 4.5
        && a.monobit_p > 0.01
        && a.runs_p > 0.01
        && a.serial_correlation.abs() < 0.2
    {
        return "STRONG: no obvious statistical bias".into();
    }
    "INCONCLUSIVE: review the statistics".into()
}

fn build_notes(a: &TokenAnalysis) -> Vec<String> {
    let mut notes = Vec::new();
    if a.min_length != a.max_length {
        notes.push(format!(
            "token length varies between {} and {} bytes",
            a.min_length, a.max_length
        ));
    }
    if a.unique < a.count {
        notes.push(format!("{} duplicate token(s)", a.count - a.unique));
    }
    if a.entropy_bits_per_char < 3.0 {
        notes.push("low per-character entropy; a larger alphabet is recommended".into());
    }
    if a.chi_square_p < 0.01 {
        notes.push("byte distribution is significantly non-uniform (chi-square)".into());
    }
    if a.monobit_p < 0.01 {
        notes.push("bit stream is biased (monobit test)".into());
    }
    if a.runs_p < 0.01 {
        notes.push("bit runs differ from random expectation (runs test)".into());
    }
    if a.position_entropy.iter().any(|e| *e < 1.0) {
        notes.push("some token positions have almost no variation".into());
    }
    notes
}

fn normal_survival(z: f64) -> f64 {
    0.5 * erfc(z / std::f64::consts::SQRT_2)
}

/// Numerical Recipes complementary error function approximation.
fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let ans = t
        * (-z * z - 1.265_512_23
            + t * (1.000_023_68
                + t * (0.374_091_96
                    + t * (0.096_784_18
                        + t * (-0.186_288_06
                            + t * (0.278_868_07
                                + t * (-1.135_203_98
                                    + t * (1.488_515_87
                                        + t * (-0.822_152_23 + t * 0.170_872_77)))))))))
            .exp();
    if x >= 0.0 {
        ans
    } else {
        2.0 - ans
    }
}

#[derive(Clone, Debug)]
pub enum Extraction {
    Cookie(String),
    Header(String),
    Body(String),
    Location,
}

impl Extraction {
    pub fn parse(value: &str) -> Result<Self> {
        let (kind, arg) = value.split_once(':').unwrap_or((value, ""));
        match kind.to_ascii_lowercase().as_str() {
            "cookie" if !arg.is_empty() => Ok(Self::Cookie(arg.to_string())),
            "header" if !arg.is_empty() => Ok(Self::Header(arg.to_string())),
            "body" if !arg.is_empty() => Ok(Self::Body(arg.to_string())),
            "location" => Ok(Self::Location),
            _ => bail!(
                "invalid extraction '{value}' (use cookie:NAME, header:NAME, body:REGEX or location)"
            ),
        }
    }
}

pub fn extract_token(response: &Response, extraction: &Extraction) -> Result<String> {
    match extraction {
        Extraction::Cookie(name) => {
            for header in response.headers_named("Set-Cookie") {
                let first = header.split(';').next().unwrap_or("");
                if let Some((key, value)) = first.split_once('=') {
                    if key.trim() == name {
                        return Ok(value.trim().to_string());
                    }
                }
            }
            Err(anyhow!("cookie '{name}' not found in response"))
        }
        Extraction::Header(name) => response
            .header(name)
            .map(|v| v.to_string())
            .ok_or_else(|| anyhow!("header '{name}' not found in response")),
        Extraction::Location => response
            .header("Location")
            .map(|v| v.to_string())
            .ok_or_else(|| anyhow!("no Location header in response")),
        Extraction::Body(pattern) => {
            let re = regex::Regex::new(pattern)
                .with_context(|| format!("invalid body regex '{pattern}'"))?;
            let text = response.body_text();
            let captures = re
                .captures(&text)
                .ok_or_else(|| anyhow!("body pattern did not match"))?;
            Ok(captures
                .get(1)
                .or_else(|| captures.get(0))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default())
        }
    }
}

pub struct SampleOptions {
    pub url: String,
    pub count: usize,
    pub extraction: Extraction,
    pub delay: Duration,
    pub client: ClientOptions,
}

pub fn fetch_samples(options: &SampleOptions) -> Result<Vec<String>> {
    let url = Url::parse(&options.url).context("invalid sample URL")?;
    let mut samples = Vec::with_capacity(options.count);
    for index in 0..options.count {
        let request = crate::http::Request::from_url("GET", &url, Vec::new(), None);
        let response = client::send(&request, &options.client)
            .with_context(|| format!("sample {} failed", index + 1))?;
        let token = extract_token(&response.response, &options.extraction)?;
        samples.push(token);
        if !options.delay.is_zero() {
            std::thread::sleep(options.delay);
        }
    }
    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        assert!((shannon_entropy(b"ab") - 1.0).abs() < 1e-9);
        let random: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&random) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn static_tokens_are_weak() {
        let samples: Vec<String> = (0..50).map(|_| "fixedtoken".to_string()).collect();
        let analysis = analyze(&samples);
        assert!(analysis.verdict.starts_with("STATIC"));
        assert_eq!(analysis.unique, 1);
    }

    #[test]
    fn numeric_sequence_is_detected() {
        let samples: Vec<String> = (1000..1050).map(|n| n.to_string()).collect();
        let analysis = analyze(&samples);
        assert!(analysis.sequential);
        assert!(analysis.verdict.starts_with("PREDICTABLE"));
    }

    #[test]
    fn random_tokens_score_well() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let samples: Vec<String> = (0..120)
            .map(|_| {
                (0..32)
                    .map(|_| {
                        let alphabet =
                            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                        alphabet[rng.gen_range(0..alphabet.len())] as char
                    })
                    .collect()
            })
            .collect();
        let analysis = analyze(&samples);
        assert!(!analysis.sequential);
        assert!(analysis.entropy_bits_per_char > 4.0);
        assert!(analysis.unique > 100);
    }

    #[test]
    fn extraction() {
        let response = Response::parse(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc123; Path=/\r\nX-Token: xyz\r\nLocation: /next\r\n\r\n{\"token\":\"body-token\"}",
        )
        .unwrap();
        assert_eq!(
            extract_token(&response, &Extraction::Cookie("sid".into())).unwrap(),
            "abc123"
        );
        assert_eq!(
            extract_token(&response, &Extraction::Header("X-Token".into())).unwrap(),
            "xyz"
        );
        assert_eq!(
            extract_token(&response, &Extraction::Body(r#""token":"([^"]+)""#.into())).unwrap(),
            "body-token"
        );
        assert_eq!(
            extract_token(&response, &Extraction::Location).unwrap(),
            "/next"
        );
    }
}
