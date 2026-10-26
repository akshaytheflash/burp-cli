//! Small cross-cutting helpers: time, encoding, terminal output and matching.

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use chrono::{SecondsFormat, Utc};
use regex::Regex;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn b64_decode(data: &str) -> Result<Vec<u8>> {
    let cleaned: String = data.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .context("invalid base64 data")
}

pub fn b64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn b64url_decode(data: &str) -> Result<Vec<u8>> {
    let cleaned: String = data
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_end_matches('=')
        .to_string();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cleaned.as_bytes())
        .context("invalid base64url data")
}

/// Lossy UTF-8 rendering suitable for terminals. Binary bytes are shown as
/// `\xNN` so that they cannot corrupt the terminal.
pub fn display_bytes(data: &[u8]) -> String {
    match std::str::from_utf8(data) {
        Ok(s) => s.to_string(),
        Err(_) => {
            let mut out = String::with_capacity(data.len() + 16);
            for &b in data {
                match b {
                    b'\n' | b'\r' | b'\t' => out.push(b as char),
                    0x20..=0x7e => out.push(b as char),
                    _ => out.push_str(&format!("\\x{b:02x}")),
                }
            }
            out
        }
    }
}

/// Render a byte buffer as text, replacing invalid sequences with U+FFFD.
pub fn to_text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

pub fn random_token(len: usize) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn parse_duration(input: &str) -> Result<Duration> {
    let input = input.trim();
    if input.is_empty() {
        return Err(anyhow!("empty duration"));
    }
    let (number, unit) = input.split_at(
        input
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(input.len()),
    );
    let value: f64 = number
        .parse()
        .with_context(|| format!("invalid duration '{input}'"))?;
    let millis = match unit.trim() {
        "" | "s" | "sec" | "secs" => value * 1000.0,
        "ms" | "msec" => value,
        "m" | "min" | "mins" => value * 60_000.0,
        "h" | "hr" | "hrs" => value * 3_600_000.0,
        other => return Err(anyhow!("unknown duration unit '{other}'")),
    };
    if !millis.is_finite() || millis < 0.0 {
        return Err(anyhow!("invalid duration '{input}'"));
    }
    Ok(Duration::from_millis(millis.round() as u64))
}

pub fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

pub fn format_size(bytes: usize) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Expand a shell-style glob (`*`, `?`) into an anchored regex.
pub fn glob_to_regex(pattern: &str) -> Result<Regex> {
    let mut regex = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            c => regex.push_str(&regex::escape(&c.to_string())),
        }
    }
    regex.push('$');
    Regex::new(&regex).with_context(|| format!("invalid glob pattern '{pattern}'"))
}

pub fn glob_match(pattern: &str, text: &str) -> bool {
    match glob_to_regex(pattern) {
        Ok(re) => re.is_match(text),
        Err(_) => false,
    }
}

/// Case-insensitive wildcard match used for header/body "grep" filters.
pub fn wildcard_contains(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    let regex = format!(
        "(?is){}",
        pattern
            .split('*')
            .map(regex::escape)
            .collect::<Vec<_>>()
            .join(".*")
    );
    Regex::new(&regex)
        .map(|r| r.is_match(text))
        .unwrap_or(false)
}

pub fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn truncate(input: &str, max: usize) -> String {
    if input.chars().count() <= max {
        return input.to_string();
    }
    let mut out: String = input.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

pub fn truncate_bytes(input: &str, max: usize) -> &str {
    if input.len() <= max {
        return input;
    }
    let mut end = max;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

/// A cheap structural similarity score between two bodies in `[0.0, 1.0]`.
/// Uses line multiset Jaccard similarity with a length penalty. This is used
/// by differential scanner checks, not as a general-purpose diff.
pub fn body_similarity(a: &[u8], b: &[u8]) -> f64 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    use std::collections::HashSet;
    let sa: HashSet<&[u8]> = a.split(|c| *c == b'\n').collect();
    let sb: HashSet<&[u8]> = b.split(|c| *c == b'\n').collect();
    if sa.is_empty() && sb.is_empty() {
        return 1.0;
    }
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    let jaccard = if union == 0.0 { 1.0 } else { inter / union };
    let len_ratio = (a.len().min(b.len()) as f64) / (a.len().max(b.len()) as f64);
    (jaccard * 0.7 + len_ratio * 0.3).clamp(0.0, 1.0)
}

/// Length of the common prefix of two byte slices.
pub fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

static COLOR: AtomicBool = AtomicBool::new(false);

pub fn set_color(enabled: bool) {
    COLOR.store(enabled, Ordering::Relaxed);
}

pub fn color_enabled() -> bool {
    COLOR.load(Ordering::Relaxed)
}

/// Decide whether to emit ANSI colour, honouring `NO_COLOR` and terminals.
pub fn init_color(mode: &str) {
    let enabled = match mode {
        "always" => true,
        "never" => false,
        _ => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    };
    set_color(enabled);
}

pub fn paint(code: &str, text: &str) -> String {
    if color_enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

pub fn bold(text: &str) -> String {
    paint("1", text)
}
pub fn dim(text: &str) -> String {
    paint("2", text)
}
pub fn red(text: &str) -> String {
    paint("31", text)
}
pub fn green(text: &str) -> String {
    paint("32", text)
}
pub fn yellow(text: &str) -> String {
    paint("33", text)
}
pub fn blue(text: &str) -> String {
    paint("34", text)
}
pub fn magenta(text: &str) -> String {
    paint("35", text)
}
pub fn cyan(text: &str) -> String {
    paint("36", text)
}

/// Render an ASCII table with wrapped cells.
pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }
    let line = |widths: &[usize]| {
        widths
            .iter()
            .map(|w| "-".repeat(w + 2))
            .collect::<Vec<_>>()
            .join("+")
    };
    let header_line = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!(" {:<width$} ", h, width = widths[i]))
        .collect::<Vec<_>>()
        .join("|");
    println!("{}", bold(&header_line));
    println!("{}", line(&widths));
    for row in rows {
        let cells = widths
            .iter()
            .enumerate()
            .map(|(i, w)| {
                format!(
                    " {:<width$} ",
                    row.get(i).map(String::as_str).unwrap_or(""),
                    width = w
                )
            })
            .collect::<Vec<_>>()
            .join("|");
        println!("{cells}");
    }
}

/// Print a `key: value` block with consistent alignment.
pub fn kv_block(pairs: &[(&str, String)]) {
    let width = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (key, value) in pairs {
        println!("{:<width$}  {}", format!("{key}:"), value, width = width);
    }
}

pub fn prompt(message: &str) -> Result<String> {
    print!("{message}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line)?;
    if read == 0 {
        return Err(anyhow!("end of input"));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

pub fn confirm(message: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        let answer = prompt(&format!("{message} {hint} "))?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("Please answer yes or no."),
        }
    }
}

/// Split a command line into arguments, honouring single and double quotes and
/// backslash escapes. Used for plugin commands, not for shell execution.
///
/// Inside double quotes a backslash only escapes `"` and `\`, so Windows paths
/// such as `"C:\tools\plugin.exe"` survive unchanged.
pub fn split_command(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut has_current = false;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('"'), '\\') if matches!(chars.peek(), Some('"') | Some('\\')) => {
                if let Some(next) = chars.next() {
                    current.push(next);
                    has_current = true;
                }
            }
            (Some(_), c) if Some(c) == quote => {
                quote = None;
                has_current = true;
            }
            (None, '"') | (None, '\'') => {
                quote = Some(ch);
                has_current = true;
            }
            (None, c) if c.is_whitespace() => {
                if has_current {
                    args.push(std::mem::take(&mut current));
                    has_current = false;
                }
            }
            (_, c) => {
                current.push(c);
                has_current = true;
            }
        }
    }
    if has_current {
        args.push(current);
    }
    args
}

/// Human-friendly relative path display.
pub fn display_path(path: &std::path::Path) -> String {
    path.display().to_string()
}

pub fn strip_ansi(input: &str) -> String {
    Regex::new(r"\x1b\[[0-9;]*m")
        .map(|re| re.replace_all(input, "").into_owned())
        .unwrap_or_else(|_| input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let data = b"hello\x00world";
        assert_eq!(b64_decode(&b64_encode(data)).unwrap(), data);
    }

    #[test]
    fn durations() {
        assert_eq!(
            parse_duration("1500ms").unwrap(),
            Duration::from_millis(1500)
        );
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("1.5").unwrap(), Duration::from_millis(1500));
        assert!(parse_duration("nope").is_err());
    }

    #[test]
    fn globs() {
        assert!(glob_match(
            "https://example.com/*",
            "https://example.com/a/b"
        ));
        assert!(!glob_match("https://example.com/*", "https://other.com/a"));
        assert!(glob_match("*.example.com", "api.example.com"));
        assert!(!glob_match("*.example.com", "example.com.evil"));
    }

    #[test]
    fn command_splitting() {
        assert_eq!(
            split_command(r#"python "my script.py" --flag 'a b'"#),
            vec!["python", "my script.py", "--flag", "a b"]
        );
        assert_eq!(
            split_command(r#""C:\tools\burpcli.exe" __plugin-demo"#),
            vec![r#"C:\tools\burpcli.exe"#, "__plugin-demo"]
        );
        assert_eq!(
            split_command(r#""C:\a b\burpcli.exe" run"#),
            vec![r#"C:\a b\burpcli.exe"#, "run"]
        );
        assert_eq!(
            split_command(r#"say "hi \"there\"""#),
            vec!["say", "hi \"there\""]
        );
    }

    #[test]
    fn similarity_bounds() {
        assert!((body_similarity(b"a\nb", b"a\nb") - 1.0).abs() < 1e-9);
        assert!(body_similarity(b"aaaa", b"bbbb") < 0.5);
    }
}
