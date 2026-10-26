//! Diffing ("Comparer") with unified output and similarity statistics.

use crate::util::{bold, cyan, green, red};
use anyhow::{Context, Result};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffMode {
    Lines,
    Words,
    Bytes,
}

impl DiffMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "line" | "lines" => Ok(Self::Lines),
            "word" | "words" => Ok(Self::Words),
            "byte" | "bytes" | "binary" => Ok(Self::Bytes),
            other => anyhow::bail!("unknown diff mode '{other}' (use lines, words or bytes)"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiffOptions {
    pub mode: DiffMode,
    pub context: usize,
    pub color: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            mode: DiffMode::Lines,
            context: 3,
            color: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DiffResult {
    pub output: String,
    pub added: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub similarity: f64,
    pub first_difference: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Equal,
    Delete,
    Insert,
}

#[derive(Clone, Debug)]
struct Op {
    kind: Kind,
    text: String,
    old_line: usize,
    new_line: usize,
}

pub fn compare(a: &[u8], b: &[u8], opts: &DiffOptions) -> DiffResult {
    let first_difference = a.iter().zip(b).position(|(x, y)| x != y).or_else(|| {
        if a.len() != b.len() {
            Some(a.len().min(b.len()))
        } else {
            None
        }
    });

    let (a_text, b_text) = match opts.mode {
        DiffMode::Lines => (
            String::from_utf8_lossy(a).into_owned(),
            String::from_utf8_lossy(b).into_owned(),
        ),
        DiffMode::Words => (
            String::from_utf8_lossy(a).into_owned(),
            String::from_utf8_lossy(b).into_owned(),
        ),
        DiffMode::Bytes => (hexdump(a), hexdump(b)),
    };

    let old_units: Vec<&str> = match opts.mode {
        DiffMode::Words => a_text.split_inclusive(char::is_whitespace).collect(),
        _ => a_text.split_inclusive('\n').collect(),
    };
    let new_units: Vec<&str> = match opts.mode {
        DiffMode::Words => b_text.split_inclusive(char::is_whitespace).collect(),
        _ => b_text.split_inclusive('\n').collect(),
    };

    let ops = diff_units(&old_units, &new_units);
    let added = ops.iter().filter(|o| o.kind == Kind::Insert).count();
    let removed = ops.iter().filter(|o| o.kind == Kind::Delete).count();
    let unchanged = ops.iter().filter(|o| o.kind == Kind::Equal).count();
    let total = (added + removed + unchanged).max(1) as f64;
    let similarity = 1.0 - (added + removed) as f64 / total;

    let output = render(&ops, opts);
    DiffResult {
        output,
        added,
        removed,
        unchanged,
        similarity,
        first_difference,
    }
}

fn diff_units(a: &[&str], b: &[&str]) -> Vec<Op> {
    // Trim common prefix/suffix to keep the LCS table small.
    let mut prefix = 0;
    while prefix < a.len() && prefix < b.len() && a[prefix] == b[prefix] {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < a.len() - prefix
        && suffix < b.len() - prefix
        && a[a.len() - 1 - suffix] == b[b.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let mut ops = Vec::new();
    for (i, text) in a[..prefix].iter().enumerate() {
        ops.push(Op {
            kind: Kind::Equal,
            text: (*text).to_string(),
            old_line: i + 1,
            new_line: i + 1,
        });
    }

    let mid_a = &a[prefix..a.len() - suffix];
    let mid_b = &b[prefix..b.len() - suffix];
    let table = if mid_a.len().saturating_mul(mid_b.len()) <= 4_000_000 {
        Some(lcs_table(mid_a, mid_b))
    } else {
        None
    };
    if let Some(table) = table {
        lcs_ops(mid_a, mid_b, &table, prefix, prefix, &mut ops);
    } else {
        for (i, text) in mid_a.iter().enumerate() {
            ops.push(Op {
                kind: Kind::Delete,
                text: (*text).to_string(),
                old_line: prefix + i + 1,
                new_line: prefix + 1,
            });
        }
        for (i, text) in mid_b.iter().enumerate() {
            ops.push(Op {
                kind: Kind::Insert,
                text: (*text).to_string(),
                old_line: prefix + 1,
                new_line: prefix + i + 1,
            });
        }
    }

    for (i, text) in a[a.len() - suffix..].iter().enumerate() {
        let old_line = a.len() - suffix + i + 1;
        let new_line = b.len() - suffix + i + 1;
        ops.push(Op {
            kind: Kind::Equal,
            text: (*text).to_string(),
            old_line,
            new_line,
        });
    }
    ops
}

fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<u32>> {
    let mut table = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            table[i][j] = if a[i] == b[j] {
                table[i + 1][j + 1] + 1
            } else {
                table[i + 1][j].max(table[i][j + 1])
            };
        }
    }
    table
}

fn lcs_ops(
    a: &[&str],
    b: &[&str],
    table: &[Vec<u32>],
    old_offset: usize,
    new_offset: usize,
    ops: &mut Vec<Op>,
) {
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            ops.push(Op {
                kind: Kind::Equal,
                text: a[i].to_string(),
                old_line: old_offset + i + 1,
                new_line: new_offset + j + 1,
            });
            i += 1;
            j += 1;
        } else if table[i + 1][j] >= table[i][j + 1] {
            ops.push(Op {
                kind: Kind::Delete,
                text: a[i].to_string(),
                old_line: old_offset + i + 1,
                new_line: new_offset + j + 1,
            });
            i += 1;
        } else {
            ops.push(Op {
                kind: Kind::Insert,
                text: b[j].to_string(),
                old_line: old_offset + i + 1,
                new_line: new_offset + j + 1,
            });
            j += 1;
        }
    }
    while i < a.len() {
        ops.push(Op {
            kind: Kind::Delete,
            text: a[i].to_string(),
            old_line: old_offset + i + 1,
            new_line: new_offset + j + 1,
        });
        i += 1;
    }
    while j < b.len() {
        ops.push(Op {
            kind: Kind::Insert,
            text: b[j].to_string(),
            old_line: old_offset + i + 1,
            new_line: new_offset + j + 1,
        });
        j += 1;
    }
}

fn render(ops: &[Op], opts: &DiffOptions) -> String {
    if ops.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, o)| o.kind != Kind::Equal)
        .map(|(i, _)| i)
        .collect();
    if changed.is_empty() {
        return format!("{}\n", cyan("Files are identical"));
    }

    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for &index in &changed {
        let start = index.saturating_sub(opts.context);
        let end = (index + opts.context + 1).min(ops.len());
        match ranges.last_mut() {
            Some((_, last_end)) if start <= *last_end => *last_end = end,
            _ => ranges.push((start, end)),
        }
    }

    for (start, end) in ranges {
        let slice = &ops[start..end];
        let old_start = slice
            .iter()
            .find(|o| o.kind != Kind::Insert)
            .map(|o| o.old_line)
            .unwrap_or_else(|| slice.first().map(|o| o.old_line).unwrap_or(0));
        let new_start = slice
            .iter()
            .find(|o| o.kind != Kind::Delete)
            .map(|o| o.new_line)
            .unwrap_or_else(|| slice.first().map(|o| o.new_line).unwrap_or(0));
        let old_len = slice.iter().filter(|o| o.kind != Kind::Insert).count();
        let new_len = slice.iter().filter(|o| o.kind != Kind::Delete).count();
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            old_start, old_len, new_start, new_len
        ));
        for op in slice {
            let (sign, text) = match op.kind {
                Kind::Equal => (' ', op.text.clone()),
                Kind::Delete => ('-', op.text.clone()),
                Kind::Insert => ('+', op.text.clone()),
            };
            let mut line = format!("{sign}{text}");
            if !line.ends_with('\n') {
                line.push('\n');
            }
            let painted = match op.kind {
                Kind::Equal => line.clone(),
                Kind::Delete => red(&line),
                Kind::Insert => green(&line),
            };
            if opts.color {
                out.push_str(&painted);
            } else {
                out.push_str(&line);
            }
        }
    }
    out
}

fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for b in chunk {
            out.push_str(&format!("{b:02x} "));
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push_str(" |");
        for b in chunk {
            out.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    out
}

pub fn read_input(value: &str) -> Result<Vec<u8>> {
    let path = Path::new(value);
    if path.exists() && path.is_file() {
        std::fs::read(path).with_context(|| format!("cannot read '{}'", path.display()))
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

pub fn print_result(result: &DiffResult, label_a: &str, label_b: &str) {
    print!("{}", result.output);
    println!();
    println!("{}", bold(&format!("--- {label_a}")));
    println!("{}", bold(&format!("+++ {label_b}")));
    println!(
        "{} added, {} removed, {} unchanged | similarity {:.1}%",
        green(&result.added.to_string()),
        red(&result.removed.to_string()),
        result.unchanged,
        result.similarity * 100.0
    );
    if let Some(offset) = result.first_difference {
        println!("first byte difference at offset {offset}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_changes_and_stats() {
        let opts = DiffOptions::default();
        let result = compare(b"a\nb\nc\n", b"a\nx\nc\n", &opts);
        assert_eq!(result.removed, 1);
        assert_eq!(result.added, 1);
        assert!(result.output.contains("-b"));
        assert!(result.output.contains("+x"));
        assert!(result.similarity > 0.0 && result.similarity < 1.0);
        assert_eq!(result.first_difference, Some(2));
    }

    #[test]
    fn identical_input() {
        let result = compare(b"same", b"same", &DiffOptions::default());
        assert_eq!(result.added, 0);
        assert_eq!(result.removed, 0);
        assert!(result.output.contains("identical"));
    }

    #[test]
    fn word_mode() {
        let opts = DiffOptions {
            mode: DiffMode::Words,
            ..Default::default()
        };
        let result = compare(b"one two three", b"one four three", &opts);
        assert!(result.output.contains("-two"));
        assert!(result.output.contains("+four"));
    }
}
