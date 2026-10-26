//! Target sitemap populated by the spider, scanner and proxy imports.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SitemapEntry {
    pub url: String,
    pub method: String,
    pub status: u16,
    #[serde(default)]
    pub mime: String,
    #[serde(default)]
    pub length: usize,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub found_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Sitemap {
    #[serde(skip)]
    path: PathBuf,
    #[serde(default)]
    pub entries: BTreeMap<String, SitemapEntry>,
}

impl Sitemap {
    pub fn load(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                path,
                entries: BTreeMap::new(),
            });
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read sitemap '{}'", path.display()))?;
        if text.trim().is_empty() {
            return Ok(Self {
                path,
                entries: BTreeMap::new(),
            });
        }
        let mut sitemap: Sitemap = serde_json::from_str(&text)
            .with_context(|| format!("cannot parse sitemap '{}'", path.display()))?;
        sitemap.path = path;
        Ok(sitemap)
    }

    pub fn save(&self) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        crate::config::atomic_write(&self.path, text.as_bytes())
    }

    pub fn add(&mut self, entry: SitemapEntry) {
        self.entries.insert(entry.url.clone(), entry);
    }

    pub fn add_response(
        &mut self,
        url: &str,
        method: &str,
        status: u16,
        mime: &str,
        body: &[u8],
        source: &str,
    ) {
        let title = extract_title(body);
        let params = query_params(url);
        self.add(SitemapEntry {
            url: url.to_string(),
            method: method.to_string(),
            status,
            mime: mime.to_string(),
            length: body.len(),
            title,
            params,
            source: source.to_string(),
            found_at: crate::util::now_rfc3339(),
        });
    }

    pub fn get(&self, url: &str) -> Option<&SitemapEntry> {
        self.entries.get(url)
    }

    pub fn list(&self) -> Vec<&SitemapEntry> {
        self.entries.values().collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Render an indented tree grouped by origin and path segment.
    pub fn tree(&self) -> Vec<String> {
        #[derive(Default)]
        struct Node {
            entry: Option<SitemapEntry>,
            children: BTreeMap<String, Node>,
        }
        let mut roots: BTreeMap<String, Node> = BTreeMap::new();
        for entry in self.entries.values() {
            let parsed = match url::Url::parse(&entry.url) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let origin = format!(
                "{}://{}{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or(""),
                parsed.port().map(|p| format!(":{p}")).unwrap_or_default()
            );
            let mut node = roots.entry(origin).or_default();
            let path = parsed.path();
            for segment in path.split('/').filter(|s| !s.is_empty()) {
                node = node.children.entry(segment.to_string()).or_default();
            }
            node.entry = Some(entry.clone());
        }

        fn walk(node: &Node, depth: usize, out: &mut Vec<String>) {
            let indent = "  ".repeat(depth);
            for (name, child) in &node.children {
                match &child.entry {
                    Some(entry) => out.push(format!(
                        "{indent}{}/  [{} {} {}]",
                        name,
                        entry.status,
                        entry.method,
                        crate::util::format_size(entry.length)
                    )),
                    None => out.push(format!("{indent}{name}/")),
                }
                walk(child, depth + 1, out);
            }
        }

        let mut out = Vec::new();
        for (origin, node) in &roots {
            out.push(origin.clone());
            walk(node, 1, &mut out);
        }
        out
    }
}

pub fn extract_title(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    let start = match lower.find("<title") {
        Some(i) => i,
        None => return String::new(),
    };
    let after = match lower[start..].find('>') {
        Some(i) => start + i + 1,
        None => return String::new(),
    };
    let end = match lower[after..].find("</title>") {
        Some(i) => after + i,
        None => return String::new(),
    };
    text[after..end].trim().chars().take(120).collect()
}

pub fn query_params(url: &str) -> Vec<String> {
    match url::Url::parse(url) {
        Ok(url) => url.query_pairs().map(|(k, _)| k.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

pub fn default_sitemap_path(project: &crate::storage::Project) -> PathBuf {
    project.sitemap_path()
}

/// Helper used by CLI to load a sitemap from an arbitrary project root.
pub fn load_from(root: &Path) -> Result<Sitemap> {
    Sitemap::load(root.join(crate::storage::SITEMAP_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_and_params() {
        assert_eq!(
            extract_title(b"<html><title>Hello &amp; world</title></html>"),
            "Hello &amp; world"
        );
        assert_eq!(extract_title(b"no title"), "");
        let params = query_params("http://example.com/a?x=1&y=2");
        assert_eq!(params, vec!["x", "y"]);
    }

    #[test]
    fn sitemap_roundtrip_and_tree() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sitemap.json");
        let mut map = Sitemap::load(path.clone()).unwrap();
        map.add_response(
            "http://example.com/a/b",
            "GET",
            200,
            "text/html",
            b"<title>B</title>",
            "spider",
        );
        map.save().unwrap();
        let reloaded = Sitemap::load(path).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded.get("http://example.com/a/b").unwrap().title, "B");
        let tree = reloaded.tree();
        assert!(tree.iter().any(|line| line.contains("example.com")));
        assert!(tree.iter().any(|line| line.contains("b")));
    }
}
