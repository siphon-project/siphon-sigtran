//! Every `sigtran.yaml` example shipped in the README and the docs parses and
//! validates. Guards the published examples against config-model and YAML
//! parser changes.

#![allow(clippy::disallowed_methods)] // a test harness: its waits run on test threads that are not handler threads
use std::path::{Path, PathBuf};

use siphon_sigtran::config::Config;

/// The markdown files that carry `sigtran.yaml` examples.
fn markdown_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("README.md")];
    let mut dirs = vec![root.join("docs")];
    while let Some(dir) = dirs.pop() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
            .map(|entry| entry.expect("dir entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                files.push(path);
            }
        }
    }
    files
}

/// The fenced ```yaml blocks of one markdown file, with their line numbers.
fn yaml_blocks(text: &str) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (index, line) in text.lines().enumerate() {
        match current.as_mut() {
            None if line.trim_start().starts_with("```yaml") => {
                current = Some((index + 1, String::new()));
            }
            Some(_) if line.trim_start().starts_with("```") => {
                blocks.extend(current.take());
            }
            Some((_, body)) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {}
        }
    }
    blocks
}

/// A block is a `sigtran.yaml` example unless it is the host's own
/// `siphon.yaml` (the `extensions:` mount point).
fn is_sigtran_config(block: &str) -> bool {
    !block
        .lines()
        .any(|line| line.trim_start().starts_with("extensions:"))
}

/// A block that documents one section (`tcap:`, `isup_screening:`) leaves out
/// the `node:` block every file needs; give it a synthetic one so the section
/// itself is still parsed and validated.
fn complete(block: &str) -> String {
    if block.lines().any(|line| line.starts_with("node:")) {
        block.to_string()
    } else {
        format!("node: {{ point_code: 1000, variant: itu }}\n{block}")
    }
}

#[test]
fn every_documented_sigtran_yaml_example_parses() {
    let mut checked = 0;
    for path in markdown_files() {
        let text = std::fs::read_to_string(&path).expect("read markdown");
        for (line, block) in yaml_blocks(&text) {
            if !is_sigtran_config(&block) {
                continue;
            }
            if let Err(e) = Config::parse(&complete(&block)) {
                panic!("{}:{line}: example does not parse: {e}", path.display());
            }
            checked += 1;
        }
    }
    assert!(
        checked >= 8,
        "expected the shipped examples, found {checked}"
    );
}
