use anyhow::{anyhow, Result};
use serde_json;
use std::fs;
use std::path::Path;
use url::Url;

pub fn read_scope(case_dir: &Path) -> Result<Vec<String>> {
    let path = crate::util::scope_path(case_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path)?;
    let scope: Vec<String> = serde_json::from_str(&text).unwrap_or_default();
    Ok(scope)
}

pub fn add_scope(case_dir: &Path, url: &str) -> Result<()> {
    let parsed = Url::parse(url)?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(anyhow!("only http/https URLs are supported"));
    }

    let mut scope = read_scope(case_dir)?;
    let clean = parsed.to_string();
    if !scope.contains(&clean) {
        scope.push(clean.clone());
    }

    fs::write(crate::util::scope_path(case_dir), serde_json::to_string_pretty(&scope)?)?;
    println!("scope added: {}", clean);
    Ok(())
}

pub fn show_scope(case_dir: &Path) -> Result<()> {
    let scope = read_scope(case_dir)?;
    println!("AUTHORIZED SCOPE");
    if scope.is_empty() {
        println!("  [empty]");
    }
    for s in scope {
        println!("  - {}", s);
    }
    Ok(())
}

pub fn same_origin(base: &str, candidate: &str) -> bool {
    let a = Url::parse(base);
    let b = Url::parse(candidate);
    if let (Ok(a), Ok(b)) = (a, b) {
        return a.scheme() == b.scheme()
            && a.domain() == b.domain()
            && a.port_or_known_default() == b.port_or_known_default();
    }
    false
}
