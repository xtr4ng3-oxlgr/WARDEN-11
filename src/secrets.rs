use crate::models::{Finding, SecretObservation};
use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

const ALLOWED_EXT: &[&str] = &[
    "env", "json", "yaml", "yml", "toml", "ini", "conf", "config", "txt", "md",
    "py", "js", "ts", "php", "java", "kt", "rs", "go", "cs", "xml", "properties"
];

pub fn scan_local_secrets(case_dir: &Path, target: &Path) -> Result<()> {
    if !target.exists() || !target.is_dir() {
        return Err(anyhow!("target must be an existing folder"));
    }

    let conn = crate::db::open(case_dir)?;
    let regexes = crate::util::regexes();
    let mut files = 0usize;
    let mut hits = 0usize;

    println!("secrets patrol: {}", target.display());

    for entry in WalkDir::new(target).follow_links(false).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() || should_skip(path) {
            continue;
        }

        let name = path.file_name().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
        let ext = path.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();

        // A dotfile like `.env` or `.npmrc` has no extension by Rust's
        // definition (the leading dot makes the whole name the stem), so
        // matching on `path.extension()` alone silently skips the single
        // most common real-world secrets file. Fall back to checking the
        // name itself (minus its leading dot) against the allow-list.
        let is_allowed = ALLOWED_EXT.contains(&ext.as_str())
            || (name.starts_with('.') && ALLOWED_EXT.iter().any(|e| *e == &name[1..]));
        if !is_allowed {
            continue;
        }

        let meta = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if meta.len() > 8 * 1024 * 1024 {
            continue;
        }

        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => continue,
        };

        files += 1;

        for (idx, line) in text.lines().enumerate() {
            for (kind, re) in &regexes {
                if let Some(m) = re.find(line) {
                    let obs = SecretObservation {
                        file_path: crate::util::html_escape(&path.to_string_lossy()),
                        line: idx + 1,
                        kind: kind.to_string(),
                        masked_value: crate::util::mask_secret(m.as_str()),
                        context: crate::util::clean_line_masked(line, m.as_str(), 160),
                    };
                    crate::db::insert_secret(&conn, &obs)?;
                    crate::db::insert_finding(&conn, &Finding {
                        severity: if *kind == "private_key" || *kind == "aws_access_key" || *kind == "github_token" { "high" } else { "medium" }.to_string(),
                        module: "secrets".to_string(),
                        category: kind.to_string(),
                        title: "Potential secret detected".to_string(),
                        detail: format!("{}:{} matched {}", path.display(), idx + 1, kind),
                        recommendation: "Rotate the secret if real, remove it from source control, and move it to a secure secret store.".to_string(),
                        evidence: format!("{}:{}", path.display(), idx + 1),
                    })?;
                    hits += 1;
                }
            }
        }
    }

    println!("files scanned: {}", files);
    println!("potential secrets: {}", hits);
    Ok(())
}

fn should_skip(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    let blocked = [
        "\\node_modules\\", "\\.git\\", "\\target\\", "\\build\\", "\\dist\\",
        "/node_modules/", "/.git/", "/target/", "/build/", "/dist/",
    ];
    blocked.iter().any(|x| lower.contains(x))
}
