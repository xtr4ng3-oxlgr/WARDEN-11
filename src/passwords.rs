use crate::models::{Finding, PasswordObservation};
use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub fn check_password_file(case_dir: &Path, file: &Path) -> Result<()> {
    if !file.exists() || !file.is_file() {
        return Err(anyhow!("password file must exist"));
    }

    let conn = crate::db::open(case_dir)?;
    let text = fs::read_to_string(file)?;
    let mut seen = HashSet::new();
    let mut weak = 0usize;
    let mut reused = 0usize;
    let mut total = 0usize;

    for (idx, raw) in text.lines().enumerate() {
        let pw = raw.trim();
        if pw.is_empty() {
            continue;
        }

        total += 1;
        let mut obs = analyze_password(idx + 1, pw);

        if !seen.insert(pw.to_string()) {
            obs.issues.push("reused_in_file".to_string());
            obs.score = obs.score.saturating_sub(20);
            reused += 1;
        }

        if obs.score < 50 {
            weak += 1;
        }

        crate::db::insert_password(&conn, &obs)?;
    }

    if weak > 0 {
        crate::db::insert_finding(&conn, &Finding {
            severity: if weak >= 10 { "high" } else { "medium" }.to_string(),
            module: "passwords".to_string(),
            category: "hygiene".to_string(),
            title: "Weak password hygiene detected".to_string(),
            detail: format!("{} weak entries found in an owner-provided password list.", weak),
            recommendation: "Use unique long passphrases and a password manager. Avoid reuse.".to_string(),
            evidence: file.display().to_string(),
        })?;
    }

    if reused > 0 {
        crate::db::insert_finding(&conn, &Finding {
            severity: "medium".to_string(),
            module: "passwords".to_string(),
            category: "reuse".to_string(),
            title: "Repeated passwords in file".to_string(),
            detail: format!("{} repeated password entries found.", reused),
            recommendation: "Avoid password reuse across services.".to_string(),
            evidence: file.display().to_string(),
        })?;
    }

    println!("password entries checked: {}", total);
    println!("weak entries: {}", weak);
    println!("reused entries: {}", reused);
    Ok(())
}

fn analyze_password(index: usize, pw: &str) -> PasswordObservation {
    let mut score = 100u32;
    let mut issues = Vec::new();

    if pw.len() < 10 {
        score = score.saturating_sub(35);
        issues.push("too_short".to_string());
    } else if pw.len() < 14 {
        score = score.saturating_sub(15);
        issues.push("could_be_longer".to_string());
    }

    if !pw.chars().any(|c| c.is_ascii_lowercase()) {
        score = score.saturating_sub(10);
        issues.push("missing_lowercase".to_string());
    }
    if !pw.chars().any(|c| c.is_ascii_uppercase()) {
        score = score.saturating_sub(10);
        issues.push("missing_uppercase".to_string());
    }
    if !pw.chars().any(|c| c.is_ascii_digit()) {
        score = score.saturating_sub(10);
        issues.push("missing_digit".to_string());
    }
    if !pw.chars().any(|c| !c.is_ascii_alphanumeric()) {
        score = score.saturating_sub(10);
        issues.push("missing_symbol".to_string());
    }

    let lower = pw.to_lowercase();
    for bad in ["password", "admin", "qwerty", "letmein", "welcome", "123456", "111111", "iloveyou"] {
        if lower.contains(bad) {
            score = score.saturating_sub(35);
            issues.push(format!("common_pattern_{}", bad));
            break;
        }
    }

    if has_repetition(pw) {
        score = score.saturating_sub(15);
        issues.push("repetition_pattern".to_string());
    }

    let label = if score >= 80 {
        "strong"
    } else if score >= 60 {
        "acceptable"
    } else if score >= 40 {
        "weak"
    } else {
        "critical"
    };

    PasswordObservation {
        index,
        score,
        label: label.to_string(),
        issues,
    }
}

fn has_repetition(pw: &str) -> bool {
    let chars: Vec<char> = pw.chars().collect();
    for w in chars.windows(3) {
        if w[0] == w[1] && w[1] == w[2] {
            return true;
        }
    }
    false
}
