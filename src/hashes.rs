use crate::models::{Finding, HashObservation};
use anyhow::{anyhow, Result};
use regex::Regex;
use std::fs;
use std::path::Path;

pub fn classify_hash_file(case_dir: &Path, file: &Path) -> Result<()> {
    if !file.exists() || !file.is_file() {
        return Err(anyhow!("hash file must exist"));
    }

    let conn = crate::db::open(case_dir)?;
    let text = fs::read_to_string(file)?;
    let token_re = Regex::new(r#"[A-Za-z0-9/\+\$\.=:_-]{16,}"#).unwrap();

    let mut count = 0usize;
    for cap in token_re.find_iter(&text) {
        let value = cap.as_str();
        if let Some(obs) = classify_hash(value) {
            crate::db::insert_hash(&conn, &obs)?;
            if obs.kind == "MD5_or_NTLM" || obs.kind == "SHA1" {
                crate::db::insert_finding(&conn, &Finding {
                    severity: "medium".to_string(),
                    module: "hashes".to_string(),
                    category: "legacy_hash".to_string(),
                    title: "Legacy or fast hash format detected".to_string(),
                    detail: format!("{}-like value detected.", obs.kind),
                    recommendation: obs.recommendation.clone(),
                    evidence: crate::util::mask_secret(value),
                })?;
            }
            count += 1;
        }
    }

    println!("hash-like values classified: {}", count);
    Ok(())
}

fn classify_hash(value: &str) -> Option<HashObservation> {
    let v = value.trim();
    let kind = if Regex::new(r#"^[a-fA-F0-9]{32}$"#).unwrap().is_match(v) {
        // MD5 and NTLM are both 32 lowercase/uppercase hex characters with
        // no distinguishing marker, so they cannot be told apart from the
        // string alone. Reporting one and never the other (as a duplicate
        // regex checked second used to do) silently misrepresents the
        // tool's advertised NTLM detection -- be honest about the
        // ambiguity instead of guessing.
        "MD5_or_NTLM"
    } else if Regex::new(r#"^[a-fA-F0-9]{40}$"#).unwrap().is_match(v) {
        "SHA1"
    } else if Regex::new(r#"^[a-fA-F0-9]{64}$"#).unwrap().is_match(v) {
        "SHA256"
    } else if Regex::new(r#"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"#).unwrap().is_match(v) {
        "bcrypt"
    } else if Regex::new(r#"^\$argon2(id|i|d)\$"#).unwrap().is_match(v) {
        "argon2"
    } else {
        return None;
    };

    let recommendation = match kind {
        "MD5_or_NTLM" => "This is a 32-character hex value, consistent with either MD5 or an NTLM hash -- the two are indistinguishable by format alone. If it is a password hash: MD5 is fast/legacy and NTLM is Windows-specific; migrate to Argon2id/bcrypt where applicable and protect NTLM hashes carefully.",
        "SHA1" => "SHA1 is legacy for many security uses. Use modern alternatives.",
        "SHA256" => "SHA256 is a general cryptographic hash. For passwords, use Argon2id/bcrypt/scrypt with salts.",
        "bcrypt" => "bcrypt is suitable for password hashing when configured with an appropriate cost.",
        "argon2" => "Argon2 is suitable for password hashing when configured correctly.",
        _ => "Review hash usage.",
    };

    Some(HashObservation {
        value: crate::util::mask_secret(v),
        kind: kind.to_string(),
        recommendation: recommendation.to_string(),
    })
}
