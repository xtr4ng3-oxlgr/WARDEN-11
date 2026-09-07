use crate::models::CaseMeta;
use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

pub fn create_case(case_dir: &Path, title: Option<String>) -> Result<()> {
    if case_dir.exists() {
        return Err(anyhow!("case already exists: {}", case_dir.display()));
    }

    crate::util::ensure_dir(case_dir)?;
    crate::util::ensure_dir(&crate::util::reports_dir(case_dir))?;
    crate::util::ensure_dir(&crate::util::exports_dir(case_dir))?;

    let conn = crate::db::open(case_dir)?;

    let name = case_dir.file_name()
        .map(|x| x.to_string_lossy().to_string())
        .unwrap_or_else(|| "warden11-case".to_string());

    let meta = CaseMeta {
        name: name.clone(),
        title: title.unwrap_or_else(|| name.clone()),
        created_at: crate::util::now_iso(),
        tool: crate::APP.to_string(),
        version: crate::VERSION.to_string(),
        author: crate::AUTHOR.to_string(),
    };

    crate::db::save_meta(&conn, &meta)?;
    fs::write(crate::util::scope_path(case_dir), "[]\n")?;
    fs::write(case_dir.join("CASE.md"), format!(
        "# {}\n\nCreated: {}\nTool: WARDEN-11 {}\nAuthor: xtr4ng3\n\nAuthorized cyber patrol workspace.\n",
        meta.title, meta.created_at, meta.version
    ))?;

    println!("WARDEN-11 case created: {}", case_dir.display());
    Ok(())
}

pub fn status(case_dir: &Path) -> Result<()> {
    let conn = crate::db::open(case_dir)?;
    let meta = crate::db::read_meta(&conn)?;
    let findings = crate::db::read_findings(&conn)?;
    let web = crate::db::read_web(&conn)?;
    let secrets = crate::db::read_secrets(&conn)?;
    let passwords = crate::db::read_passwords(&conn)?;
    let hashes = crate::db::read_hashes(&conn)?;

    println!("WARDEN-11 STATUS");
    println!("case      : {}", meta.name);
    println!("title     : {}", meta.title);
    println!("created   : {}", meta.created_at);
    println!("findings  : {}", findings.len());
    println!("web       : {}", web.len());
    println!("secrets   : {}", secrets.len());
    println!("passwords : {}", passwords.len());
    println!("hashes    : {}", hashes.len());
    println!("reports   : {}", crate::util::reports_dir(case_dir).display());
    Ok(())
}
