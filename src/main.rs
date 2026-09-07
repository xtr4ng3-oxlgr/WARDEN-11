mod case;
mod db;
mod hashes;
mod models;
mod passwords;
mod report;
mod scope;
mod secrets;
mod util;
mod web;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

const APP: &str = "WARDEN-11";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHOR: &str = "xtr4ng3";

#[derive(Parser, Debug)]
#[command(name = "warden11")]
#[command(author = "xtr4ng3")]
#[command(version)]
#[command(about = "Authorized cyber patrol workbench", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create a new authorized patrol workspace.
    New {
        /// Case directory.
        case_dir: PathBuf,

        /// Optional title.
        #[arg(short, long)]
        title: Option<String>,
    },

    /// Add an authorized URL scope to the case.
    ScopeAdd {
        /// Case directory.
        case_dir: PathBuf,

        /// URL to add.
        url: String,
    },

    /// Show current scope.
    Scope {
        /// Case directory.
        case_dir: PathBuf,
    },

    /// Run passive web review against authorized scope.
    WebAudit {
        /// Case directory.
        case_dir: PathBuf,

        /// Required confirmation for authorized targets.
        #[arg(long)]
        yes_authorized: bool,
    },

    /// Scan local folders for secrets and risky config artifacts.
    Secrets {
        /// Case directory.
        case_dir: PathBuf,

        /// Folder to scan.
        target: PathBuf,
    },

    /// Check password hygiene in a user-owned text file.
    Passwords {
        /// Case directory.
        case_dir: PathBuf,

        /// File with one password candidate per line.
        file: PathBuf,
    },

    /// Classify hash formats from a file.
    Hashes {
        /// Case directory.
        case_dir: PathBuf,

        /// File containing hashes or text with hashes.
        file: PathBuf,
    },

    /// Generate HTML, JSON and SARIF reports.
    Report {
        /// Case directory.
        case_dir: PathBuf,
    },

    /// Show case status.
    Status {
        /// Case directory.
        case_dir: PathBuf,
    },

    /// Create default rules file.
    Rules {
        /// Output file.
        #[arg(default_value = "warden11.rules")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::New { case_dir, title } => case::create_case(&case_dir, title)?,
        Commands::ScopeAdd { case_dir, url } => scope::add_scope(&case_dir, &url)?,
        Commands::Scope { case_dir } => scope::show_scope(&case_dir)?,
        Commands::WebAudit { case_dir, yes_authorized } => web::run_web_audit(&case_dir, yes_authorized)?,
        Commands::Secrets { case_dir, target } => secrets::scan_local_secrets(&case_dir, &target)?,
        Commands::Passwords { case_dir, file } => passwords::check_password_file(&case_dir, &file)?,
        Commands::Hashes { case_dir, file } => hashes::classify_hash_file(&case_dir, &file)?,
        Commands::Report { case_dir } => report::generate_reports(&case_dir)?,
        Commands::Status { case_dir } => case::status(&case_dir)?,
        Commands::Rules { output } => util::write_default_rules(&output)?,
    }

    Ok(())
}
