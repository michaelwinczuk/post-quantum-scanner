use anyhow::Result;
use clap::{Parser, ValueEnum};
use pq_discovery::types::{Language, OutputFormat, Severity};
use pq_discovery::{ScanConfig, scan};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pq-discovery",
    version,
    about = "Post-quantum cryptography vulnerability scanner",
    long_about = "Scans codebases for quantum-vulnerable cryptographic primitives and recommends \
                  NIST PQC replacements (ML-KEM, ML-DSA, SLH-DSA). Supports Rust, Go, Python, \
                  Java, C/C++, JavaScript/TypeScript, Solidity, PEM certificates, and config files."
)]
struct Cli {
    /// Directory to scan (default: current directory)
    #[arg(default_value = ".")]
    target: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "summary")]
    output: OutputArg,

    /// Enable CNSA 2.0 mode (Level V recommendations for NSS compliance)
    #[arg(long)]
    cnsa: bool,

    /// Minimum severity to report
    #[arg(long, value_enum, default_value = "low")]
    min_severity: SeverityArg,

    /// Number of threads (0 = auto-detect)
    #[arg(short = 'j', long, default_value = "0")]
    threads: usize,

    /// Exclude glob patterns (can be repeated)
    #[arg(short = 'x', long = "exclude")]
    exclude: Vec<String>,

    /// Only scan specific languages (can be repeated)
    #[arg(short, long = "lang")]
    languages: Vec<LanguageArg>,

    /// Follow symbolic links
    #[arg(long)]
    follow_symlinks: bool,

    /// Don't respect .gitignore
    #[arg(long)]
    no_gitignore: bool,

    /// Exclude test files from scan results
    #[arg(long)]
    no_tests: bool,

    /// Write output to file instead of stdout
    #[arg(short = 'f', long = "file")]
    output_file: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
enum OutputArg {
    Json,
    Sarif,
    Summary,
}

#[derive(Clone, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, ValueEnum)]
enum LanguageArg {
    Rust,
    Go,
    Python,
    Java,
    C,
    Cpp,
    #[value(name = "js")]
    JavaScript,
    #[value(name = "ts")]
    TypeScript,
    Solidity,
}

impl From<LanguageArg> for Language {
    fn from(val: LanguageArg) -> Self {
        match val {
            LanguageArg::Rust => Language::Rust,
            LanguageArg::Go => Language::Go,
            LanguageArg::Python => Language::Python,
            LanguageArg::Java => Language::Java,
            LanguageArg::C => Language::C,
            LanguageArg::Cpp => Language::Cpp,
            LanguageArg::JavaScript => Language::JavaScript,
            LanguageArg::TypeScript => Language::TypeScript,
            LanguageArg::Solidity => Language::Solidity,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = ScanConfig {
        target: cli.target,
        exclude: cli.exclude,
        languages: cli.languages.into_iter().map(Language::from).collect(),
        cnsa_mode: cli.cnsa,
        output_format: match cli.output {
            OutputArg::Json => OutputFormat::Json,
            OutputArg::Sarif => OutputFormat::Sarif,
            OutputArg::Summary => OutputFormat::Summary,
        },
        threads: cli.threads,
        follow_symlinks: cli.follow_symlinks,
        respect_gitignore: !cli.no_gitignore,
        include_tests: !cli.no_tests,
        min_severity: match cli.min_severity {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        },
    };

    let report = scan(&config)?;

    // Output
    let mut writer: Box<dyn std::io::Write> = match cli.output_file {
        Some(ref path) => Box::new(std::fs::File::create(path)?),
        None => Box::new(std::io::stdout().lock()),
    };

    match config.output_format {
        OutputFormat::Json => pq_discovery::report::output_json(&report, &mut writer)?,
        OutputFormat::Sarif => pq_discovery::sarif::output_sarif(&report, &mut writer)?,
        OutputFormat::Summary => pq_discovery::report::output_summary(&report, &mut writer)?,
    }

    // Exit code: non-zero if critical or high findings
    if report.summary.critical > 0 {
        std::process::exit(2);
    }
    if report.summary.high > 0 {
        std::process::exit(1);
    }

    Ok(())
}
