use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Quantum-vulnerable cryptographic primitive detected in source code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CryptoPrimitive {
    Rsa2048,
    Rsa4096,
    RsaGeneric,
    EcdsaP256,
    EcdsaP384,
    EcdsaSecp256k1,
    Ed25519,
    X25519,
    EcdhP256,
    EcdhP384,
    Dsa,
    Dh,
    TripleDes,
    Blowfish,
    Rc4,
    Bls12381,
    Sha1Signing,
    Md5,
    EcdsaGeneric,
    RsaPkcs1v15,
}

impl CryptoPrimitive {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Rsa2048 => "RSA-2048",
            Self::Rsa4096 => "RSA-4096",
            Self::RsaGeneric => "RSA (unknown key size)",
            Self::EcdsaP256 => "ECDSA P-256",
            Self::EcdsaP384 => "ECDSA P-384",
            Self::EcdsaSecp256k1 => "ECDSA secp256k1",
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
            Self::EcdhP256 => "ECDH P-256",
            Self::EcdhP384 => "ECDH P-384",
            Self::Dsa => "DSA",
            Self::Dh => "Diffie-Hellman",
            Self::TripleDes => "3DES",
            Self::Blowfish => "Blowfish",
            Self::Rc4 => "RC4",
            Self::Bls12381 => "BLS12-381",
            Self::Sha1Signing => "SHA-1 (signing)",
            Self::Md5 => "MD5",
            Self::EcdsaGeneric => "ECDSA (unspecified curve)",
            Self::RsaPkcs1v15 => "RSA PKCS#1 v1.5",
        }
    }

    pub fn category(&self) -> PrimitiveCategory {
        match self {
            Self::Rsa2048 | Self::Rsa4096 | Self::RsaGeneric | Self::RsaPkcs1v15 => {
                PrimitiveCategory::AsymmetricEncryption
            }
            Self::EcdsaP256
            | Self::EcdsaP384
            | Self::EcdsaSecp256k1
            | Self::Ed25519
            | Self::Dsa
            | Self::Bls12381
            | Self::EcdsaGeneric => PrimitiveCategory::DigitalSignature,
            Self::X25519 | Self::EcdhP256 | Self::EcdhP384 | Self::Dh => {
                PrimitiveCategory::KeyExchange
            }
            Self::TripleDes | Self::Blowfish | Self::Rc4 => PrimitiveCategory::SymmetricCipher,
            Self::Sha1Signing | Self::Md5 => PrimitiveCategory::HashFunction,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveCategory {
    AsymmetricEncryption,
    DigitalSignature,
    KeyExchange,
    SymmetricCipher,
    HashFunction,
}

/// Risk severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low => "note",
        }
    }
}

/// Usage context affects severity and recommendations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageContext {
    /// Blockchain transaction signing — highest risk.
    BlockchainSigning,
    /// Governance / multisig contracts — systemic risk.
    GovernanceContract,
    /// Light client / bridge — aggregate signature risk.
    LightClient,
    /// TLS / VPN / SSH configuration.
    Tls,
    /// PKI / certificate authority.
    Pki,
    /// General application code.
    General,
    /// Test code — reduced severity.
    Test,
    /// Configuration file.
    Config,
}

/// Programming language or file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    Rust,
    Go,
    Python,
    Java,
    C,
    Cpp,
    JavaScript,
    TypeScript,
    Solidity,
    OpenSslConfig,
    GnuTlsConfig,
    Toml,
    Yaml,
    Pem,
    Certificate,
    Unknown,
}

impl Language {
    pub fn from_extension(ext: &str) -> Self {
        match ext {
            "rs" => Self::Rust,
            "go" => Self::Go,
            "py" | "pyi" => Self::Python,
            "java" => Self::Java,
            "c" | "h" => Self::C,
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Self::Cpp,
            "js" | "mjs" | "cjs" => Self::JavaScript,
            "ts" | "mts" | "cts" => Self::TypeScript,
            "sol" => Self::Solidity,
            "toml" => Self::Toml,
            "yml" | "yaml" => Self::Yaml,
            "pem" | "crt" | "cer" | "key" => Self::Pem,
            "der" | "p12" | "pfx" | "jks" => Self::Certificate,
            "cnf" | "conf" => Self::OpenSslConfig,
            _ => Self::Unknown,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Rust => "Rust",
            Self::Go => "Go",
            Self::Python => "Python",
            Self::Java => "Java",
            Self::C => "C",
            Self::Cpp => "C++",
            Self::JavaScript => "JavaScript",
            Self::TypeScript => "TypeScript",
            Self::Solidity => "Solidity",
            Self::OpenSslConfig => "OpenSSL Config",
            Self::GnuTlsConfig => "GnuTLS Config",
            Self::Toml => "TOML",
            Self::Yaml => "YAML",
            Self::Pem => "PEM",
            Self::Certificate => "Certificate",
            Self::Unknown => "Unknown",
        }
    }
}

/// A single finding from the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Absolute or relative file path.
    pub file_path: PathBuf,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column (0 if unavailable).
    pub column: usize,
    /// The detected primitive.
    pub primitive: CryptoPrimitive,
    /// Risk severity.
    pub severity: Severity,
    /// Usage context.
    pub context: UsageContext,
    /// Language of the source file.
    pub language: Language,
    /// The matched source text (trimmed).
    pub matched_text: String,
    /// Human-readable description.
    pub description: String,
    /// PQC replacement recommendation.
    pub recommendation: Recommendation,
}

/// Recommended NIST PQC replacement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Primary replacement algorithm.
    pub replacement: String,
    /// Migration guidance.
    pub guidance: String,
    /// Hybrid construction suggestion (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid: Option<String>,
    /// Compliance note (CNSA 2.0, PCI DSS 4.0, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<String>,
}

/// CLI / scan configuration.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Directory to scan.
    pub target: PathBuf,
    /// Glob patterns to exclude.
    pub exclude: Vec<String>,
    /// Only scan these languages (empty = all).
    pub languages: Vec<Language>,
    /// Enable CNSA 2.0 mode (stricter recommendations).
    pub cnsa_mode: bool,
    /// Output format.
    pub output_format: OutputFormat,
    /// Number of threads (0 = auto).
    pub threads: usize,
    /// Follow symlinks.
    pub follow_symlinks: bool,
    /// Respect .gitignore.
    pub respect_gitignore: bool,
    /// Include test files.
    pub include_tests: bool,
    /// Minimum severity to report.
    pub min_severity: Severity,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target: PathBuf::from("."),
            exclude: vec![],
            languages: vec![],
            cnsa_mode: false,
            output_format: OutputFormat::Json,
            threads: 0,
            follow_symlinks: false,
            respect_gitignore: true,
            include_tests: true,
            min_severity: Severity::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
    Sarif,
    Summary,
}

/// Complete scan report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub version: String,
    pub scan_target: String,
    pub scan_timestamp: String,
    pub scan_duration_ms: u64,
    pub total_files_scanned: usize,
    pub total_findings: usize,
    pub findings: Vec<Finding>,
    pub summary: ReportSummary,
}

/// Aggregate summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub by_primitive: Vec<PrimitiveStat>,
    pub by_language: Vec<LanguageStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimitiveStat {
    pub primitive: CryptoPrimitive,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageStat {
    pub language: Language,
    pub count: usize,
}
