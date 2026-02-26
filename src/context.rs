use crate::types::{Language, UsageContext};
use std::path::Path;

/// Detect usage context from file path and surrounding source lines.
pub fn detect_context(path: &Path, language: Language, line_text: &str, surrounding: &[&str]) -> UsageContext {
    // Check language-specific context first (more precise than path-based)
    if let Some(ctx) = context_from_language(language, line_text, surrounding) {
        return ctx;
    }

    // Check file path patterns
    if let Some(ctx) = context_from_path(path) {
        return ctx;
    }

    // Check if this is test code
    if is_test_context(path, language, surrounding) {
        return UsageContext::Test;
    }

    UsageContext::General
}

/// Detect context from file path.
fn context_from_path(path: &Path) -> Option<UsageContext> {
    let path_str = path.to_string_lossy().to_lowercase();

    // Test paths
    if path_str.contains("/test/")
        || path_str.contains("/tests/")
        || path_str.contains("/spec/")
        || path_str.contains("/__tests__/")
        || path_str.contains("_test.")
        || path_str.contains(".test.")
        || path_str.contains(".spec.")
        || path_str.contains("/fixtures/")
        || path_str.contains("/testdata/")
    {
        return Some(UsageContext::Test);
    }

    // TLS / SSL config
    if path_str.contains("tls")
        || path_str.contains("ssl")
        || path_str.contains("nginx")
        || path_str.contains("haproxy")
        || path_str.contains("apache")
    {
        return Some(UsageContext::Tls);
    }

    // Certificate / PKI paths
    if path_str.contains("/certs/")
        || path_str.contains("/pki/")
        || path_str.contains("/ca/")
        || path_str.contains("certificate")
    {
        return Some(UsageContext::Pki);
    }

    // Blockchain paths
    if path_str.contains("ethereum")
        || path_str.contains("solidity")
        || path_str.contains("contracts/")
        || path_str.contains("hardhat")
        || path_str.contains("foundry")
        || path_str.contains("truffle")
        || path_str.contains("blockchain")
        || path_str.contains("web3")
    {
        return Some(UsageContext::BlockchainSigning);
    }

    // Config files
    if path_str.ends_with(".cnf")
        || path_str.ends_with(".conf")
        || path_str.ends_with(".cfg")
        || path_str.contains("openssl")
        || path_str.contains("gnutls")
    {
        return Some(UsageContext::Config);
    }

    None
}

/// Detect context from language and source content.
fn context_from_language(language: Language, line_text: &str, surrounding: &[&str]) -> Option<UsageContext> {
    let combined = once_with_surrounding(line_text, surrounding);

    match language {
        Language::Solidity => {
            // Check for governance patterns
            if combined.contains("Governor")
                || combined.contains("GnosisSafe")
                || combined.contains("Timelock")
                || combined.contains("MultiSig")
                || combined.contains("onlyOwner")
                || combined.contains("AccessControl")
            {
                return Some(UsageContext::GovernanceContract);
            }
            // All Solidity is blockchain context
            Some(UsageContext::BlockchainSigning)
        }

        Language::Rust | Language::Go | Language::TypeScript | Language::JavaScript | Language::Python => {
            // Light client detection
            if combined.contains("light_client")
                || combined.contains("LightClient")
                || combined.contains("sync_committee")
                || combined.contains("SyncCommittee")
                || combined.contains("beacon")
            {
                return Some(UsageContext::LightClient);
            }

            // Blockchain transaction signing
            if combined.contains("signTransaction")
                || combined.contains("sign_transaction")
                || combined.contains("eth_sign")
                || combined.contains("personal_sign")
                || combined.contains("wallet")
                || combined.contains("web3")
                || combined.contains("ethers")
                || combined.contains("solana")
                || combined.contains("substrate")
            {
                return Some(UsageContext::BlockchainSigning);
            }

            // TLS context
            if combined.contains("tls::")
                || combined.contains("TlsConfig")
                || combined.contains("tls.Config")
                || combined.contains("rustls")
                || combined.contains("ssl_context")
                || combined.contains("SSLContext")
                || combined.contains("https")
            {
                return Some(UsageContext::Tls);
            }

            None
        }

        Language::C | Language::Cpp => {
            // OpenSSL TLS
            if combined.contains("SSL_CTX")
                || combined.contains("SSL_new")
                || combined.contains("SSL_connect")
                || combined.contains("EVP_")
            {
                return Some(UsageContext::Tls);
            }
            None
        }

        Language::Java => {
            if combined.contains("SSLContext")
                || combined.contains("TrustManager")
                || combined.contains("KeyManager")
                || combined.contains("javax.net.ssl")
            {
                return Some(UsageContext::Tls);
            }
            None
        }

        _ => None,
    }
}

/// Check if surrounding code indicates test context.
fn is_test_context(path: &Path, language: Language, surrounding: &[&str]) -> bool {
    let combined = surrounding.join(" ");

    match language {
        Language::Rust => {
            combined.contains("#[test]")
                || combined.contains("#[cfg(test)]")
                || combined.contains("mod tests")
        }
        Language::Python => {
            combined.contains("def test_")
                || combined.contains("class Test")
                || combined.contains("unittest")
                || combined.contains("pytest")
        }
        Language::Go => {
            path.to_string_lossy().ends_with("_test.go")
                || combined.contains("func Test")
                || combined.contains("testing.T")
        }
        Language::Java => {
            combined.contains("@Test")
                || combined.contains("@Before")
                || combined.contains("junit")
        }
        Language::JavaScript | Language::TypeScript => {
            combined.contains("describe(")
                || combined.contains("it(")
                || combined.contains("test(")
                || combined.contains("expect(")
                || combined.contains("jest")
                || combined.contains("mocha")
        }
        _ => false,
    }
}

fn once_with_surrounding(line: &str, surrounding: &[&str]) -> String {
    let mut buf = String::with_capacity(line.len() + surrounding.iter().map(|s| s.len()).sum::<usize>() + surrounding.len());
    buf.push_str(line);
    for s in surrounding {
        buf.push(' ');
        buf.push_str(s);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_context_test() {
        let path = Path::new("src/tests/crypto_test.rs");
        let ctx = detect_context(path, Language::Rust, "", &[]);
        assert_eq!(ctx, UsageContext::Test);
    }

    #[test]
    fn test_path_context_tls() {
        let path = Path::new("config/tls/server.conf");
        let ctx = detect_context(path, Language::OpenSslConfig, "", &[]);
        assert_eq!(ctx, UsageContext::Tls);
    }

    #[test]
    fn test_solidity_governance() {
        let path = Path::new("contracts/Governance.sol");
        let ctx = detect_context(
            path,
            Language::Solidity,
            "contract MyGovernor is Governor {",
            &[],
        );
        assert_eq!(ctx, UsageContext::GovernanceContract);
    }

    #[test]
    fn test_solidity_default_blockchain() {
        let path = Path::new("src/Token.sol");
        let ctx = detect_context(path, Language::Solidity, "ecrecover(hash, v, r, s)", &[]);
        assert_eq!(ctx, UsageContext::BlockchainSigning);
    }

    #[test]
    fn test_rust_test_context() {
        let path = Path::new("src/crypto.rs");
        let ctx = detect_context(
            path,
            Language::Rust,
            "let key = rsa::RsaPrivateKey::new()",
            &["#[test]", "fn test_keygen() {"],
        );
        assert_eq!(ctx, UsageContext::Test);
    }

    #[test]
    fn test_blockchain_path() {
        let path = Path::new("ethereum/contracts/Bridge.sol");
        let ctx = detect_context(path, Language::Solidity, "", &[]);
        assert_eq!(ctx, UsageContext::BlockchainSigning);
    }
}
