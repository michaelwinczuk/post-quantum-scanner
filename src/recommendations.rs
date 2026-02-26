use crate::types::{CryptoPrimitive, Recommendation, Severity, UsageContext};

/// Compute severity based on the primitive and the usage context.
pub fn compute_severity(primitive: CryptoPrimitive, context: UsageContext) -> Severity {
    use CryptoPrimitive::*;
    use UsageContext::*;

    match (primitive, context) {
        // Blockchain contexts — always critical
        (EcdsaSecp256k1, BlockchainSigning) => Severity::Critical,
        (EcdsaSecp256k1, GovernanceContract) => Severity::Critical,
        (Ed25519, BlockchainSigning) => Severity::Critical,
        (Bls12381, LightClient) => Severity::Critical,
        (_, GovernanceContract) => Severity::Critical,
        (_, LightClient) => Severity::Critical,
        (_, BlockchainSigning) => Severity::Critical,

        // Test code — reduced severity
        (TripleDes | Blowfish | Rc4, Test) => Severity::Low,
        (Sha1Signing | Md5, Test) => Severity::Low,
        (_, Test) => Severity::Medium,

        // Weak symmetric / hash — always at least high outside tests
        (TripleDes | Blowfish | Rc4, _) => Severity::High,
        (Sha1Signing | Md5, _) => Severity::High,

        // RSA — high for 2048, medium for 4096
        (Rsa2048 | RsaPkcs1v15, Tls | Pki) => Severity::High,
        (Rsa2048 | RsaPkcs1v15, _) => Severity::High,
        (Rsa4096, _) => Severity::Medium,
        (RsaGeneric, _) => Severity::High,

        // ECC curves
        (EcdsaP256 | EcdhP256, Tls) => Severity::High,
        (EcdsaP256 | EcdhP256, _) => Severity::High,
        (EcdsaP384 | EcdhP384, _) => Severity::Medium,
        (EcdsaSecp256k1, _) => Severity::High,
        (EcdsaGeneric, _) => Severity::High,

        // Ed25519 / X25519
        (Ed25519, _) => Severity::High,
        (X25519, _) => Severity::High,

        // DSA / DH
        (Dsa, _) => Severity::High,
        (Dh, _) => Severity::High,

        // BLS12-381
        (Bls12381, _) => Severity::High,
    }
}

/// Generate a NIST PQC recommendation for a detected primitive + context.
pub fn recommend(
    primitive: CryptoPrimitive,
    context: UsageContext,
    cnsa_mode: bool,
) -> Recommendation {
    use CryptoPrimitive::*;
    use UsageContext::*;

    // CNSA 2.0 mode uses Level V everywhere
    if cnsa_mode {
        return recommend_cnsa(primitive, context);
    }

    match (primitive, context) {
        // ── Blockchain-specific recommendations ──
        (EcdsaSecp256k1, BlockchainSigning) => Recommendation {
            replacement: "ML-DSA-65 (FIPS 204) via ERC-4337 smart account".into(),
            guidance: "EOAs have no upgrade path. Migrate to ERC-4337 account abstraction \
                       with ML-DSA-65 signature validation. secp256k1 has permanent on-chain \
                       public key exposure and mempool visibility enabling quantum front-running."
                .into(),
            hybrid: Some("FN-DSA-512 as interim (5x smaller signatures for on-chain cost)".into()),
            compliance: Some(
                "CRITICAL: Irreversible value transfer with no post-compromise remediation."
                    .into(),
            ),
        },
        (EcdsaSecp256k1, GovernanceContract) => Recommendation {
            replacement: "ML-DSA-65 (FIPS 204) with upgraded governance contract".into(),
            guidance: "Governance/multisig contracts are systemic risk — one compromised key \
                       drains entire protocol. Upgrade to PQ-safe signature verification. \
                       Consider threshold ML-DSA for multisig replacement."
                .into(),
            hybrid: None,
            compliance: Some(
                "CRITICAL+: Systemic risk. One compromised multisig signer can upgrade \
                 protocol contracts to drain all user funds."
                    .into(),
            ),
        },
        (Bls12381, LightClient) => Recommendation {
            replacement: "STARK-compressed ML-DSA for validator attestations".into(),
            guidance: "BLS12-381 aggregate signatures are quantum-vulnerable. Light client \
                       security breaks under quantum attack — forged sync committee signatures \
                       can feed fraudulent headers. Migrate to STARK-compressed ML-DSA proofs."
                .into(),
            hybrid: None,
            compliance: Some(
                "CRITICAL: Light client protocol integrity depends on BLS aggregate signatures."
                    .into(),
            ),
        },
        (Ed25519, BlockchainSigning) => Recommendation {
            replacement: "ML-DSA-65 (FIPS 204)".into(),
            guidance: "Ed25519 used in Solana/Polkadot transaction signing. Same quantum risk \
                       profile as secp256k1: permanent on-chain key exposure and mempool \
                       visibility. Migrate to ML-DSA-65 via account abstraction."
                .into(),
            hybrid: Some("Hybrid Ed25519 + ML-DSA-65 during transition".into()),
            compliance: None,
        },

        // ── RSA recommendations ──
        (Rsa2048, Tls) | (RsaGeneric, Tls) => Recommendation {
            replacement: "ML-KEM-768 (FIPS 203) for key exchange + ML-DSA-65 (FIPS 204) for authentication".into(),
            guidance: "Migrate TLS to hybrid key exchange (X25519+ML-KEM-768) as supported \
                       by Chrome, Cloudflare, AWS. Use ML-DSA-65 for server authentication."
                .into(),
            hybrid: Some("X25519 + ML-KEM-768 (concatenation-then-KDF combiner)".into()),
            compliance: Some("CNSA 2.0: RSA-2048 non-compliant by 2030. Migrate by 2028 for 2-year buffer.".into()),
        },
        (Rsa2048, _) | (RsaPkcs1v15, _) => Recommendation {
            replacement: "ML-KEM-768 (key exchange) + ML-DSA-65 (signatures)".into(),
            guidance: "RSA-2048 provides ~112-bit classical security, vulnerable to Shor's \
                       algorithm. ML-KEM-768 provides NIST Level III (192-bit) security."
                .into(),
            hybrid: Some("RSA-2048 + ML-KEM-768 hybrid during transition".into()),
            compliance: Some("CNSA 2.0 Phase 3 (2030): RSA-2048 will be non-compliant.".into()),
        },
        (Rsa4096, _) => Recommendation {
            replacement: "ML-KEM-1024 (key exchange) + ML-DSA-87 (signatures)".into(),
            guidance: "RSA-4096 provides ~140-bit classical security. Migration to ML-KEM-1024 \
                       (Level V, 256-bit) provides maximum security margin."
                .into(),
            hybrid: Some("RSA-4096 + ML-KEM-1024 hybrid during transition".into()),
            compliance: Some("Lower urgency than RSA-2048 but still quantum-vulnerable.".into()),
        },
        (RsaGeneric, _) => Recommendation {
            replacement: "ML-KEM-768 (key exchange) + ML-DSA-65 (signatures)".into(),
            guidance: "RSA detected (key size unknown). Determine key size and migrate: \
                       2048-bit → ML-KEM-768, 4096-bit → ML-KEM-1024."
                .into(),
            hybrid: Some("Hybrid classical+PQ construction during transition".into()),
            compliance: None,
        },

        // ── ECDSA / ECC recommendations ──
        (EcdsaP256, Tls) | (EcdhP256, Tls) => Recommendation {
            replacement: "ML-KEM-768 (key exchange) + ML-DSA-65 (signatures)".into(),
            guidance: "P-256 ECDSA/ECDH in TLS. Migrate to hybrid X25519+ML-KEM-768 for \
                       key exchange. Industry deployment: Chrome, Cloudflare, AWS already support."
                .into(),
            hybrid: Some("X25519 + ML-KEM-768 for TLS key exchange".into()),
            compliance: Some("CNSA 2.0: ECC non-compliant by 2030.".into()),
        },
        (EcdsaP256 | EcdhP256, _) => Recommendation {
            replacement: "ML-DSA-65 (signatures) / ML-KEM-768 (key exchange)".into(),
            guidance: "P-256 provides ~128-bit classical security. ML-DSA-65/ML-KEM-768 \
                       provide Level III (192-bit) security."
                .into(),
            hybrid: Some("P-256 + ML-KEM-768 hybrid during transition".into()),
            compliance: None,
        },
        (EcdsaP384 | EcdhP384, _) => Recommendation {
            replacement: "ML-DSA-87 (signatures) / ML-KEM-1024 (key exchange)".into(),
            guidance: "P-384 provides ~192-bit classical security. ML-DSA-87/ML-KEM-1024 \
                       provide Level V (256-bit) security."
                .into(),
            hybrid: Some("P-384 + ML-KEM-1024 hybrid during transition".into()),
            compliance: None,
        },
        (EcdsaSecp256k1, _) => Recommendation {
            replacement: "ML-DSA-65 (FIPS 204)".into(),
            guidance: "secp256k1 is primarily used in blockchain contexts. Verify usage context \
                       and migrate to ML-DSA-65 for signatures."
                .into(),
            hybrid: Some("FN-DSA-512 for blockchain (smaller on-chain signatures)".into()),
            compliance: None,
        },
        (EcdsaGeneric, _) => Recommendation {
            replacement: "ML-DSA-65 (signatures) / ML-KEM-768 (key exchange)".into(),
            guidance: "ECDSA detected (curve unspecified). Determine the curve and migrate: \
                       P-256/secp256k1 → ML-DSA-65, P-384 → ML-DSA-87."
                .into(),
            hybrid: None,
            compliance: None,
        },

        // ── Ed25519 / X25519 ──
        (Ed25519, Tls) => Recommendation {
            replacement: "ML-DSA-65 (FIPS 204)".into(),
            guidance: "Ed25519 in TLS authentication. Migrate to ML-DSA-65 or hybrid \
                       Ed25519 + ML-DSA-65 during transition."
                .into(),
            hybrid: Some("Ed25519 + ML-DSA-65 hybrid".into()),
            compliance: None,
        },
        (Ed25519, _) => Recommendation {
            replacement: "ML-DSA-65 (FIPS 204)".into(),
            guidance: "Ed25519 provides ~128-bit classical security. ML-DSA-65 is the \
                       recommended NIST PQC replacement for EdDSA signatures."
                .into(),
            hybrid: Some("Ed25519 + ML-DSA-65 hybrid during transition".into()),
            compliance: None,
        },
        (X25519, Tls) => Recommendation {
            replacement: "ML-KEM-768 (FIPS 203)".into(),
            guidance: "X25519 in TLS key exchange. Migrate to X25519+ML-KEM-768 hybrid \
                       (already deployed by Chrome, Cloudflare, AWS, Signal)."
                .into(),
            hybrid: Some("X25519 + ML-KEM-768 (industry standard hybrid)".into()),
            compliance: Some("CNSA 2.0: Curve25519 non-compliant by 2030.".into()),
        },
        (X25519, _) => Recommendation {
            replacement: "ML-KEM-768 (FIPS 203)".into(),
            guidance: "X25519 key exchange. Migrate to ML-KEM-768 or hybrid \
                       X25519+ML-KEM-768 for defense in depth."
                .into(),
            hybrid: Some("X25519 + ML-KEM-768 hybrid".into()),
            compliance: None,
        },

        // ── DSA / DH ──
        (Dsa, _) => Recommendation {
            replacement: "ML-DSA-65 (FIPS 204)".into(),
            guidance: "DSA is deprecated and quantum-vulnerable. Migrate to ML-DSA-65."
                .into(),
            hybrid: None,
            compliance: Some("DSA is already deprecated by NIST (FIPS 186-5).".into()),
        },
        (Dh, _) => Recommendation {
            replacement: "ML-KEM-768 (FIPS 203)".into(),
            guidance: "Diffie-Hellman key exchange is quantum-vulnerable. Migrate to ML-KEM-768."
                .into(),
            hybrid: Some("DH + ML-KEM-768 hybrid during transition".into()),
            compliance: None,
        },

        // ── Weak symmetric ciphers ──
        (TripleDes, _) => Recommendation {
            replacement: "AES-256-GCM".into(),
            guidance: "3DES has 64-bit block size (Sweet32 attack) and only 112-bit effective \
                       key strength. Migrate to AES-256-GCM for authenticated encryption."
                .into(),
            hybrid: None,
            compliance: Some("NIST SP 800-131A: 3DES deprecated after 2023.".into()),
        },
        (Blowfish, _) => Recommendation {
            replacement: "AES-256-GCM".into(),
            guidance: "Blowfish has 64-bit block size. Migrate to AES-256-GCM."
                .into(),
            hybrid: None,
            compliance: None,
        },
        (Rc4, _) => Recommendation {
            replacement: "AES-256-GCM or ChaCha20-Poly1305".into(),
            guidance: "RC4 has known biases and is broken for TLS. Migrate to AES-256-GCM \
                       or ChaCha20-Poly1305."
                .into(),
            hybrid: None,
            compliance: Some("RFC 7465: RC4 prohibited in TLS.".into()),
        },

        // ── BLS12-381 ──
        (Bls12381, _) => Recommendation {
            replacement: "STARK-compressed ML-DSA or SLH-DSA (FIPS 205)".into(),
            guidance: "BLS12-381 pairing-based cryptography is quantum-vulnerable. For \
                       aggregate signatures, consider STARK-compressed ML-DSA. For \
                       conservative fallback, use SLH-DSA (hash-based, stateless)."
                .into(),
            hybrid: None,
            compliance: None,
        },

        // ── Weak hashes ──
        (Sha1Signing, _) => Recommendation {
            replacement: "SHA-256 or SHA-3 with ML-DSA-65".into(),
            guidance: "SHA-1 is collision-broken (SHAttered attack, 2017). Do not use for \
                       digital signatures. Migrate to SHA-256/SHA-3 with ML-DSA-65."
                .into(),
            hybrid: None,
            compliance: Some("NIST SP 800-131A: SHA-1 disallowed for digital signatures.".into()),
        },
        (Md5, _) => Recommendation {
            replacement: "SHA-256 or SHA-3".into(),
            guidance: "MD5 is collision-broken. Do not use for any security purpose."
                .into(),
            hybrid: None,
            compliance: Some("MD5 is prohibited for all cryptographic uses.".into()),
        },
    }
}

/// CNSA 2.0 mode: Level V everywhere (ML-KEM-1024, ML-DSA-87).
fn recommend_cnsa(primitive: CryptoPrimitive, _context: UsageContext) -> Recommendation {
    use CryptoPrimitive::*;

    let (replacement, guidance) = match primitive.category() {
        crate::types::PrimitiveCategory::AsymmetricEncryption => (
            "ML-KEM-1024 (FIPS 203, Level V) + ML-DSA-87 (FIPS 204, Level V)",
            "CNSA 2.0 mandates Level V for National Security Systems.",
        ),
        crate::types::PrimitiveCategory::DigitalSignature => (
            "ML-DSA-87 (FIPS 204, Level V)",
            "CNSA 2.0 mandates ML-DSA-87 for all signature operations in NSS.",
        ),
        crate::types::PrimitiveCategory::KeyExchange => (
            "ML-KEM-1024 (FIPS 203, Level V)",
            "CNSA 2.0 mandates ML-KEM-1024 for all key exchange in NSS.",
        ),
        crate::types::PrimitiveCategory::SymmetricCipher => (
            "AES-256-GCM",
            "CNSA 2.0 mandates AES-256 for symmetric encryption.",
        ),
        crate::types::PrimitiveCategory::HashFunction => (
            "SHA-384 or SHA-512",
            "CNSA 2.0 mandates SHA-384 minimum for hashing.",
        ),
    };

    let timeline = match primitive {
        Rsa2048 | RsaPkcs1v15 | EcdsaP256 | EcdsaSecp256k1 | Ed25519 | X25519 => {
            "Software/firmware signing: preferred by 2025, required by 2030. \
             Networking equipment: preferred by 2026, required by 2030."
        }
        _ => "Migrate as soon as operationally feasible per CNSA 2.0 timeline.",
    };

    Recommendation {
        replacement: replacement.into(),
        guidance: guidance.into(),
        hybrid: Some("CNSA 2.0 permits hybrid during transition but mandates pure PQ by deadlines.".into()),
        compliance: Some(format!("CNSA 2.0 Timeline: {timeline}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain_signing_critical() {
        let sev = compute_severity(CryptoPrimitive::EcdsaSecp256k1, UsageContext::BlockchainSigning);
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn test_governance_critical() {
        let sev = compute_severity(CryptoPrimitive::EcdsaSecp256k1, UsageContext::GovernanceContract);
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn test_test_context_reduced() {
        let sev = compute_severity(CryptoPrimitive::Rsa2048, UsageContext::Test);
        assert_eq!(sev, Severity::Medium);

        let sev = compute_severity(CryptoPrimitive::TripleDes, UsageContext::Test);
        assert_eq!(sev, Severity::Low);
    }

    #[test]
    fn test_rsa_2048_high() {
        let sev = compute_severity(CryptoPrimitive::Rsa2048, UsageContext::General);
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn test_rsa_4096_medium() {
        let sev = compute_severity(CryptoPrimitive::Rsa4096, UsageContext::General);
        assert_eq!(sev, Severity::Medium);
    }

    #[test]
    fn test_recommend_secp256k1_blockchain() {
        let rec = recommend(
            CryptoPrimitive::EcdsaSecp256k1,
            UsageContext::BlockchainSigning,
            false,
        );
        assert!(rec.replacement.contains("ML-DSA-65"));
        assert!(rec.replacement.contains("ERC-4337"));
    }

    #[test]
    fn test_recommend_rsa_tls() {
        let rec = recommend(CryptoPrimitive::Rsa2048, UsageContext::Tls, false);
        assert!(rec.replacement.contains("ML-KEM-768"));
        assert!(rec.hybrid.is_some());
    }

    #[test]
    fn test_cnsa_mode_level_v() {
        let rec = recommend(CryptoPrimitive::Rsa2048, UsageContext::General, true);
        assert!(rec.replacement.contains("ML-KEM-1024"));
        assert!(rec.replacement.contains("Level V"));
    }

    #[test]
    fn test_triple_des_recommendation() {
        let rec = recommend(CryptoPrimitive::TripleDes, UsageContext::General, false);
        assert!(rec.replacement.contains("AES-256-GCM"));
    }

    #[test]
    fn test_bls_light_client() {
        let rec = recommend(CryptoPrimitive::Bls12381, UsageContext::LightClient, false);
        assert!(rec.replacement.contains("STARK"));
        assert!(rec.compliance.is_some());
    }
}
