//! Rust producer: signs the stable AP2 PaymentMandate payload and writes the artefact.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, Signer as Ed25519Signer};
use ml_dsa::{Generate, Keypair, KeyExport, MlDsa65, SignatureEncoding, Signer as MlSigner, SigningKey as MlSigningKey};
use p256::{
    ecdsa::{Signature as EcdsaSig, SigningKey as P256SigningKey, signature::Signer as EcdsaSigner},
    pkcs8::EncodePublicKey,
};
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::{SystemTime, UNIX_EPOCH}};

const EXPECTED_SHA: &str =
    "sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0";

fn mandate_body() -> Value {
    json!({
        "amount": {
            "currency": "USD",
            "minor_units": 4995
        },
        "constraints": [
            {
                "type": "merchant_id_allowlist",
                "value": ["did:web:merchant.example.com"]
            },
            {
                "type": "expiry_unix_ms",
                "value": 1782259200000_u64
            }
        ],
        "issued_at": "2026-05-21T00:00:00Z",
        "issued_at_ms": 1779667200000_u64,
        "issuer": "did:web:wallet.example.org",
        "merchant": "did:web:merchant.example.com",
        "nonce": "0x7b5ce8a4f1b9a4d2",
        "schema": "google-agentic-commerce/AP2 PaymentMandate",
        "subject": "did:web:agent.example.org#agent-7",
        "vct": "mandate.payment.1",
        "version": "0.1"
    })
}

pub fn run(out_path: &str) {
    let body = mandate_body();

    // JCS canonical bytes.
    let canonical = serde_jcs::to_vec(&body).expect("JCS serialization failed");

    // Verify byte-anchor SHA-256.
    let digest = Sha256::digest(&canonical);
    let got_sha = format!("sha256:{}", hex::encode(digest.as_slice()));
    if got_sha != EXPECTED_SHA {
        eprintln!(
            "FATAL: JCS canonical SHA mismatch\n  got:  {}\n  want: {}",
            got_sha, EXPECTED_SHA
        );
        std::process::exit(1);
    }
    eprintln!(
        "canonical_sha_ok: {} (len={})",
        got_sha,
        canonical.len()
    );

    let mut sigs: BTreeMap<String, Value> = BTreeMap::new();

    // --- ES256 (P-256 + SHA-256) ---
    {
        // p256 with getrandom feature provides Generate trait.
        use p256::elliptic_curve::Generate;
        let sk = P256SigningKey::generate();
        // p256::ecdsa::Signature signs SHA-256(message) internally.
        let sig: EcdsaSig = sk.sign(&canonical);
        // DER-encode the signature.
        let sig_der = sig.to_der();
        // DER-encode the public key (SubjectPublicKeyInfo).
        let pub_der = sk
            .verifying_key()
            .to_public_key_der()
            .expect("P-256 pubkey DER encoding failed");
        sigs.insert(
            "ES256".to_string(),
            json!({
                "algorithm": "ES256",
                "curve": "P-256",
                "hash": "SHA-256",
                "publicKeyDer": B64.encode(pub_der.as_bytes()),
                "signature_der": B64.encode(sig_der.as_bytes()),
            }),
        );
    }

    // --- Ed25519 ---
    {
        // Generate 32 random bytes via getrandom, then construct signing key.
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom failed");
        let sk = Ed25519SigningKey::from_bytes(&seed);
        let sig = sk.sign(&canonical);
        let vk = sk.verifying_key();
        sigs.insert(
            "Ed25519".to_string(),
            json!({
                "algorithm": "Ed25519",
                "publicKey_b64": B64.encode(vk.as_bytes()),
                "signature_b64": B64.encode(sig.to_bytes()),
            }),
        );
    }

    // --- ML-DSA-65 (RustCrypto FIPS 204) ---
    {
        // ml-dsa with getrandom feature enables SigningKey::generate().
        let sk = MlSigningKey::<MlDsa65>::generate();
        let sig = sk.sign(&canonical);
        let vk = sk.verifying_key();
        let vk_bytes = vk.to_bytes();
        let sig_bytes = sig.to_bytes();
        sigs.insert(
            "ML-DSA-65".to_string(),
            json!({
                "algorithm": "ML-DSA-65",
                "fips": "FIPS 204",
                "nist_level": 3,
                "publicKey_b64": B64.encode(vk_bytes.as_slice()),
                "signature_b64": B64.encode(sig_bytes.as_slice()),
                "signature_length_bytes": sig_bytes.len(),
                "publicKey_length_bytes": vk_bytes.len(),
            }),
        );
    }

    // --- Falcon-1024 ---
    {
        let (pk, sk) = falcon1024::keypair();
        let sig = falcon1024::detached_sign(&canonical, &sk);
        let pk_bytes = pk.as_bytes();
        let sig_bytes = sig.as_bytes();
        sigs.insert(
            "Falcon-1024".to_string(),
            json!({
                "algorithm": "Falcon-1024",
                "fips": "FIPS 206 (FN-DSA)",
                "nist_level": 5,
                "publicKey_b64": B64.encode(pk_bytes),
                "signature_b64": B64.encode(sig_bytes),
                "signature_length_bytes": sig_bytes.len(),
                "publicKey_length_bytes": pk_bytes.len(),
            }),
        );
    }

    // --- Build artefact ---
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let published_at = format_unix(now);

    let artefact = json!({
        "schema_version": "1.0",
        "artefact_id": "cross-product-v0-rust-side",
        "canonicalizer": "serde_jcs@0.2.0",
        "published_at": published_at,
        "anchored_to": {
            "thread": "https://github.com/chopmob-cloud/algovoi-substrate-pqc",
            "schema": "AP2 PaymentMandate v0.1 (cross-product exemplar)",
            "rfc": "RFC 8785 (JCS)"
        },
        "context": {
            "producer": "rust/p256+ed25519-dalek+ml-dsa+pqcrypto-falcon",
            "producer_runtime": "rust/1.95",
            "purpose": "Rust-side producer for the cross-product matrix; signs the stable canonical payload under ES256 + Ed25519 + ML-DSA-65 + Falcon-1024."
        },
        "mandate_body": body,
        "expected_jcs_bytes_b64": B64.encode(&canonical),
        "expected_jcs_bytes_hex": hex::encode(&canonical),
        "expected_jcs_bytes_length": canonical.len(),
        "expected_canonical_sha256": got_sha,
        "signatures": sigs,
    });

    let json_str = serde_json::to_string_pretty(&artefact).expect("JSON serialization failed");

    // Write output file.
    let path = Path::new(out_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create output directory failed");
    }
    fs::write(path, format!("{}\n", json_str)).expect("write artefact failed");
    println!(
        "wrote {} (signatures: Ed25519, ES256, Falcon-1024, ML-DSA-65)",
        out_path
    );
}

fn format_unix(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let months = if is_leap(year) {
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for dm in &months {
        if days < *dm {
            break;
        }
        days -= dm;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
