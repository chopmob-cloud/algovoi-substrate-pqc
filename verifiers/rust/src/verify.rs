//! Rust verifier: reads an AP2 PQC v0 artefact and verifies all declared signature schemes.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature as EdSig, VerifyingKey as Ed25519VerifyKey};
use ml_dsa::{MlDsa65, Signature as MlSig, VerifyingKey as MlVerifyKey};
use p256::ecdsa::{DerSignature, VerifyingKey as P256VerifyKey, signature::Verifier as _};
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, process};

pub fn run(artefact_path: &str) {
    let data = fs::read_to_string(artefact_path).unwrap_or_else(|e| {
        eprintln!("read artefact: {}", e);
        process::exit(1);
    });
    let artefact: Value = serde_json::from_str(&data).unwrap_or_else(|e| {
        eprintln!("parse JSON: {}", e);
        process::exit(1);
    });

    // Get mandate_body (or payload fallback).
    let body = artefact
        .get("mandate_body")
        .or_else(|| artefact.get("payload"))
        .cloned()
        .unwrap_or_else(|| {
            eprintln!("artefact missing mandate_body / payload");
            process::exit(1);
        });

    // Recompute JCS canonical bytes.
    let canonical = serde_jcs::to_vec(&body).unwrap_or_else(|e| {
        eprintln!("JCS error: {}", e);
        process::exit(1);
    });

    let digest = Sha256::digest(&canonical);
    let got_sha = format!("sha256:{}", hex::encode(digest.as_slice()));
    let expected_sha = artefact["expected_canonical_sha256"]
        .as_str()
        .unwrap_or("");
    let sha_ok = got_sha == expected_sha;
    println!("canonical_sha_ok={}", sha_ok);
    if !sha_ok {
        eprintln!(
            "canonical SHA mismatch: got {} want {}",
            got_sha, expected_sha
        );
    }

    let sigs = match artefact.get("signatures").and_then(|v| v.as_object()) {
        Some(s) => s.clone(),
        None => {
            eprintln!("no signatures field");
            process::exit(1);
        }
    };

    let mut all_pass = sha_ok;

    for (alg, sig_val) in &sigs {
        let sig = match sig_val.as_object() {
            Some(o) => o,
            None => {
                println!("FAIL: {}: not a JSON object", alg);
                all_pass = false;
                continue;
            }
        };

        match alg.as_str() {
            "ES256" => match verify_es256(&canonical, sig) {
                Ok(()) => println!("PASS: ES256"),
                Err(e) => {
                    println!("FAIL: ES256: {}", e);
                    all_pass = false;
                }
            },
            "Ed25519" => match verify_ed25519(&canonical, sig) {
                Ok(()) => println!("PASS: Ed25519"),
                Err(e) => {
                    println!("FAIL: Ed25519: {}", e);
                    all_pass = false;
                }
            },
            "ML-DSA-65" => match verify_mldsa65(&canonical, sig) {
                Ok(()) => println!("PASS: ML-DSA-65"),
                Err(e) => {
                    println!("FAIL: ML-DSA-65: {}", e);
                    all_pass = false;
                }
            },
            "Falcon-1024" => match verify_falcon1024(&canonical, sig) {
                Ok(()) => println!("PASS: Falcon-1024"),
                Err(e) => {
                    println!("FAIL: Falcon-1024: {}", e);
                    all_pass = false;
                }
            },
            other => {
                println!("SKIP: {}: unknown scheme", other);
            }
        }
    }

    if !all_pass {
        process::exit(1);
    }
}

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|e| format!("base64 decode: {}", e))
}

fn get_str<'a>(sig: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str, String> {
    sig.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing field: {}", key))
}

fn verify_es256(
    canonical: &[u8],
    sig: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    use p256::pkcs8::DecodePublicKey;

    // Load public key — accept DER (publicKeyDer) or raw 65-byte uncompressed (publicKey_b64).
    let pub_key: P256VerifyKey = if let Some(der_b64) = sig
        .get("publicKeyDer")
        .and_then(|v| v.as_str())
    {
        let der = b64d(der_b64)?;
        P256VerifyKey::from_public_key_der(&der)
            .map_err(|e| format!("parse DER public key: {}", e))?
    } else if let Some(raw_b64) = sig.get("publicKey_b64").and_then(|v| v.as_str()) {
        let raw = b64d(raw_b64)?;
        P256VerifyKey::from_sec1_bytes(&raw)
            .map_err(|e| format!("parse SEC1 public key: {}", e))?
    } else {
        return Err("no publicKeyDer or publicKey_b64".to_string());
    };

    // Load signature — accept DER (signature_der) or compact 64-byte r||s.
    let sig_bytes: Vec<u8> = if let Some(der_b64) = sig
        .get("signature_der")
        .and_then(|v| v.as_str())
    {
        b64d(der_b64)?
    } else {
        let compact_b64 = sig
            .get("signature_b64")
            .or_else(|| sig.get("signature_compact_b64"))
            .and_then(|v| v.as_str())
            .ok_or("no signature_der / signature_b64 / signature_compact_b64")?;
        let compact = b64d(compact_b64)?;
        if compact.len() == 64 {
            compact_to_der(&compact)?
        } else {
            compact
        }
    };

    // ES256 hashes with SHA-256 internally (p256 ecdsa verifier).
    let ecdsa_sig = DerSignature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("parse DER signature: {}", e))?;
    pub_key
        .verify(canonical, &ecdsa_sig)
        .map_err(|e| format!("ES256 verify failed: {}", e))
}

fn compact_to_der(compact: &[u8]) -> Result<Vec<u8>, String> {
    if compact.len() != 64 {
        return Err(format!(
            "expected 64-byte compact signature, got {}",
            compact.len()
        ));
    }
    let r = &compact[..32];
    let s = &compact[32..];
    let r_der = der_int(r);
    let s_der = der_int(s);
    let inner_len = r_der.len() + s_der.len();
    let mut out = Vec::with_capacity(2 + inner_len);
    out.push(0x30u8); // SEQUENCE
    out.push(inner_len as u8);
    out.extend_from_slice(&r_der);
    out.extend_from_slice(&s_der);
    Ok(out)
}

fn der_int(bytes: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = bytes.iter().skip_while(|&&b| b == 0).cloned().collect();
    let need_pad = trimmed.first().map_or(false, |&b| b & 0x80 != 0);
    let content_len = trimmed.len() + if need_pad { 1 } else { 0 };
    let mut out = vec![0x02u8, content_len as u8];
    if need_pad {
        out.push(0x00);
    }
    out.extend_from_slice(&trimmed);
    out
}

fn verify_ed25519(
    canonical: &[u8],
    sig: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    use ed25519_dalek::Verifier;

    let pub_b64 = get_str(sig, "publicKey_b64")?;
    let sig_b64 = get_str(sig, "signature_b64")?;
    let pub_bytes = b64d(pub_b64)?;
    let sig_bytes = b64d(sig_b64)?;

    let pub_arr: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| "expected 32-byte Ed25519 public key".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "expected 64-byte Ed25519 signature".to_string())?;

    let vk = Ed25519VerifyKey::from_bytes(&pub_arr)
        .map_err(|e| format!("Ed25519 public key parse: {}", e))?;
    let signature = EdSig::from_bytes(&sig_arr);
    vk.verify(canonical, &signature)
        .map_err(|e| format!("Ed25519 verify failed: {}", e))
}

fn verify_mldsa65(
    canonical: &[u8],
    sig: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    use ml_dsa::{KeyInit, Verifier};

    let pub_b64 = get_str(sig, "publicKey_b64")?;
    let sig_b64 = get_str(sig, "signature_b64")?;
    let pub_bytes = b64d(pub_b64)?;
    let sig_bytes = b64d(sig_b64)?;

    // Build VerifyingKey from bytes using new_from_slice (from KeyInit trait).
    let vk = MlVerifyKey::<MlDsa65>::new_from_slice(&pub_bytes)
        .map_err(|_| format!("ML-DSA-65 public key wrong size (got {} bytes)", pub_bytes.len()))?;

    // Decode signature using TryFrom<&[u8]>.
    let ml_sig = MlSig::<MlDsa65>::try_from(sig_bytes.as_slice())
        .map_err(|_| format!("ML-DSA-65 signature decode failed (got {} bytes)", sig_bytes.len()))?;

    vk.verify(canonical, &ml_sig)
        .map_err(|e| format!("ML-DSA-65 verify failed: {}", e))
}

fn verify_falcon1024(
    canonical: &[u8],
    sig: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    let pub_b64 = get_str(sig, "publicKey_b64")?;
    let sig_b64 = get_str(sig, "signature_b64")?;
    let pub_bytes = b64d(pub_b64)?;
    let sig_bytes = b64d(sig_b64)?;

    let pk = falcon1024::PublicKey::from_bytes(&pub_bytes)
        .map_err(|e| format!("Falcon-1024 public key parse: {}", e))?;
    let dsig = falcon1024::DetachedSignature::from_bytes(&sig_bytes)
        .map_err(|e| format!("Falcon-1024 signature parse: {}", e))?;
    falcon1024::verify_detached_signature(&dsig, canonical, &pk)
        .map_err(|e| format!("Falcon-1024 verify failed: {}", e))
}
