"""End-to-end sign/verify round-trip tests for all four schemes."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from algovoi_substrate_pqc import (
    UnknownSignatureAlgorithm,
    build_convergence_artefact,
    generate_falcon_1024_keypair,
    generate_ml_dsa_65_keypair,
    jcs_canonical_bytes,
    sign_ed25519,
    sign_es256,
    sign_falcon_1024,
    sign_ml_dsa_65,
    verify_artefact,
    verify_signature,
)


@pytest.fixture
def payload():
    return {
        "amount": {"currency": "USD", "minor_units": 4995},
        "issuer": "did:web:wallet.example.org",
        "merchant": "did:web:merchant.example.com",
        "nonce": "0x7b5ce8a4f1b9a4d2",
    }


def test_es256_roundtrip(payload):
    sk = ec.generate_private_key(ec.SECP256R1())
    sig = sign_es256(payload, sk)
    canonical = jcs_canonical_bytes(payload)
    result = verify_signature(canonical, "ES256", sig)
    assert result.ok, result.detail


def test_ed25519_roundtrip(payload):
    sk = ed25519.Ed25519PrivateKey.generate()
    sig = sign_ed25519(payload, sk)
    canonical = jcs_canonical_bytes(payload)
    result = verify_signature(canonical, "Ed25519", sig)
    assert result.ok, result.detail


def test_falcon_1024_roundtrip(payload):
    public_key, secret_key = generate_falcon_1024_keypair()
    sig = sign_falcon_1024(payload, secret_key, public_key)
    canonical = jcs_canonical_bytes(payload)
    result = verify_signature(canonical, "Falcon-1024", sig)
    assert result.ok, result.detail


def test_ml_dsa_65_roundtrip(payload):
    public_key, secret_key = generate_ml_dsa_65_keypair()
    sig = sign_ml_dsa_65(payload, secret_key, public_key)
    canonical = jcs_canonical_bytes(payload)
    result = verify_signature(canonical, "ML-DSA-65", sig)
    assert result.ok, result.detail


def test_convergence_artefact_all_four_schemes(payload):
    """One canonical payload, four signature schemes, byte-identical SHA-256."""
    es_sk = ec.generate_private_key(ec.SECP256R1())
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    fp, fs = generate_falcon_1024_keypair()
    mp, ms = generate_ml_dsa_65_keypair()

    signatures = {
        "ES256": sign_es256(payload, es_sk),
        "Ed25519": sign_ed25519(payload, ed_sk),
        "Falcon-1024": sign_falcon_1024(payload, fs, fp),
        "ML-DSA-65": sign_ml_dsa_65(payload, ms, mp),
    }

    artefact = build_convergence_artefact(
        payload,
        signatures,
        artefact_id="test-convergence-v0",
    )

    # Recompute canonical SHA-256 from the artefact and verify all four schemes.
    result = verify_artefact(artefact)
    assert result.canonical_sha_ok, (
        f"canonical SHA mismatch: recomputed={result.canonical_sha_recomputed} "
        f"expected={result.canonical_sha_expected}"
    )
    assert len(result.signatures) == 4
    for s in result.signatures:
        assert s.ok, f"{s.algorithm} failed: {s.detail}"


def test_unknown_algorithm_fails_closed(payload):
    canonical = jcs_canonical_bytes(payload)
    with pytest.raises(UnknownSignatureAlgorithm):
        verify_signature(canonical, "NotAReal-Scheme", {"signature_b64": "AAA="})
