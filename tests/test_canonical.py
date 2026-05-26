"""Tests for canonical-bytes derivation (RFC 8785 thin re-export)."""

from __future__ import annotations

from algovoi_substrate_pqc import jcs_canonical_bytes, jcs_canonical_sha256_hex


def test_canonical_bytes_stable_under_key_reordering():
    """JCS sorts keys, so two payloads with different key order canonicalise identically."""
    a = jcs_canonical_bytes({"b": 1, "a": 2})
    b = jcs_canonical_bytes({"a": 2, "b": 1})
    assert a == b


def test_canonical_sha256_has_sha256_prefix():
    digest = jcs_canonical_sha256_hex({"a": 1})
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64  # lowercase hex SHA-256


def test_ap2_paymentmandate_canonical_sha_matches_published_anchor():
    """The AP2 PaymentMandate exemplar canonical SHA matches the published anchor.

    The published byte-anchor for the AP2 PQC v0 joint fixture is
    ``sha256:cc8315f7…e0``. This test confirms the package's canonicalisation
    pipeline produces the same anchor for the same payload.
    """
    payload = {
        "amount": {"currency": "USD", "minor_units": 4995},
        "constraints": [
            {"type": "merchant_id_allowlist", "value": ["did:web:merchant.example.com"]},
            {"type": "expiry_unix_ms", "value": 1782259200000},
        ],
        "issued_at": "2026-05-21T00:00:00Z",
        "issued_at_ms": 1779667200000,
        "issuer": "did:web:wallet.example.org",
        "merchant": "did:web:merchant.example.com",
        "nonce": "0x7b5ce8a4f1b9a4d2",
        "schema": "google-agentic-commerce/AP2 PaymentMandate",
        "subject": "did:web:agent.example.org#agent-7",
        "vct": "mandate.payment.1",
        "version": "0.1",
    }
    assert (
        jcs_canonical_sha256_hex(payload)
        == "sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0"
    )
