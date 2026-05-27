"""Security regression tests for algovoi-substrate-pqc.

Covers the findings from the 0.1.2 security audit:

  H-1  Vacuous-truth bypass — artefact with empty signatures must not verify OK.
  H-2  Missing-payload KeyError — bare dict access on mandate_body raises; must
       be a ValueError with a useful message instead.
  M-3  Registry-known-but-unimplemented algorithm must return ok=False (not
       raise, not silently pass).
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from algovoi_substrate_pqc import (
    build_convergence_artefact,
    jcs_canonical_bytes,
    sign_ed25519,
    sign_es256,
    verify_artefact,
)
from algovoi_substrate_pqc.verify import ArtefactVerifyResult, VerifyResult


# ---------------------------------------------------------------------------
# H-1 — vacuous-truth empty-signatures bypass
# ---------------------------------------------------------------------------


def _make_valid_artefact_no_sigs(payload):
    """Craft an artefact with a valid canonical-SHA but zero signatures."""
    canonical = jcs_canonical_bytes(payload)
    sha = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return {
        "mandate_body": payload,
        "expected_canonical_sha256": sha,
        "signatures": {},
    }


@pytest.fixture
def simple_payload():
    return {"amount": 100, "currency": "USD", "nonce": "abc123"}


def test_empty_signatures_not_ok(simple_payload):
    """H-1: An artefact with no signatures must NOT return ok=True."""
    artefact = _make_valid_artefact_no_sigs(simple_payload)
    result = verify_artefact(artefact)
    assert result.canonical_sha_ok, "precondition: canonical SHA should be valid"
    assert result.signatures == [], "precondition: no signatures"
    assert result.ok is False, (
        "H-1 REGRESSION: artefact with empty signatures vacuously returned ok=True"
    )


def test_artefact_verify_result_ok_requires_signatures():
    """H-1: ArtefactVerifyResult.ok is False when signatures list is empty."""
    r = ArtefactVerifyResult(
        canonical_sha_ok=True,
        canonical_sha_recomputed="sha256:aabbcc",
        canonical_sha_expected="sha256:aabbcc",
        signatures=[],
    )
    assert r.ok is False


def test_artefact_verify_result_ok_true_with_signatures(simple_payload):
    """H-1: ArtefactVerifyResult.ok is True only when signatures are present and valid."""
    sk = ec.generate_private_key(ec.SECP256R1())
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    sigs = {
        "ES256": sign_es256(simple_payload, sk),
        "Ed25519": sign_ed25519(simple_payload, ed_sk),
    }
    artefact = build_convergence_artefact(simple_payload, sigs, artefact_id="test-h1")
    result = verify_artefact(artefact)
    assert result.ok is True


# ---------------------------------------------------------------------------
# H-2 — missing mandate_body / payload raises ValueError not KeyError
# ---------------------------------------------------------------------------


def test_missing_mandate_body_raises_value_error(simple_payload):
    """H-2: artefact without mandate_body or payload raises ValueError."""
    canonical = jcs_canonical_bytes(simple_payload)
    sha = "sha256:" + hashlib.sha256(canonical).hexdigest()
    artefact = {
        # mandate_body intentionally omitted
        "expected_canonical_sha256": sha,
        "signatures": {},
    }
    with pytest.raises(ValueError, match="mandate_body|payload"):
        verify_artefact(artefact)


def test_payload_key_accepted_as_fallback(simple_payload):
    """H-2: 'payload' key is accepted as a fallback for 'mandate_body'."""
    sk = ec.generate_private_key(ec.SECP256R1())
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    sigs = {
        "ES256": sign_es256(simple_payload, sk),
        "Ed25519": sign_ed25519(simple_payload, ed_sk),
    }
    artefact = build_convergence_artefact(simple_payload, sigs, artefact_id="test-h2-fallback")
    # Rename mandate_body → payload
    artefact["payload"] = artefact.pop("mandate_body")
    result = verify_artefact(artefact)
    assert result.canonical_sha_ok
    assert result.ok is True


def test_missing_expected_sha_raises_value_error(simple_payload):
    """H-2: artefact without expected_canonical_sha256 raises ValueError."""
    artefact = {
        "mandate_body": simple_payload,
        # expected_canonical_sha256 intentionally omitted
        "signatures": {},
    }
    with pytest.raises(ValueError, match="expected_canonical_sha256"):
        verify_artefact(artefact)


# ---------------------------------------------------------------------------
# M-3 — registry-known but unimplemented algorithm
# ---------------------------------------------------------------------------


def test_known_unimplemented_algorithm_returns_not_ok(simple_payload):
    """M-3: A registry-known algorithm without a verifier returns ok=False."""
    from algovoi_substrate_pqc.verify import verify_signature

    # HMAC-SHA-256 is in the registry but has no verifier implemented in this package.
    canonical = jcs_canonical_bytes(simple_payload)
    result = verify_signature(canonical, "HMAC-SHA-256", {"signature_b64": "dGVzdA=="})
    assert result.ok is False
    assert "no verifier" in result.detail.lower() or "not implemented" in result.detail.lower()
