"""Tests for the ``signature_algorithm`` open-enum registry."""

from __future__ import annotations

import pytest

from algovoi_substrate_pqc import (
    KNOWN_SIGNATURE_ALGORITHMS,
    SignatureAlgorithmFamily,
    UnknownSignatureAlgorithm,
    lookup_signature_algorithm,
)


def test_registry_has_12_rows():
    assert len(KNOWN_SIGNATURE_ALGORITHMS) == 12


@pytest.mark.parametrize(
    ("identifier", "family"),
    [
        ("ECDSA", SignatureAlgorithmFamily.CLASSICAL),
        ("ES256", SignatureAlgorithmFamily.CLASSICAL),
        ("ES256K", SignatureAlgorithmFamily.CLASSICAL),
        ("Ed25519", SignatureAlgorithmFamily.CLASSICAL),
        ("ML-DSA-44", SignatureAlgorithmFamily.PQC),
        ("ML-DSA-65", SignatureAlgorithmFamily.PQC),
        ("ML-DSA-87", SignatureAlgorithmFamily.PQC),
        ("Falcon-512", SignatureAlgorithmFamily.PQC),
        ("Falcon-1024", SignatureAlgorithmFamily.PQC),
        ("SLH-DSA-SHA2-128s", SignatureAlgorithmFamily.PQC_STATELESS_HASH),
        ("HMAC-SHA-256", SignatureAlgorithmFamily.HMAC),
        ("HMAC-SHA-384", SignatureAlgorithmFamily.HMAC),
    ],
)
def test_recommended_values_present(identifier, family):
    rec = lookup_signature_algorithm(identifier)
    assert rec.identifier == identifier
    assert rec.family == family


def test_lookup_case_sensitive_per_rfc_7517():
    # Per RFC 7517 §4.1, identifiers are case-sensitive.
    # "Ed25519" is in the registry; "ed25519" is not.
    lookup_signature_algorithm("Ed25519")  # no raise
    with pytest.raises(UnknownSignatureAlgorithm):
        lookup_signature_algorithm("ed25519")


def test_unknown_identifier_fail_closed():
    # The substrate verifier rule: unknown identifiers MUST raise.
    with pytest.raises(UnknownSignatureAlgorithm):
        lookup_signature_algorithm("NotAnAlgorithm-9999")


def test_unknown_signature_algorithm_is_value_error():
    # UnknownSignatureAlgorithm is a ValueError subclass for ergonomic catching.
    with pytest.raises(ValueError):
        lookup_signature_algorithm("Nope")
