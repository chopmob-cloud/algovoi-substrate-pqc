"""``signature_algorithm`` open-enum registry — AlgoVoi-authored convention.

This module implements the AlgoVoi substrate-author ``signature_algorithm``
convention: an open enum of 12 recommended values across classical, post-quantum,
and HMAC families, with case-sensitive lookup per RFC 7517 §4.1 and a
fail-closed verifier rule.

The 12-row recommended-values table is the informative table from
``chopmob-cloud/ap2-pq-conformance/algorithm-identifier-table.md``. Verifiers
MUST treat unknown ``signature_algorithm`` values as opaque and refuse to
verify (fail-closed). Implementors MAY declare any value.

This convention is AlgoVoi-authored. The signature primitives are not — see
the package README for the upstream-attribution table.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SignatureAlgorithmFamily(str, Enum):
    """Algorithm-family taxonomy."""

    CLASSICAL = "Classical"
    PQC = "PQC"
    PQC_STATELESS_HASH = "PQC stateless-hash"
    HMAC = "HMAC"


@dataclass(frozen=True)
class SignatureAlgorithmRecord:
    """One row of the recommended-values registry."""

    identifier: str
    family: SignatureAlgorithmFamily
    source: str
    notes: str


KNOWN_SIGNATURE_ALGORITHMS: dict[str, SignatureAlgorithmRecord] = {
    rec.identifier: rec
    for rec in (
        SignatureAlgorithmRecord(
            identifier="ECDSA",
            family=SignatureAlgorithmFamily.CLASSICAL,
            source="Generic ECDSA",
            notes=(
                "Backward-compat alias for AP2 v0.1 emitters. Curve- and "
                "hash-ambiguous. New deployments SHOULD use the specific JOSE "
                "identifier (ES256 / ES256K / ES384 / ES512) corresponding to "
                "the curve and hash actually in use."
            ),
        ),
        SignatureAlgorithmRecord(
            identifier="ES256",
            family=SignatureAlgorithmFamily.CLASSICAL,
            source="RFC 7518 §3.4",
            notes="ECDSA P-256 SHA-256.",
        ),
        SignatureAlgorithmRecord(
            identifier="ES256K",
            family=SignatureAlgorithmFamily.CLASSICAL,
            source="RFC 8812",
            notes="ECDSA secp256k1 SHA-256.",
        ),
        SignatureAlgorithmRecord(
            identifier="Ed25519",
            family=SignatureAlgorithmFamily.CLASSICAL,
            source="RFC 8032 / RFC 8037",
            notes="EdDSA Ed25519.",
        ),
        SignatureAlgorithmRecord(
            identifier="ML-DSA-44",
            family=SignatureAlgorithmFamily.PQC,
            source="FIPS 204 / draft-ietf-cose-dilithium",
            notes="NIST Level 2.",
        ),
        SignatureAlgorithmRecord(
            identifier="ML-DSA-65",
            family=SignatureAlgorithmFamily.PQC,
            source="FIPS 204 / draft-ietf-cose-dilithium",
            notes="NIST Level 3.",
        ),
        SignatureAlgorithmRecord(
            identifier="ML-DSA-87",
            family=SignatureAlgorithmFamily.PQC,
            source="FIPS 204 / draft-ietf-cose-dilithium",
            notes="NIST Level 5.",
        ),
        SignatureAlgorithmRecord(
            identifier="Falcon-512",
            family=SignatureAlgorithmFamily.PQC,
            source="FIPS 206 (FN-DSA)",
            notes="NIST Level 1.",
        ),
        SignatureAlgorithmRecord(
            identifier="Falcon-1024",
            family=SignatureAlgorithmFamily.PQC,
            source="FIPS 206 (FN-DSA)",
            notes="NIST Level 5.",
        ),
        SignatureAlgorithmRecord(
            identifier="SLH-DSA-SHA2-128s",
            family=SignatureAlgorithmFamily.PQC_STATELESS_HASH,
            source="FIPS 205",
            notes="SPHINCS+ small.",
        ),
        SignatureAlgorithmRecord(
            identifier="HMAC-SHA-256",
            family=SignatureAlgorithmFamily.HMAC,
            source="RFC 2104",
            notes="Internal-channel only.",
        ),
        SignatureAlgorithmRecord(
            identifier="HMAC-SHA-384",
            family=SignatureAlgorithmFamily.HMAC,
            source="RFC 2104 / FIPS 198-1",
            notes="PQC-conservative HMAC.",
        ),
    )
}


class UnknownSignatureAlgorithm(ValueError):
    """Raised by :func:`lookup_signature_algorithm` when an identifier is not
    in :data:`KNOWN_SIGNATURE_ALGORITHMS`.

    Verifiers MUST treat unknown ``signature_algorithm`` values as opaque and
    refuse to verify (fail-closed). This exception is the AlgoVoi-substrate
    canonical signal of that condition.

    Per the convention: implementors MAY emit any value. Verifiers MUST
    reject any value not in the recommended-values registry — or escalate to
    a registered extension — rather than guessing.
    """


def lookup_signature_algorithm(identifier: str) -> SignatureAlgorithmRecord:
    """Look up a ``signature_algorithm`` identifier (case-sensitive).

    Per RFC 7517 §4.1, the lookup is case-sensitive. ``Ed25519`` and
    ``ed25519`` are different identifiers; the recommended-values registry
    pins the casing.

    :param identifier: the ``signature_algorithm`` value as it appears in an
        artefact.
    :raises UnknownSignatureAlgorithm: if the identifier is not in
        :data:`KNOWN_SIGNATURE_ALGORITHMS`. This is the fail-closed signal
        the verifier discipline relies on.
    :returns: the registry record for the identifier.
    """
    try:
        return KNOWN_SIGNATURE_ALGORITHMS[identifier]
    except KeyError as exc:
        raise UnknownSignatureAlgorithm(
            f"unknown signature_algorithm identifier {identifier!r}; "
            f"per the AlgoVoi-substrate convention verifiers MUST treat "
            f"unknown values as opaque and refuse to verify"
        ) from exc
