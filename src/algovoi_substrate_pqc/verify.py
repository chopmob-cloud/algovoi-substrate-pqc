"""Substrate-author verification — wraps upstream primitives with fail-closed discipline.

This module provides the AlgoVoi-substrate verifier discipline:

1. Recompute JCS canonical bytes from the artefact payload.
2. Confirm the recomputed canonical SHA-256 matches the artefact-declared
   ``expected_canonical_sha256`` byte-anchor.
3. For each declared signature, look up the ``signature_algorithm`` identifier
   in the registry (case-sensitive). If unknown, raise
   :class:`UnknownSignatureAlgorithm` — the fail-closed substrate rule.
4. Dispatch to the per-scheme verifier (ES256, Ed25519, Falcon-1024, ML-DSA-65)
   over the recomputed canonical bytes.

The cryptographic primitives are not AlgoVoi-authored. See the README for the
upstream-attribution table.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

import pqcrypto.sign.falcon_1024 as _falcon_1024
import pqcrypto.sign.ml_dsa_65 as _ml_dsa_65
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .canonical import jcs_canonical_bytes
from .registry import (
    KNOWN_SIGNATURE_ALGORITHMS,
    UnknownSignatureAlgorithm,
    lookup_signature_algorithm,
)


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


@dataclass
class VerifyResult:
    """Per-scheme verification outcome."""

    algorithm: str
    ok: bool
    detail: str = ""

    def __bool__(self) -> bool:
        return self.ok


@dataclass
class ArtefactVerifyResult:
    """Aggregate verification outcome over the full artefact."""

    canonical_sha_ok: bool
    canonical_sha_recomputed: str
    canonical_sha_expected: str
    signatures: list[VerifyResult]

    @property
    def ok(self) -> bool:
        """``True`` iff canonical SHA matches AND all known-scheme verifications pass."""
        return self.canonical_sha_ok and all(s.ok for s in self.signatures)


def verify_es256(canonical: bytes, sig: dict[str, Any]) -> VerifyResult:
    """ES256 verifier per the AP2 PQC v0 ``signatures[].ES256`` shape."""
    try:
        pub = serialization.load_der_public_key(_b64d(sig["publicKeyDer"]))
        pub.verify(_b64d(sig["signature_der"]), canonical, ec.ECDSA(hashes.SHA256()))
        return VerifyResult(algorithm="ES256", ok=True)
    except InvalidSignature:
        return VerifyResult(algorithm="ES256", ok=False, detail="signature invalid")
    except Exception as exc:
        return VerifyResult(algorithm="ES256", ok=False, detail=f"{type(exc).__name__}: {exc}")


def verify_ed25519(canonical: bytes, sig: dict[str, Any]) -> VerifyResult:
    """Ed25519 verifier per the AP2 PQC v0 ``signatures[].Ed25519`` shape."""
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(_b64d(sig["publicKey_b64"]))
        pub.verify(_b64d(sig["signature_b64"]), canonical)
        return VerifyResult(algorithm="Ed25519", ok=True)
    except InvalidSignature:
        return VerifyResult(algorithm="Ed25519", ok=False, detail="signature invalid")
    except Exception as exc:
        return VerifyResult(algorithm="Ed25519", ok=False, detail=f"{type(exc).__name__}: {exc}")


def verify_falcon_1024(canonical: bytes, sig: dict[str, Any]) -> VerifyResult:
    """Falcon-1024 verifier per the AP2 PQC v0 ``signatures[].Falcon-1024`` shape.

    The Falcon-1024 primitive is PQClean reference C via the ``pqcrypto`` PyPI
    package. This function applies the AlgoVoi-substrate verifier discipline
    around that primitive.
    """
    try:
        ok = _falcon_1024.verify(
            _b64d(sig["publicKey_b64"]),
            canonical,
            _b64d(sig["signature_b64"]),
        )
        return VerifyResult(
            algorithm="Falcon-1024",
            ok=ok,
            detail="" if ok else "pqcrypto.falcon_1024.verify returned False",
        )
    except Exception as exc:
        return VerifyResult(
            algorithm="Falcon-1024", ok=False, detail=f"{type(exc).__name__}: {exc}"
        )


def verify_ml_dsa_65(canonical: bytes, sig: dict[str, Any]) -> VerifyResult:
    """ML-DSA-65 verifier per the AP2 PQC v0 ``signatures[].ML-DSA-65`` shape.

    The ML-DSA-65 primitive is PQClean reference C via the ``pqcrypto`` PyPI
    package. This function applies the AlgoVoi-substrate verifier discipline
    around that primitive.
    """
    try:
        ok = _ml_dsa_65.verify(
            _b64d(sig["publicKey_b64"]),
            canonical,
            _b64d(sig["signature_b64"]),
        )
        return VerifyResult(
            algorithm="ML-DSA-65",
            ok=ok,
            detail="" if ok else "pqcrypto.ml_dsa_65.verify returned False",
        )
    except Exception as exc:
        return VerifyResult(
            algorithm="ML-DSA-65", ok=False, detail=f"{type(exc).__name__}: {exc}"
        )


_VERIFIERS = {
    "ES256": verify_es256,
    "Ed25519": verify_ed25519,
    "Falcon-1024": verify_falcon_1024,
    "ML-DSA-65": verify_ml_dsa_65,
}


def verify_signature(
    canonical: bytes,
    algorithm: str,
    sig: dict[str, Any],
) -> VerifyResult:
    """Dispatch verification for a single signature.

    Applies the fail-closed substrate rule: unknown ``algorithm`` raises
    :class:`UnknownSignatureAlgorithm`. The signing-side caller is expected
    to use only registered values.
    """
    lookup_signature_algorithm(algorithm)  # raises UnknownSignatureAlgorithm
    verifier = _VERIFIERS.get(algorithm)
    if verifier is None:
        # algorithm is in the registry but no verifier is implemented in this
        # package (e.g. SLH-DSA, HMAC). Caller can extend by registering its
        # own verifier; this is intentional substrate vs. implementation
        # separation.
        return VerifyResult(
            algorithm=algorithm,
            ok=False,
            detail=(
                f"algorithm {algorithm!r} is in the recommended-values registry "
                f"but no verifier is implemented in this package; provide your "
                f"own verifier or use an extension"
            ),
        )
    return verifier(canonical, sig)


def verify_artefact(artefact: dict[str, Any]) -> ArtefactVerifyResult:
    """Verify an AP2 PQC v0 artefact end-to-end.

    Steps:

    1. Recompute JCS canonical bytes from ``artefact["mandate_body"]``.
    2. Confirm the recomputed SHA-256 matches ``artefact["expected_canonical_sha256"]``.
    3. For each declared signature, dispatch the per-scheme verifier.
       Unknown identifiers cause :class:`UnknownSignatureAlgorithm` to be
       raised — this is the fail-closed substrate rule.

    Returns :class:`ArtefactVerifyResult` carrying the canonical-bytes check
    plus the per-signature outcomes.
    """
    payload = artefact["mandate_body"]
    canonical = jcs_canonical_bytes(payload)
    recomputed_sha = "sha256:" + hashlib.sha256(canonical).hexdigest()
    expected_sha = artefact["expected_canonical_sha256"]
    sha_ok = recomputed_sha == expected_sha

    results: list[VerifyResult] = []
    for algorithm, sig in artefact.get("signatures", {}).items():
        results.append(verify_signature(canonical, algorithm, sig))

    return ArtefactVerifyResult(
        canonical_sha_ok=sha_ok,
        canonical_sha_recomputed=recomputed_sha,
        canonical_sha_expected=expected_sha,
        signatures=results,
    )


__all__ = [
    "VerifyResult",
    "ArtefactVerifyResult",
    "UnknownSignatureAlgorithm",
    "verify_es256",
    "verify_ed25519",
    "verify_falcon_1024",
    "verify_ml_dsa_65",
    "verify_signature",
    "verify_artefact",
    "KNOWN_SIGNATURE_ALGORITHMS",
]
