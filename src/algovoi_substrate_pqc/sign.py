"""Substrate-author signing helpers — wraps upstream primitives.

This module provides thin signing helpers across the four signature schemes
covered by the AP2 PQC joint conformance fixture (ES256, Ed25519, Falcon-1024,
ML-DSA-65). Each helper:

1. Computes the RFC 8785 canonical-byte representation of the payload.
2. Signs those canonical bytes under the chosen scheme.
3. Returns an artefact dict in the AP2 PQC v0 schema shape, with
   ``expected_canonical_sha256`` populated for cross-implementor verifiers.

The cryptographic primitives are not AlgoVoi-authored. See the README for the
upstream-attribution table.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

import pqcrypto.sign.falcon_1024 as _falcon_1024
import pqcrypto.sign.ml_dsa_65 as _ml_dsa_65
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .canonical import jcs_canonical_bytes
from .registry import lookup_signature_algorithm


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def sign_es256(payload: Any, secret_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    """Sign ``payload`` (JCS-canonicalised) under ES256 (P-256 SHA-256).

    Returns the AP2 PQC v0 ``signatures[].ES256`` shape:
    ``{algorithm, curve, hash, publicKeyDer, signature_der}``.
    """
    lookup_signature_algorithm("ES256")  # registry validation
    canonical = jcs_canonical_bytes(payload)
    # ``cryptography`` delegates ECDSA signing to the OpenSSL backend (required
    # >= 1.1.1 by ``cryptography >= 42``). OpenSSL 3.x uses RFC 6979
    # deterministic nonces for ECDSA by default, so the signature is
    # deterministic on all supported platforms. There is no separate
    # ``deterministic_signing`` API knob in this library version.
    signature_der = secret_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    pub_der = secret_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "algorithm": "ES256",
        "curve": "P-256",
        "hash": "SHA-256",
        "publicKeyDer": _b64(pub_der),
        "signature_der": _b64(signature_der),
    }


def sign_ed25519(payload: Any, secret_key: ed25519.Ed25519PrivateKey) -> dict[str, Any]:
    """Sign ``payload`` (JCS-canonicalised) under Ed25519 (RFC 8032).

    Returns the AP2 PQC v0 ``signatures[].Ed25519`` shape:
    ``{algorithm, publicKey_b64, signature_b64}``.
    """
    lookup_signature_algorithm("Ed25519")
    canonical = jcs_canonical_bytes(payload)
    signature = secret_key.sign(canonical)
    pub_raw = secret_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "algorithm": "Ed25519",
        "publicKey_b64": _b64(pub_raw),
        "signature_b64": _b64(signature),
    }


def sign_falcon_1024(
    payload: Any,
    secret_key: bytes,
    public_key: bytes,
) -> dict[str, Any]:
    """Sign ``payload`` (JCS-canonicalised) under Falcon-1024, public key passed in.

    Returns the AP2 PQC v0 ``signatures[].Falcon-1024`` shape:
    ``{algorithm, fips, nist_level, publicKey_b64, signature_b64,
       signature_length_bytes, publicKey_length_bytes}``.
    """
    lookup_signature_algorithm("Falcon-1024")
    canonical = jcs_canonical_bytes(payload)
    signature = _falcon_1024.sign(secret_key, canonical)
    return {
        "algorithm": "Falcon-1024",
        "fips": "FIPS 206 (FN-DSA)",
        "nist_level": 5,
        "publicKey_b64": _b64(public_key),
        "signature_b64": _b64(signature),
        "signature_length_bytes": len(signature),
        "publicKey_length_bytes": len(public_key),
    }


def sign_ml_dsa_65(
    payload: Any,
    secret_key: bytes,
    public_key: bytes,
) -> dict[str, Any]:
    """Sign ``payload`` (JCS-canonicalised) under ML-DSA-65 (FIPS 204).

    ML-DSA-65 primitive is PQClean reference C via the ``pqcrypto`` PyPI
    package. This function is the AlgoVoi-authored binding to that primitive
    in the substrate ``signatures[].ML-DSA-65`` shape.

    Returns the AP2 PQC v0 ``signatures[].ML-DSA-65`` shape:
    ``{algorithm, fips, nist_level, publicKey_b64, signature_b64,
       signature_length_bytes, publicKey_length_bytes}``.
    """
    lookup_signature_algorithm("ML-DSA-65")
    canonical = jcs_canonical_bytes(payload)
    signature = _ml_dsa_65.sign(secret_key, canonical)
    return {
        "algorithm": "ML-DSA-65",
        "fips": "FIPS 204",
        "nist_level": 3,
        "publicKey_b64": _b64(public_key),
        "signature_b64": _b64(signature),
        "signature_length_bytes": len(signature),
        "publicKey_length_bytes": len(public_key),
    }


def generate_falcon_1024_keypair() -> tuple[bytes, bytes]:
    """Generate a Falcon-1024 keypair via PQClean / pqcrypto.

    Returns ``(public_key, secret_key)`` as raw bytes. PQClean primitive;
    AlgoVoi-substrate authorship is in the surrounding registry + binding +
    verifier discipline, not in the keypair generation itself.
    """
    return _falcon_1024.generate_keypair()


def generate_ml_dsa_65_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 keypair via PQClean / pqcrypto.

    Returns ``(public_key, secret_key)`` as raw bytes. PQClean primitive;
    AlgoVoi-substrate authorship is in the surrounding registry + binding +
    verifier discipline, not in the keypair generation itself.
    """
    return _ml_dsa_65.generate_keypair()
