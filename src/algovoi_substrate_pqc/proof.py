"""Cross-implementor byte-anchor convergence proof — AlgoVoi-authored methodology.

The substrate-author position rests on byte-anchor convergence: one canonical
payload, N independent signature schemes, byte-identical SHA-256 across
implementations. This module provides the helper for constructing such
artefacts.

The reference exemplar is the AP2 PaymentMandate joint fixture at
``chopmob-cloud/ap2-pq-conformance``, where AlgoVoi-side (ES256 + Ed25519 +
Falcon-1024) and PQSafe-side (ML-DSA-65) both sign over the identical 501-byte
JCS canonical anchored at ``sha256:cc8315f7…e0``.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
from dataclasses import dataclass
from typing import Any

from .canonical import jcs_canonical_bytes


@dataclass
class CanonicalAnchor:
    """The canonical-bytes anchor for a payload.

    All N signatures in a convergence-proof artefact MUST be over these
    identical bytes; the SHA-256 of these bytes is the substrate-level
    cross-implementor agreement point.
    """

    bytes: bytes
    sha256_hex_prefixed: str  # ``sha256:<lowercase-hex-64>``
    length: int
    b64: str
    hex: str

    @classmethod
    def from_payload(cls, payload: Any) -> "CanonicalAnchor":
        b = jcs_canonical_bytes(payload)
        return cls(
            bytes=b,
            sha256_hex_prefixed="sha256:" + hashlib.sha256(b).hexdigest(),
            length=len(b),
            b64=base64.b64encode(b).decode("ascii"),
            hex=b.hex(),
        )


def build_convergence_artefact(
    payload: Any,
    signatures: dict[str, dict[str, Any]],
    *,
    artefact_id: str,
    canonicalizer: str = "rfc8785@0.1.4",
    anchored_to: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a cross-implementor byte-anchor convergence artefact.

    :param payload: the payload to canonicalise (e.g. AP2 PaymentMandate body).
    :param signatures: a dict mapping ``signature_algorithm`` identifier
        (e.g. ``"Falcon-1024"``) to the signature dict returned by the
        corresponding :mod:`.sign` helper.
    :param artefact_id: a stable identifier for this artefact (e.g.
        ``"ap2-pqc-conformance-v0-algovoi-side"``).
    :param canonicalizer: the canonicalizer used; conventionally
        ``"rfc8785@0.1.4"``.
    :param anchored_to: optional dict naming the thread, schema, and RFC the
        artefact is anchored to.
    :param context: optional dict naming the purpose, the verification recipe,
        and any cross-implementor coordination notes.

    Returns the AP2 PQC v0 artefact-schema dict shape.
    """
    anchor = CanonicalAnchor.from_payload(payload)
    return {
        "schema_version": "1.0",
        "artefact_id": artefact_id,
        "canonicalizer": canonicalizer,
        "published_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "anchored_to": anchored_to or {},
        "context": context or {},
        "mandate_body": payload,
        "expected_jcs_bytes_b64": anchor.b64,
        "expected_jcs_bytes_hex": anchor.hex,
        "expected_jcs_bytes_length": anchor.length,
        "expected_canonical_sha256": anchor.sha256_hex_prefixed,
        "signatures": signatures,
    }
