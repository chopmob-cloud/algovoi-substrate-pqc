"""Canonical-bytes derivation — RFC 8785 (Anders Rundgren) via ``rfc8785``.

This module is a thin re-export of the Rundgren JCS canonicalisation rule.
The canonicalisation algorithm itself is RFC 8785 (Anders Rundgren); the
Python implementation is the ``rfc8785`` PyPI package.

AlgoVoi's substrate-author contribution is the **binding** of these canonical
bytes to a signature artefact (see :mod:`algovoi_substrate_pqc.sign` and
:mod:`algovoi_substrate_pqc.proof`), not the canonicalisation rule itself.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


def jcs_canonical_bytes(payload: Any) -> bytes:
    """Return the RFC 8785 JCS canonical-byte representation of ``payload``.

    Thin re-export of :func:`rfc8785.dumps` for substrate-author convenience.
    The canonicalisation rule is RFC 8785 (Anders Rundgren); see the package
    README for upstream attribution.
    """
    return rfc8785.dumps(payload)


def jcs_canonical_sha256_hex(payload: Any) -> str:
    """Return ``"sha256:" + hex(sha256(jcs(payload)))``.

    The artefact-level byte-anchor format used across AlgoVoi-substrate
    conformance fixtures (e.g. ``sha256:cc8315f7…e0`` for the AP2 PaymentMandate
    joint fixture).
    """
    return "sha256:" + hashlib.sha256(jcs_canonical_bytes(payload)).hexdigest()
