#!/usr/bin/env python3
"""Python producer for the cross-product matrix.

Generates a fresh AP2 PQC v0 artefact signed with all four schemes
(ES256 + Ed25519 + Falcon-1024 + ML-DSA-65) over the shared cross-product
canonical payload. Writes the artefact to ``_attestations/<date>-cross-product/
producers/python.json``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from algovoi_substrate_pqc import (
    build_convergence_artefact,
    generate_falcon_1024_keypair,
    generate_ml_dsa_65_keypair,
    sign_ed25519,
    sign_es256,
    sign_falcon_1024,
    sign_ml_dsa_65,
)


# The cross-product matrix uses a stable payload that all producers sign so
# every producer's canonical SHA-256 is identical and every verifier knows what
# to expect. The payload is the AP2 PaymentMandate exemplar — same payload as
# the AP2 PQ conformance fixture, so byte-anchor sha256:cc8315f7…e0 applies.
PAYLOAD = {
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


def main(out_path: Path) -> int:
    es_sk = ec.generate_private_key(ec.SECP256R1())
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    fk_pub, fk_sk = generate_falcon_1024_keypair()
    mk_pub, mk_sk = generate_ml_dsa_65_keypair()

    signatures = {
        "ES256": sign_es256(PAYLOAD, es_sk),
        "Ed25519": sign_ed25519(PAYLOAD, ed_sk),
        "Falcon-1024": sign_falcon_1024(PAYLOAD, fk_sk, fk_pub),
        "ML-DSA-65": sign_ml_dsa_65(PAYLOAD, mk_sk, mk_pub),
    }

    artefact = build_convergence_artefact(
        PAYLOAD,
        signatures,
        artefact_id="cross-product-v0-python-side",
        anchored_to={
            "thread": "https://github.com/chopmob-cloud/algovoi-substrate-pqc",
            "schema": "AP2 PaymentMandate v0.1 (cross-product exemplar)",
            "rfc": "RFC 8785 (JCS)",
        },
        context={
            "producer": "python/algovoi-substrate-pqc v0.1.0",
            "producer_runtime": (
                f"python/{sys.version_info.major}.{sys.version_info.minor}"
                f".{sys.version_info.micro}"
            ),
            "purpose": "Python-side producer for the cross-product matrix; "
            "signs the stable canonical payload under all 4 schemes the package "
            "supports. Other producers (TypeScript, Ruby, PHP) sign the IDENTICAL "
            "canonical payload and their artefacts are cross-verified by every "
            "available verifier.",
        },
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(artefact, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {out_path} (signatures: {sorted(signatures)})")
    return 0


if __name__ == "__main__":
    default_out = (
        Path(__file__).resolve().parents[1]
        / "_attestations"
        / "2026-05-26-cross-product"
        / "producers"
        / "python.json"
    )
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else default_out
    sys.exit(main(out))
