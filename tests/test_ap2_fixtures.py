"""Cross-validation against the ap2-pq-conformance joint fixture.

This is the substrate regression suite: the package MUST verify the existing
AlgoVoi-side (ES256 + Ed25519 + Falcon-1024) and PQSafe-side (ML-DSA-65)
artefacts byte-for-byte. If this test breaks, the substrate-author byte-anchor
convergence proof has regressed.

The fixtures live in ``chopmob-cloud/ap2-pq-conformance``; this test resolves
them via a sibling-directory check first (local dev convenience), and falls
back to a no-op skip if neither is available (CI without the sibling clone).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from algovoi_substrate_pqc import verify_artefact


def _find_fixture(rel_path: str) -> Path | None:
    here = Path(__file__).resolve()
    # Walk up looking for sibling ``ap2-pq-conformance``.
    candidates = [
        here.parents[3] / "ap2-pq-conformance" / rel_path,  # algo/ root, sibling repo
        here.parents[2] / "ap2-pq-conformance" / rel_path,
        Path("/algo/ap2-pq-conformance") / rel_path,
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


@pytest.mark.parametrize(
    ("fixture_relpath", "expected_signature_count"),
    [
        ("algovoi-side/ap2-pqc-v0-algovoi-side.json", 3),  # ES256 + Ed25519 + Falcon-1024
        ("pqsafe-side/ap2-pqc-v0-pqsafe-side.json", 1),  # ML-DSA-65
    ],
)
def test_existing_ap2_pq_conformance_fixture_verifies(
    fixture_relpath, expected_signature_count
):
    """Each AP2 PQC v0 fixture verifies end-to-end through this package's verifier."""
    path = _find_fixture(fixture_relpath)
    if path is None:
        pytest.skip(f"ap2-pq-conformance fixture {fixture_relpath} not available locally")

    artefact = json.loads(path.read_text(encoding="utf-8"))

    # The PQSafe-side fixture uses a different schema (no `mandate_body` field;
    # the canonical bytes are embedded directly via ALGOVOI_JCS_HEX in its
    # standalone verify.py). For that case, fall through to a manual verification
    # path using the JCS-canonical from the AlgoVoi-side fixture.
    if "mandate_body" not in artefact:
        # PQSafe-side fixture: signs over the AlgoVoi-side canonical bytes.
        algovoi_path = _find_fixture("algovoi-side/ap2-pqc-v0-algovoi-side.json")
        if algovoi_path is None:
            pytest.skip("PQSafe-side fixture requires algovoi-side fixture as canonical source")
        algovoi_art = json.loads(algovoi_path.read_text(encoding="utf-8"))
        # Borrow the canonical payload + repackage signatures into the v0 schema
        # shape so verify_artefact() can run.
        rebound = {
            "mandate_body": algovoi_art["mandate_body"],
            "expected_canonical_sha256": artefact["expected_canonical_sha256"],
            "signatures": artefact["signatures"],
        }
        result = verify_artefact(rebound)
    else:
        result = verify_artefact(artefact)

    assert result.canonical_sha_ok, (
        f"canonical SHA mismatch on {fixture_relpath}: "
        f"recomputed={result.canonical_sha_recomputed} "
        f"expected={result.canonical_sha_expected}"
    )
    assert len(result.signatures) == expected_signature_count, (
        f"expected {expected_signature_count} signatures in {fixture_relpath}, "
        f"got {len(result.signatures)}"
    )
    for s in result.signatures:
        assert s.ok, f"{s.algorithm} failed: {s.detail}"
