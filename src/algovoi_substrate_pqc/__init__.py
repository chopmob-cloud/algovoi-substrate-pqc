"""algovoi-substrate-pqc — AlgoVoi substrate-author layer for JCS+PQC integration.

AlgoVoi-authored substrate:

- ``signature_algorithm`` open-enum convention (12-row recommended-values
  registry), with fail-closed verifier discipline (unknown identifiers are
  treated as opaque and refused).
- JCS+PQC integration pattern: canonical bytes via RFC 8785 (Anders Rundgren) →
  signature via chosen scheme → artefact with ``expected_canonical_sha256``
  byte-anchor.
- Cross-implementor byte-anchor convergence proof: one canonical payload,
  multiple signature schemes, byte-identical SHA-256 across implementations.

Underlying primitives (we depend on, do not claim authorship):

- Falcon-1024 / ML-DSA-65 — PQClean reference C, exposed via the ``pqcrypto``
  PyPI package (Backbone Authors, Apache-2.0).
- ES256 / Ed25519 — Python Cryptographic Authority (``cryptography``).
- JCS canonicalisation — Anders Rundgren / RFC 8785 (``rfc8785``).
- SHA-256 — NIST FIPS 180-4 (stdlib ``hashlib``).

See README.md for the full attribution table.
"""

__version__ = "0.1.2"

from .canonical import jcs_canonical_bytes, jcs_canonical_sha256_hex
from .proof import CanonicalAnchor, build_convergence_artefact
from .registry import (
    KNOWN_SIGNATURE_ALGORITHMS,
    SignatureAlgorithmFamily,
    SignatureAlgorithmRecord,
    UnknownSignatureAlgorithm,
    lookup_signature_algorithm,
)
from .sign import (
    generate_falcon_1024_keypair,
    generate_ml_dsa_65_keypair,
    sign_ed25519,
    sign_es256,
    sign_falcon_1024,
    sign_ml_dsa_65,
)
from .verify import (
    ArtefactVerifyResult,
    VerifyResult,
    verify_artefact,
    verify_ed25519,
    verify_es256,
    verify_falcon_1024,
    verify_ml_dsa_65,
    verify_signature,
)

__all__ = [
    "__version__",
    # registry
    "KNOWN_SIGNATURE_ALGORITHMS",
    "SignatureAlgorithmFamily",
    "SignatureAlgorithmRecord",
    "UnknownSignatureAlgorithm",
    "lookup_signature_algorithm",
    # canonical
    "jcs_canonical_bytes",
    "jcs_canonical_sha256_hex",
    # sign
    "sign_es256",
    "sign_ed25519",
    "sign_falcon_1024",
    "sign_ml_dsa_65",
    "generate_falcon_1024_keypair",
    "generate_ml_dsa_65_keypair",
    # verify
    "VerifyResult",
    "ArtefactVerifyResult",
    "verify_es256",
    "verify_ed25519",
    "verify_falcon_1024",
    "verify_ml_dsa_65",
    "verify_signature",
    "verify_artefact",
    # proof
    "CanonicalAnchor",
    "build_convergence_artefact",
]
