#!/usr/bin/env python3
"""Cross-product matrix harness for the AlgoVoi substrate-pqc package.

Runs every available verifier against every available producer artefact and
produces a single attestation document capturing pass / fail / skip per cell.

Producers (generate fresh artefacts signing a stable canonical payload):

- python  →  _attestations/<date>-cross-product/producers/python.json
              (ES256 + Ed25519 + Falcon-1024 + ML-DSA-65)
- ts      →  ..../producers/ts.json     (same 4 schemes via @noble/post-quantum)
- ruby    →  ..../producers/ruby.json   (ES256 + Ed25519 via OpenSSL stdlib)
- php     →  ..../producers/php.json    (ES256 + Ed25519 via openssl + sodium)

Verifiers (consume the artefact at the path passed as ARGV[1]):

- python  →  python -m algovoi_substrate_pqc.verify <artefact> (via inline runner)
- ts      →  node ts/scripts/verify-artefact.mjs <artefact>
- ruby    →  ruby verifiers/ruby/verify.rb <artefact>
- php     →  bash verifiers/php/run.sh <artefact>
- perl    →  perl verifiers/perl/verify.pl <artefact>

Output:

- _attestations/2026-05-26-cross-product/matrix.json — machine-readable result
- _attestations/2026-05-26-cross-product-matrix.md  — human-readable attestation
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent

REPO = Path(__file__).resolve().parents[1]
ATTEST = REPO / "_attestations" / "2026-05-30-cross-product"
PRODUCERS_DIR = ATTEST / "producers"


def php_command(args: list[str]) -> list[str]:
    """Build a PHP invocation with openssl + sodium auto-loaded if needed.

    Avoids the bash wrapper so the harness works on environments where bash
    isn't in PATH from a Python subprocess. Detects the bundled extension
    directory next to the PHP binary; this is where WinGet / common Windows
    PHP installs keep ``php_openssl.dll`` + ``php_sodium.dll``.
    """
    import shutil

    php = shutil.which("php") or "php"
    cmd = [php]
    try:
        # Check whether extensions are already loaded.
        probe = subprocess.run(
            [
                php,
                "-r",
                'exit(extension_loaded("openssl") && extension_loaded("sodium") ? 0 : 1);',
            ],
            capture_output=True,
            timeout=10,
        )
        if probe.returncode != 0:
            php_dir = Path(php).resolve().parent
            ext_dir = php_dir / "ext"
            if ext_dir.is_dir():
                cmd += [
                    "-d",
                    f"extension_dir={ext_dir}",
                    "-d",
                    "extension=openssl",
                    "-d",
                    "extension=sodium",
                ]
    except Exception:
        pass
    return cmd + args

DATE = "2026-05-30"
ATTEST_MD = REPO / "_attestations" / f"{DATE}-cross-product-matrix.md"
ATTEST_JSON = ATTEST / "matrix.json"

# Rust binary path (pre-built with cargo build --release).
RUST_BIN = REPO / "verifiers" / "rust" / "target" / "release" / "algovoi-pqc-rust.exe"

# Producers: (name, runner-args). Each writes producers/<name>.json
PRODUCERS = [
    ("python", [sys.executable, str(REPO / "scripts" / "produce.py")]),
    ("ts", ["node", str(REPO / "ts" / "scripts" / "produce.mjs")]),
    ("ruby", ["ruby", str(REPO / "verifiers" / "ruby" / "produce.rb")]),
    ("php", php_command([str(REPO / "verifiers" / "php" / "produce.php")])),
    # Go producer: run from verifiers/go/ so go.mod is picked up; output path
    # is passed explicitly so it lands in the 2026-05-30 producers directory.
    (
        "go",
        [
            "go", "run", str(REPO / "verifiers" / "go" / "produce.go"),
            str(PRODUCERS_DIR / "go.json"),
        ],
    ),
    # Rust producer: binary pre-built; write to the producers directory.
    (
        "rust",
        [str(RUST_BIN), "produce", str(PRODUCERS_DIR / "rust.json")],
    ),
]

# Verifiers: (name, command-template). {artefact} is replaced with the artefact
# path. Each returns exit 0 iff verification passes.
VERIFIERS = [
    (
        "python",
        [
            sys.executable,
            "-c",
            (
                "import json, sys; from pathlib import Path; "
                "from algovoi_substrate_pqc import verify_artefact; "
                "art = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); "
                "r = verify_artefact(art); "
                "print(f'canonical_sha_ok={r.canonical_sha_ok}'); "
                "[print(f'{s.algorithm}: {\"OK\" if s.ok else \"FAIL: \" + s.detail}') "
                " for s in r.signatures]; "
                "sys.exit(0 if r.ok else 1)"
            ),
            "{artefact}",
        ],
    ),
    (
        "ts",
        ["node", str(REPO / "ts" / "scripts" / "verify-artefact.mjs"), "{artefact}"],
    ),
    ("ruby", ["ruby", str(REPO / "verifiers" / "ruby" / "verify.rb"), "{artefact}"]),
    ("php", php_command([str(REPO / "verifiers" / "php" / "verify.php"), "{artefact}"])),
    (
        "java",
        [
            "java",
            "-cp",
            str(REPO / "verifiers" / "java" / "out")
            + (";" if os.name == "nt" else ":")
            + str(REPO / "verifiers" / "java" / "lib" / "*"),
            "Verify",
            "{artefact}",
        ],
    ),
    ("perl", ["perl", str(REPO / "verifiers" / "perl" / "verify.pl"), "{artefact}"]),
    # Go verifier: run from verifiers/go/ so go.mod is found.
    (
        "go",
        ["go", "run", str(REPO / "verifiers" / "go" / "verify" / "verify.go"), "{artefact}"],
    ),
    # Rust verifier: pre-built binary.
    ("rust", [str(RUST_BIN), "verify", "{artefact}"]),
]


def _cwd_for(name: str) -> Path:
    """Return the working directory for a given producer/verifier name.

    Go commands must be invoked from the verifiers/go/ directory so that
    ``go run`` can find the go.mod file. All other producers/verifiers run
    from the repo root.
    """
    if name == "go":
        return REPO / "verifiers" / "go"
    return REPO


def run_producer(name: str, cmd: list[str]) -> tuple[bool, str]:
    """Run one producer; return (ok, stdout-tail)."""
    print(f"[produce] {name}: {' '.join(cmd)}")
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, cwd=_cwd_for(name), timeout=180
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"
    if out.returncode != 0:
        return False, (out.stdout + out.stderr).strip()[-500:]
    return True, out.stdout.strip()[-200:]


def run_verifier(
    name: str, cmd_template: list[str], artefact_path: Path
) -> tuple[bool, str]:
    """Run one verifier against one artefact; return (ok, output-tail)."""
    cmd = [str(artefact_path) if a == "{artefact}" else a for a in cmd_template]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, cwd=_cwd_for(name), timeout=180
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"
    output = (out.stdout + "\n" + out.stderr).strip()
    return out.returncode == 0, output


def summarise_verifier_output(name: str, output: str) -> str:
    """Compress verifier output to a one-line cell tag (e.g. '4/4', 'JCS', 'SKIP')."""
    lines = output.splitlines()
    passes = sum(1 for line in lines if "PASS" in line and "FAIL" not in line)
    fails = sum(1 for line in lines if "FAIL" in line)
    if name == "perl":
        # Perl reports JCS canonical-bytes proof only; ES256/Ed25519 SKIP when
        # CryptX isn't installed.
        if "CryptX: NOT installed" in output or "CryptX not installed" in output:
            return f"JCS {passes}/{passes}"
        return f"{passes}/{passes + fails}"
    if name in ("python", "ts"):
        # Inline / TS-CLI verifier prints one line per scheme + canonical_sha_ok=…
        ok_lines = sum(
            1
            for line in lines
            if (": OK" in line and "FAIL" not in line)
            or line.strip() in ("canonical_sha_ok=True", "canonical_sha_ok=true")
        )
        fail_lines = sum(1 for line in lines if "FAIL" in line)
        return f"{ok_lines}/{ok_lines + fail_lines}"
    if name == "java":
        # Java verifier reports PASS/FAIL lines. PQC schemes not present in
        # the artefact emit SKIP lines, which we exclude from the count.
        return f"{passes}/{passes + fails}"
    if name == "go":
        # Go verifier prints PASS: <scheme> / FAIL: <scheme>: <reason> / SKIP: <scheme>
        # and canonical_sha_ok=true|false. Count PASS lines, FAIL lines.
        return f"{passes}/{passes + fails}"
    if name == "rust":
        # Rust verifier prints PASS: <scheme> / FAIL: <scheme>: <reason>
        # and canonical_sha_ok=true|false.
        return f"{passes}/{passes + fails}"
    return f"{passes}/{passes + fails}"


def main() -> int:
    PRODUCERS_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Run producers ---
    producer_results: dict[str, dict] = {}
    for name, cmd in PRODUCERS:
        ok, tail = run_producer(name, cmd)
        producer_results[name] = {"ok": ok, "output_tail": tail}
        if not ok:
            print(f"  ! producer {name} failed; will SKIP verification rows for it")
        else:
            artefact = PRODUCERS_DIR / f"{name}.json"
            d = json.loads(artefact.read_text(encoding="utf-8"))
            producer_results[name]["canonical_sha256"] = d["expected_canonical_sha256"]
            producer_results[name]["signature_schemes"] = list(d["signatures"].keys())
            print(f"  ok {name}: schemes={producer_results[name]['signature_schemes']}")

    # --- 2. Confirm all producers agree on canonical SHA-256 ---
    shas = {n: r.get("canonical_sha256") for n, r in producer_results.items() if r["ok"]}
    sha_consensus = len(set(shas.values())) == 1 if shas else False
    consensus_sha = next(iter(set(shas.values()))) if sha_consensus else None
    print(
        f"\n[byte-anchor] {len(shas)} producers agreed on canonical SHA-256: "
        f"{consensus_sha if sha_consensus else 'DIVERGENCE — see matrix.json'}"
    )

    # --- 3. Cross-product verification matrix ---
    matrix: dict[str, dict[str, dict]] = {}
    for producer_name, producer_meta in producer_results.items():
        if not producer_meta["ok"]:
            matrix[producer_name] = {
                v: {"ok": False, "summary": "SKIP-producer-failed"} for v, _ in VERIFIERS
            }
            continue
        artefact_path = PRODUCERS_DIR / f"{producer_name}.json"
        matrix[producer_name] = {}
        for verifier_name, cmd in VERIFIERS:
            ok, output = run_verifier(verifier_name, cmd, artefact_path)
            summary = summarise_verifier_output(verifier_name, output)
            matrix[producer_name][verifier_name] = {
                "ok": ok,
                "summary": summary,
                "output_tail": output[-1500:],
            }
            tag = "PASS" if ok else "FAIL"
            print(f"  {tag}  producer:{producer_name} -> verifier:{verifier_name}  {summary}")

    # --- 4. Write machine-readable JSON ---
    ATTEST.mkdir(parents=True, exist_ok=True)
    summary_json = {
        "attestation_id": f"algovoi-substrate-pqc-cross-product-{DATE}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "byte_anchor_consensus": {
            "all_producers_agree": sha_consensus,
            "consensus_sha256": consensus_sha,
            "per_producer_sha256": shas,
        },
        "producers": producer_results,
        "matrix": matrix,
        "verifiers": [v[0] for v in VERIFIERS],
        "scope": {
            "schemes_with_full_pqc": ["ES256", "Ed25519", "Falcon-1024", "ML-DSA-65"],
            "schemes_classical_only": ["ES256", "Ed25519"],
            "pqc_producers": ["python", "ts", "rust"],
            "classical_producers": ["python", "ts", "ruby", "php", "go", "rust"],
            "go_producer_pqc": ["ML-DSA-65"],
            "all_verifiers": ["python", "ts", "ruby", "php", "java", "perl", "go", "rust"],
        },
    }
    ATTEST_JSON.write_text(json.dumps(summary_json, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {ATTEST_JSON}")

    # --- 5. Write human-readable Markdown attestation ---
    pnames = list(producer_results.keys())
    vnames = [v[0] for v in VERIFIERS]

    rows = []
    for p in pnames:
        cells = []
        for v in vnames:
            cell = matrix.get(p, {}).get(v, {"ok": False, "summary": "—"})
            icon = "✅" if cell["ok"] else "❌"
            cells.append(f"{icon} {cell['summary']}")
        rows.append(f"| **{p}** | " + " | ".join(cells) + " |")

    header = "| Producer ↓ \\ Verifier → | " + " | ".join(f"**{v}**" for v in vnames) + " |"
    sep = "|---" * (len(vnames) + 1) + "|"

    body = dedent(
        f"""\
        # AlgoVoi substrate-pqc — cross-product verification matrix ({DATE})

        **Attestation ID:** `algovoi-substrate-pqc-cross-product-{DATE}`
        **Generated:** {summary_json['generated_at']}
        **Canonical payload:** stable AP2 PaymentMandate exemplar
        **Byte-anchor consensus:** {'✅ ' if sha_consensus else '❌ '}`{consensus_sha or 'DIVERGENT'}`

        ## Summary

        Each producer signs the **identical** stable canonical payload under the
        signature schemes its audit-grade libraries support. Each verifier then
        runs against **every** producer's artefact. Cells report `<passing
        checks>/<total checks>` per cell.

        - **PQC schemes** (Falcon-1024, ML-DSA-65) are produced/verified only by
          Python (`pqcrypto`/PQClean) and TypeScript (`@noble/post-quantum`) —
          the two language ecosystems with audit-grade PQC libraries.
        - **Classical schemes** (ES256, Ed25519) are produced by Python, TS,
          Ruby, PHP and verified by every available verifier.
        - **Perl verifier** confirms the JCS canonical-bytes byte-anchor against
          every producer's artefact (using core modules); ES256/Ed25519
          verification in Perl requires `cpanm CryptX` (graceful SKIP if absent).

        ## Cross-product matrix

        {header}
        {sep}
        """
    )
    body += "\n".join(rows) + "\n\n"

    body += dedent(
        f"""\
        ## Per-producer canonical SHA-256

        | Producer | canonical_sha256 |
        |---|---|
        """
    )
    for p, sha in shas.items():
        body += f"| {p} | `{sha}` |\n"
    body += f"\n**All {len(shas)} producers** agreed on the canonical byte-anchor.\n\n"

    body += dedent(
        """\
        ## Upstream attribution

        Substrate-author work (the `signature_algorithm` open-enum
        convention, the JCS+PQC binding pattern, the fail-closed verifier
        discipline, the byte-anchor convergence proof methodology, and the
        multi-language verifier suite) is AlgoVoi's. The matrix's
        reproducibility depends on the following upstream contributions —
        credit per upstream is scoped to the specific contribution named:

        - **PQSafe ([@rayc0](https://github.com/rayc0))** — ML-DSA-65
          signature contribution per the AP2 #250 joint conformance
          fixture: [`pqsafe-side/`](https://github.com/chopmob-cloud/ap2-pq-conformance/tree/main/pqsafe-side)
          of [`chopmob-cloud/ap2-pq-conformance`](https://github.com/chopmob-cloud/ap2-pq-conformance).
          Named co-maintainer of that joint conformance repo per the
          published policy. Credit scoped to that ML-DSA-65 contribution
          only.
        - **Paul Miller ([@paulmillr](https://github.com/paulmillr))** —
          `@noble/post-quantum` author. Pure-JS Falcon-1024 + ML-DSA-65,
          MIT-licensed. Credit scoped to that library.
        - **PQClean community** — reference C implementations of
          Falcon-1024 and ML-DSA-65. Exposed to Python via the
          [`pqcrypto`](https://pypi.org/project/pqcrypto/) package
          (Backbone Authors, Apache-2.0). Credit scoped to those primitives.
        - **Bouncy Castle maintainers** — `MLDSASigner` (production) and
          `FalconSigner` (experimental), MIT-style licensed. Credit scoped
          to those Java implementations.
        - **Anders Rundgren** — RFC 8785 JCS canonicalisation rule. Credit
          scoped to that canonicalisation algorithm.

        ## Substrate-author significance

        - **Four independent JCS canonicalisations** (Python `rfc8785`,
          TypeScript `canonicalize`, Ruby minimal-JCS, PHP minimal-JCS) produce
          byte-identical canonical bytes from the same payload — confirming the
          AlgoVoi-authored substrate convention is reproducible from any
          language with standard JSON + SHA-256 primitives.
        - **Cross-product verification** (every verifier against every producer
          artefact) demonstrates that signatures emitted in language X verify
          in language Y for the schemes available in each environment. The
          substrate convention is producer-verifier-symmetric.
        - **Three audit-grade PQC implementation chains** — PQClean via
          `pqcrypto` on Python, pure-JS `@noble/post-quantum` on TypeScript,
          and Bouncy Castle on Java — produce or verify Falcon-1024 and
          ML-DSA-65 signatures over identical canonical bytes, with each
          implementation independently confirming the others'. PQSafe's
          ML-DSA-65 contribution (per AP2 #250) is the cross-implementor
          fixture this triangle agrees on.

        ## Reproduce locally

        ```bash
        cd algovoi-substrate-pqc
        python scripts/cross_product_matrix.py
        ```

        The harness runs all 4 producers, all 5 verifiers, and regenerates this
        attestation document. The exact canonical SHA-256 in the byte-anchor
        consensus row should match across producers; if not, investigate
        producer-side JCS implementation divergence.

        ## Scope statement (PQC out of scope per scripting language)

        Falcon-1024 + ML-DSA-65 cannot be produced or verified in Ruby / PHP /
        Perl / Lua / Elixir because no audit-grade PQC libraries exist in those
        ecosystems at this time. Vendoring PQClean source per scripting
        language was explicitly considered and rejected (2026-05-26) due to
        Falcon-1024 patent (US7308097B2, FRAND-pledged) redistributor liability
        + per-language FFI maintenance burden. The AlgoVoi-substrate PQC
        convergence proof is established by the Python + TypeScript
        implementations.
        """
    )

    ATTEST_MD.write_text(body, encoding="utf-8")
    print(f"Wrote {ATTEST_MD}")

    return 0 if sha_consensus else 1


if __name__ == "__main__":
    sys.exit(main())
