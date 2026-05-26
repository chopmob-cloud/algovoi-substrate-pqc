<?php
declare(strict_types=1);

/**
 * AlgoVoi substrate-pqc — PHP verifier (classical schemes only).
 *
 * Loads the AP2 PQ conformance fixture, recomputes the JCS canonical bytes,
 * confirms the canonical SHA-256 byte-anchor, and verifies ES256 + Ed25519
 * signatures against the published public keys.
 *
 * Falcon-1024 and ML-DSA-65 are out of scope: no audit-grade PQC library
 * exists for PHP. The substrate-author PQC convergence proof is established
 * by the Python and TypeScript implementations.
 *
 * Usage:
 *   php verify.php [path/to/ap2-pqc-v0-algovoi-side.json]
 */

const EXPECTED_ANCHOR =
    'sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0';

const DEFAULT_FIXTURES = [
    'C:/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
    '/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
];

/**
 * Minimal JCS (RFC 8785) canonicalisation for the AP2 PaymentMandate
 * payload shape. Handles ASCII string keys, lexicographic sort, integer
 * decimals, arrays in order, booleans, and null. Strings are escaped per
 * RFC 8259 minimum-escape rules.
 */
function jcs($value): string {
    if (is_array($value)) {
        if (array_keys($value) === range(0, count($value) - 1)) {
            // List
            return '[' . implode(',', array_map('jcs', $value)) . ']';
        }
        $keys = array_keys($value);
        sort($keys, SORT_STRING);
        $parts = [];
        foreach ($keys as $k) {
            $parts[] = jcs((string)$k) . ':' . jcs($value[$k]);
        }
        return '{' . implode(',', $parts) . '}';
    }
    if (is_string($value)) {
        return jsonEscape($value);
    }
    if (is_int($value)) {
        return (string)$value;
    }
    if (is_bool($value)) {
        return $value ? 'true' : 'false';
    }
    if ($value === null) {
        return 'null';
    }
    throw new RuntimeException('JCS: unsupported value type ' . gettype($value));
}

function jsonEscape(string $s): string {
    $out = '"';
    $len = strlen($s);
    for ($i = 0; $i < $len; $i++) {
        $c = $s[$i];
        $cp = ord($c);
        if ($cp === 0x22) {
            $out .= '\\"';
        } elseif ($cp === 0x5c) {
            $out .= '\\\\';
        } elseif ($cp === 0x08) {
            $out .= '\\b';
        } elseif ($cp === 0x09) {
            $out .= '\\t';
        } elseif ($cp === 0x0a) {
            $out .= '\\n';
        } elseif ($cp === 0x0c) {
            $out .= '\\f';
        } elseif ($cp === 0x0d) {
            $out .= '\\r';
        } elseif ($cp < 0x20) {
            $out .= sprintf('\\u%04x', $cp);
        } else {
            $out .= $c;
        }
    }
    $out .= '"';
    return $out;
}

$pass = 0;
$fail = 0;
$fails = [];

function check(string $name, bool $ok, ?string $detail = null): array {
    if ($ok) {
        echo "  PASS  $name\n";
        return [1, 0];
    }
    $line = "  FAIL  $name";
    if ($detail) $line .= " — $detail";
    echo "$line\n";
    return [0, 1];
}

echo "\n=== algovoi-substrate-pqc — PHP verifier ===\n";
echo 'Runtime: php ' . PHP_VERSION . "\n\n";

$fixturePath = $argv[1] ?? null;
if (!$fixturePath) {
    foreach (DEFAULT_FIXTURES as $p) {
        if (file_exists($p)) { $fixturePath = $p; break; }
    }
}
if (!$fixturePath || !file_exists($fixturePath)) {
    fwrite(STDERR, "Could not locate AP2 PQ conformance fixture. Tried:\n");
    foreach (DEFAULT_FIXTURES as $p) fwrite(STDERR, "  $p\n");
    exit(2);
}
echo "Fixture: $fixturePath\n\n";

$artefact = json_decode(file_get_contents($fixturePath), true, 512, JSON_THROW_ON_ERROR);
$payload  = $artefact['mandate_body'];

// --- 1. Canonical-bytes anchor ---
echo "1. JCS canonical bytes anchor:\n";
$canonical    = jcs($payload);
$recomputed   = 'sha256:' . hash('sha256', $canonical);
[$got, $gone] = check(
    'canonical SHA matches published anchor',
    $recomputed === EXPECTED_ANCHOR,
    "expected " . EXPECTED_ANCHOR . ", got $recomputed"
);
$pass += $got; $fail += $gone;
if ($gone) $fails[] = 'canonical sha';

[$got, $gone] = check(
    "canonical SHA matches fixture's expected_canonical_sha256",
    $recomputed === $artefact['expected_canonical_sha256']
);
$pass += $got; $fail += $gone;

// --- 2. ES256 ---
echo "\n2. ES256 (P-256 + SHA-256):\n";
$es = $artefact['signatures']['ES256'] ?? null;
if ($es) {
    $pubDer  = base64_decode($es['publicKeyDer']);
    $sigDer  = base64_decode($es['signature_der']);
    $pemHead = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($pubDer), 64, "\n")
             . "-----END PUBLIC KEY-----\n";
    $pubkey  = openssl_pkey_get_public($pemHead);
    if ($pubkey === false) {
        [$got, $gone] = check('ES256 verifies', false, 'openssl_pkey_get_public failed');
    } else {
        $ok           = openssl_verify($canonical, $sigDer, $pubkey, OPENSSL_ALGO_SHA256);
        [$got, $gone] = check('ES256 verifies against AlgoVoi-side fixture', $ok === 1,
                              $ok === 0 ? 'signature did not verify' : 'openssl error');
    }
    $pass += $got; $fail += $gone;
    if ($gone) $fails[] = 'ES256';
} else {
    echo "  SKIP  ES256 not present in fixture\n";
}

// --- 3. Ed25519 (via libsodium) ---
echo "\n3. Ed25519:\n";
$ed = $artefact['signatures']['Ed25519'] ?? null;
if ($ed) {
    if (!extension_loaded('sodium')) {
        [$got, $gone] = check('Ed25519 verifies', false, 'sodium extension not loaded');
    } else {
        $pubRaw = base64_decode($ed['publicKey_b64']);
        $sigRaw = base64_decode($ed['signature_b64']);
        try {
            $ok           = sodium_crypto_sign_verify_detached($sigRaw, $canonical, $pubRaw);
            [$got, $gone] = check('Ed25519 verifies against AlgoVoi-side fixture', $ok === true);
        } catch (Throwable $e) {
            [$got, $gone] = check('Ed25519 verifies', false, $e::class . ': ' . $e->getMessage());
        }
    }
    $pass += $got; $fail += $gone;
    if ($gone) $fails[] = 'Ed25519';
} else {
    echo "  SKIP  Ed25519 not present in fixture\n";
}

// --- 4. PQC schemes documented out-of-scope ---
echo "\n4. PQC schemes:\n";
foreach (['Falcon-1024', 'ML-DSA-65'] as $alg) {
    if (isset($artefact['signatures'][$alg])) {
        echo "  SKIP  $alg signature is present in fixture but PQC verification is "
           . "out of scope for PHP (no audit-grade library). See verifiers/README.md.\n";
    }
}

echo "\n=== Summary ===\n";
echo 'Runtime: php ' . PHP_VERSION . "\n";
echo "Passed:  $pass\n";
echo "Failed:  $fail\n";
exit($fail === 0 ? 0 : 1);
