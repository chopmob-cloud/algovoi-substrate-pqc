<?php
declare(strict_types=1);

/**
 * AlgoVoi substrate-pqc — PHP producer (classical schemes only).
 *
 * Generates a fresh AP2 PQC v0 artefact signed with ES256 + Ed25519 over the
 * cross-product canonical payload. Output goes to
 * `_attestations/2026-05-30-cross-product/producers/php.json`.
 *
 * Falcon-1024 + ML-DSA-65 are out of scope for PHP (no audit-grade library).
 *
 * Usage:
 *   php produce.php                          (direct, requires openssl + sodium loaded)
 *   bash run-produce.sh                      (wrapper that loads extensions)
 */

// Same minimal JCS as verify.php.
function jcs($value): string {
    if (is_array($value)) {
        if (array_keys($value) === range(0, count($value) - 1)) {
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
    if (is_string($value))  return jsonEscape($value);
    if (is_int($value))     return (string)$value;
    if (is_bool($value))    return $value ? 'true' : 'false';
    if ($value === null)    return 'null';
    throw new RuntimeException('JCS: unsupported value type ' . gettype($value));
}

function jsonEscape(string $s): string {
    $out = '"';
    $len = strlen($s);
    for ($i = 0; $i < $len; $i++) {
        $c = $s[$i];
        $cp = ord($c);
        if      ($cp === 0x22)         $out .= '\\"';
        elseif  ($cp === 0x5c)         $out .= '\\\\';
        elseif  ($cp === 0x08)         $out .= '\\b';
        elseif  ($cp === 0x09)         $out .= '\\t';
        elseif  ($cp === 0x0a)         $out .= '\\n';
        elseif  ($cp === 0x0c)         $out .= '\\f';
        elseif  ($cp === 0x0d)         $out .= '\\r';
        elseif  ($cp < 0x20)           $out .= sprintf('\\u%04x', $cp);
        else                           $out .= $c;
    }
    return $out . '"';
}

$PAYLOAD = [
    'amount'      => ['currency' => 'USD', 'minor_units' => 4995],
    'constraints' => [
        ['type' => 'merchant_id_allowlist', 'value' => ['did:web:merchant.example.com']],
        ['type' => 'expiry_unix_ms', 'value' => 1782259200000],
    ],
    'issued_at'    => '2026-05-21T00:00:00Z',
    'issued_at_ms' => 1779667200000,
    'issuer'       => 'did:web:wallet.example.org',
    'merchant'     => 'did:web:merchant.example.com',
    'nonce'        => '0x7b5ce8a4f1b9a4d2',
    'schema'       => 'google-agentic-commerce/AP2 PaymentMandate',
    'subject'      => 'did:web:agent.example.org#agent-7',
    'vct'          => 'mandate.payment.1',
    'version'      => '0.1',
];

$canonical = jcs($PAYLOAD);

// --- ES256 (P-256 + SHA-256) ---
//
// Windows-installed PHP often ships openssl.cnf under php-dir/extras/ssl/ but
// doesn't set OPENSSL_CONF, so openssl_pkey_new() can fail with a misleading
// "No such process" system-library error. We auto-discover the bundled config.
$es_options = [
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name'       => 'prime256v1',
];
$bundled_cnf = dirname(PHP_BINARY) . DIRECTORY_SEPARATOR
             . 'extras' . DIRECTORY_SEPARATOR
             . 'ssl' . DIRECTORY_SEPARATOR
             . 'openssl.cnf';
if (is_file($bundled_cnf)) {
    $es_options['config'] = $bundled_cnf;
} elseif (getenv('OPENSSL_CONF') && is_file(getenv('OPENSSL_CONF'))) {
    $es_options['config'] = getenv('OPENSSL_CONF');
}
$res = openssl_pkey_new($es_options);
if (!$res) {
    fwrite(STDERR, "openssl_pkey_new failed: " . openssl_error_string() . "\n");
    if (!isset($es_options['config'])) {
        fwrite(STDERR, "Hint: set OPENSSL_CONF to your openssl.cnf path or "
            . "place openssl.cnf at " . dirname(PHP_BINARY) . "/extras/ssl/\n");
    }
    exit(2);
}
$es_details = openssl_pkey_get_details($res);
$es_pub_pem = $es_details['key']; // PEM
// Extract DER from PEM.
$es_pub_der_b64 = preg_replace('/-----[^-]+-----|\s+/', '', $es_pub_pem);
$es_pub_der     = base64_decode($es_pub_der_b64);
openssl_sign($canonical, $es_sig_der, $res, OPENSSL_ALGO_SHA256);
unset($es_options);

// --- Ed25519 (via libsodium) ---
$ed_kp  = sodium_crypto_sign_keypair();
$ed_pub = sodium_crypto_sign_publickey($ed_kp);
$ed_sk  = sodium_crypto_sign_secretkey($ed_kp);
$ed_sig = sodium_crypto_sign_detached($canonical, $ed_sk);

$artefact = [
    'schema_version' => '1.0',
    'artefact_id'    => 'cross-product-v0-php-side',
    'canonicalizer'  => 'php-minimal-jcs/8.x',
    'published_at'   => gmdate('Y-m-d\\TH:i:s\\Z'),
    'anchored_to'    => [
        'thread' => 'https://github.com/chopmob-cloud/algovoi-substrate-pqc',
        'schema' => 'AP2 PaymentMandate v0.1 (cross-product exemplar)',
        'rfc'    => 'RFC 8785 (JCS)',
    ],
    'context' => [
        'producer'         => 'php/openssl+sodium',
        'producer_runtime' => 'php/' . PHP_VERSION,
        'purpose'          => 'PHP-side producer for the cross-product matrix; signs ' .
                              'the stable canonical payload under ES256 + Ed25519 only. ' .
                              'PQC schemes are out of scope for PHP (no audit-grade library).',
    ],
    'mandate_body'             => $PAYLOAD,
    'expected_jcs_bytes_b64'   => base64_encode($canonical),
    'expected_jcs_bytes_hex'   => bin2hex($canonical),
    'expected_jcs_bytes_length' => strlen($canonical),
    'expected_canonical_sha256' => 'sha256:' . hash('sha256', $canonical),
    'signatures' => [
        'ES256' => [
            'algorithm'    => 'ES256',
            'curve'        => 'P-256',
            'hash'         => 'SHA-256',
            'publicKeyDer' => base64_encode($es_pub_der),
            'signature_der' => base64_encode($es_sig_der),
        ],
        'Ed25519' => [
            'algorithm'     => 'Ed25519',
            'publicKey_b64' => base64_encode($ed_pub),
            'signature_b64' => base64_encode($ed_sig),
        ],
    ],
];

$default_out = realpath(__DIR__ . '/../..') .
    '/_attestations/2026-05-30-cross-product/producers/php.json';
$out_path = $argv[1] ?? $default_out;
@mkdir(dirname($out_path), 0755, true);
file_put_contents(
    $out_path,
    json_encode($artefact, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
);
echo "wrote $out_path (signatures: ES256, Ed25519)\n";
