#!/usr/bin/env perl
# AlgoVoi substrate-pqc — Perl verifier (classical schemes only).
#
# Loads the AP2 PQ conformance fixture, recomputes the JCS canonical bytes,
# confirms the canonical SHA-256 byte-anchor, and verifies ES256 + Ed25519
# signatures against the published public keys.
#
# Falcon-1024 and ML-DSA-65 are out of scope: no audit-grade PQC library
# exists for Perl. The substrate-author PQC convergence proof is established
# by the Python and TypeScript implementations.
#
# Crypto verification requires CryptX (provides Crypt::PK::ECC + Crypt::PK::Ed25519).
# If CryptX is not installed (e.g. on a minimal msys2 perl), ES256 and Ed25519
# are SKIPped with an install hint, but the canonical-bytes proof is still
# performed using core Perl modules (Digest::SHA + MIME::Base64 + JSON::PP).
#
# Install on full Perl distributions (Strawberry, ActiveState, system perl):
#   cpanm CryptX
#
# Usage:
#   perl verify.pl [path/to/ap2-pqc-v0-algovoi-side.json]

use strict;
use warnings;
use Digest::SHA       qw(sha256_hex);
use MIME::Base64      qw(decode_base64);
use JSON::PP          ();

use constant EXPECTED_ANCHOR =>
    'sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0';

my @DEFAULT_FIXTURES = (
    'C:/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
    '/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
);

# Detect CryptX presence (load lazily; absence is graceful degradation).
my $HAVE_CRYPTX = eval { require Crypt::PK::ECC; require Crypt::PK::Ed25519; 1 };

# ---------- Minimal JCS (RFC 8785) canonicalisation ----------
# Handles ASCII string keys with lexicographic sort, arrays in order, integers
# as decimals, booleans / null as JSON keywords, and minimum-escape strings.
sub jcs {
    my ($v) = @_;
    if (ref($v) eq 'HASH') {
        my @parts;
        for my $k (sort keys %$v) {
            push @parts, json_escape($k) . ':' . jcs($v->{$k});
        }
        return '{' . join(',', @parts) . '}';
    }
    if (ref($v) eq 'ARRAY') {
        return '[' . join(',', map { jcs($_) } @$v) . ']';
    }
    if (ref($v) eq 'JSON::PP::Boolean') {
        return $$v ? 'true' : 'false';
    }
    return 'null' unless defined $v;
    # Integer-or-string discrimination: JSON::PP returns integers as plain
    # numbers and strings as strings; Perl's looks-like-number heuristic is
    # adequate here because our AP2 PaymentMandate payload has integer-only
    # numerics.
    if (Scalar::Util::looks_like_number($v) && $v =~ /\A-?[0-9]+\z/) {
        return $v + 0;
    }
    return json_escape($v);
}

sub json_escape {
    my ($s) = @_;
    my $out = '"';
    for my $cp (unpack('U*', $s)) {
        if ($cp == 0x22)    { $out .= '\\"'; }
        elsif ($cp == 0x5c) { $out .= '\\\\'; }
        elsif ($cp == 0x08) { $out .= '\\b'; }
        elsif ($cp == 0x09) { $out .= '\\t'; }
        elsif ($cp == 0x0a) { $out .= '\\n'; }
        elsif ($cp == 0x0c) { $out .= '\\f'; }
        elsif ($cp == 0x0d) { $out .= '\\r'; }
        elsif ($cp < 0x20)  { $out .= sprintf('\\u%04x', $cp); }
        elsif ($cp < 0x80)  { $out .= chr($cp); }
        else                { $out .= pack('U', $cp); }
    }
    $out .= '"';
    return $out;
}

require Scalar::Util;

my $pass = 0;
my $fail = 0;
sub check {
    my ($name, $ok, $detail) = @_;
    if ($ok) {
        print "  PASS  $name\n";
        $pass++;
    }
    else {
        my $line = "  FAIL  $name";
        $line .= " - $detail" if $detail;
        print "$line\n";
        $fail++;
    }
}

print "\n=== algovoi-substrate-pqc - Perl verifier ===\n";
print "Runtime: perl $]\n";
print "CryptX:  " . ($HAVE_CRYPTX ? "available\n" : "NOT installed - ES256+Ed25519 will be SKIPped (cpanm CryptX)\n");
print "\n";

my $fixture_path = $ARGV[0];
unless ($fixture_path && -f $fixture_path) {
    for my $p (@DEFAULT_FIXTURES) {
        if (-f $p) { $fixture_path = $p; last; }
    }
}
unless ($fixture_path && -f $fixture_path) {
    print STDERR "Could not locate AP2 PQ conformance fixture. Tried:\n  "
        . join("\n  ", @DEFAULT_FIXTURES) . "\n";
    exit 2;
}
print "Fixture: $fixture_path\n\n";

open(my $fh, '<:raw', $fixture_path) or die "open $fixture_path: $!";
my $raw = do { local $/; <$fh> };
close $fh;
my $artefact = JSON::PP->new->utf8->allow_nonref->decode($raw);
my $payload  = $artefact->{mandate_body};

# --- 1. Canonical-bytes anchor ---
print "1. JCS canonical bytes anchor:\n";
my $canonical      = jcs($payload);
my $recomputed_sha = 'sha256:' . sha256_hex($canonical);
check(
    'canonical SHA matches published anchor',
    $recomputed_sha eq EXPECTED_ANCHOR,
    "expected " . EXPECTED_ANCHOR . ", got $recomputed_sha"
);
check(
    "canonical SHA matches fixture's expected_canonical_sha256",
    $recomputed_sha eq $artefact->{expected_canonical_sha256}
);

# --- 2. ES256 ---
print "\n2. ES256 (P-256 + SHA-256):\n";
my $es = $artefact->{signatures}->{ES256};
if (!$es) {
    print "  SKIP  ES256 not present in fixture\n";
}
elsif (!$HAVE_CRYPTX) {
    print "  SKIP  CryptX not installed; install with `cpanm CryptX` to enable ES256 verification\n";
}
else {
    my $pub_der = decode_base64($es->{publicKeyDer});
    my $sig_der = decode_base64($es->{signature_der});
    my $pk      = Crypt::PK::ECC->new(\$pub_der);
    my $ok      = $pk->verify_message($sig_der, $canonical, 'SHA256');
    check('ES256 verifies against AlgoVoi-side fixture', $ok ? 1 : 0);
}

# --- 3. Ed25519 ---
print "\n3. Ed25519:\n";
my $ed = $artefact->{signatures}->{Ed25519};
if (!$ed) {
    print "  SKIP  Ed25519 not present in fixture\n";
}
elsif (!$HAVE_CRYPTX) {
    print "  SKIP  CryptX not installed; install with `cpanm CryptX` to enable Ed25519 verification\n";
}
else {
    my $pub_raw = decode_base64($ed->{publicKey_b64});
    my $sig_raw = decode_base64($ed->{signature_b64});
    # CryptX Crypt::PK::Ed25519 accepts the 32-byte raw public key directly.
    my $pk = Crypt::PK::Ed25519->new();
    $pk->import_key_raw($pub_raw, 'public');
    my $ok = $pk->verify_message($sig_raw, $canonical);
    check('Ed25519 verifies against AlgoVoi-side fixture', $ok ? 1 : 0);
}

# --- 4. PQC schemes documented out-of-scope ---
print "\n4. PQC schemes:\n";
for my $alg ('Falcon-1024', 'ML-DSA-65') {
    if ($artefact->{signatures}->{$alg}) {
        print "  SKIP  $alg signature is present in fixture but PQC verification "
            . "is out of scope for Perl (no audit-grade library). See verifiers/README.md.\n";
    }
}

print "\n=== Summary ===\n";
print "Runtime: perl $]\n";
print "Passed:  $pass\n";
print "Failed:  $fail\n";
exit($fail ? 1 : 0);
