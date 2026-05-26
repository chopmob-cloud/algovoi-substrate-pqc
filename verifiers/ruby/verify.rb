#!/usr/bin/env ruby
# frozen_string_literal: true

# AlgoVoi substrate-pqc — Ruby verifier (classical schemes only).
#
# Loads the AP2 PQ conformance fixture, recomputes the JCS canonical bytes,
# confirms the canonical SHA-256 byte-anchor, and verifies ES256 + Ed25519
# signatures against the published public keys.
#
# Falcon-1024 and ML-DSA-65 are out of scope: no audit-grade PQC library
# exists for Ruby. The substrate-author PQC convergence proof is established
# by the Python and TypeScript implementations.
#
# Usage:
#   ruby verify.rb [path/to/ap2-pqc-v0-algovoi-side.json]

require 'base64'
require 'digest'
require 'json'
require 'openssl'

DEFAULT_FIXTURES = [
  'C:/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
  '/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json',
  File.expand_path('../../../ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json', __dir__),
].freeze

EXPECTED_ANCHOR =
  'sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0'

# Minimal JCS (RFC 8785) canonicalisation. Handles:
#   - Objects: keys sorted lexicographically (UTF-16 code-unit order, which
#     matches Ruby's String#<=> for ASCII keys; our AP2 payload uses ASCII
#     keys so this is sufficient).
#   - Arrays: order preserved.
#   - Strings: JSON-escaped per RFC 8259, minimum escapes.
#   - Integers: serialized as decimal (RFC 8785 §3.2.2.3).
#   - Floats: not present in the AP2 PaymentMandate exemplar; not implemented
#     here.
#   - Booleans / null: standard JSON keywords.
def jcs(value)
  case value
  when Hash
    inner = value.keys.sort.map { |k| "#{jcs(k.to_s)}:#{jcs(value[k])}" }.join(',')
    "{#{inner}}"
  when Array
    "[#{value.map { |v| jcs(v) }.join(',')}]"
  when String
    json_escape(value)
  when Integer
    value.to_s
  when TrueClass, FalseClass
    value.to_s
  when NilClass
    'null'
  else
    raise "JCS: unsupported value type #{value.class}"
  end
end

def json_escape(str)
  # Minimum-escape per RFC 8259 §7. Required escapes: " \ control chars.
  out = +'"'
  str.each_char do |c|
    cp = c.ord
    if cp == 0x22 # "
      out << '\\"'
    elsif cp == 0x5c # \
      out << '\\\\'
    elsif cp == 0x08
      out << '\\b'
    elsif cp == 0x09
      out << '\\t'
    elsif cp == 0x0a
      out << '\\n'
    elsif cp == 0x0c
      out << '\\f'
    elsif cp == 0x0d
      out << '\\r'
    elsif cp < 0x20
      out << format('\\u%04x', cp)
    else
      out << c
    end
  end
  out << '"'
  out
end

pass = 0
fail = 0
fails = []

def check(name, ok, detail = nil)
  if ok
    puts "  PASS  #{name}"
    [1, 0]
  else
    line = "  FAIL  #{name}"
    line += " — #{detail}" if detail
    puts line
    [0, 1]
  end
end

puts
puts '=== algovoi-substrate-pqc — Ruby verifier ==='
puts "Runtime: ruby #{RUBY_VERSION}"
puts

fixture_path = ARGV[0]
unless fixture_path
  found = DEFAULT_FIXTURES.find { |p| File.exist?(p) }
  fixture_path = found
end
unless fixture_path && File.exist?(fixture_path)
  warn "Could not locate AP2 PQ conformance fixture. Tried:\n" + DEFAULT_FIXTURES.join("\n")
  exit 2
end
puts "Fixture: #{fixture_path}"
puts

artefact = JSON.parse(File.read(fixture_path, encoding: 'UTF-8'))
payload = artefact.fetch('mandate_body')

# --- 1. Canonical-bytes anchor ---
puts '1. JCS canonical bytes anchor:'
canonical = jcs(payload).b
recomputed_sha = 'sha256:' + Digest::SHA256.hexdigest(canonical)
got, gone = check('canonical SHA matches published anchor',
                  recomputed_sha == EXPECTED_ANCHOR,
                  "expected #{EXPECTED_ANCHOR}, got #{recomputed_sha}")
pass += got; fail += gone
fails << 'canonical sha' if gone == 1

# Also verify against the fixture's embedded expected_canonical_sha256.
got, gone = check("canonical SHA matches fixture's expected_canonical_sha256",
                  recomputed_sha == artefact['expected_canonical_sha256'])
pass += got; fail += gone

# --- 2. ES256 ---
puts
puts '2. ES256 (P-256 + SHA-256):'
es = artefact.dig('signatures', 'ES256')
if es
  pub_der = Base64.decode64(es.fetch('publicKeyDer'))
  sig_der = Base64.decode64(es.fetch('signature_der'))
  pubkey = OpenSSL::PKey::EC.new(pub_der)
  digest = OpenSSL::Digest.new('SHA256')
  ok = pubkey.verify(digest, sig_der, canonical)
  got, gone = check('ES256 verifies against AlgoVoi-side fixture', ok)
  pass += got; fail += gone
  fails << 'ES256' if gone == 1
else
  puts '  SKIP  ES256 not present in fixture'
end

# --- 3. Ed25519 ---
puts
puts '3. Ed25519:'
ed = artefact.dig('signatures', 'Ed25519')
if ed
  pub_raw = Base64.decode64(ed.fetch('publicKey_b64'))
  sig_raw = Base64.decode64(ed.fetch('signature_b64'))

  ok = nil
  detail = nil
  begin
    # OpenSSL 3.0+ supports Ed25519 via PKey.
    pubkey = OpenSSL::PKey.new_raw_public_key('ED25519', pub_raw)
    ok = pubkey.verify(nil, sig_raw, canonical)
  rescue StandardError => e
    detail = "OpenSSL: #{e.class}: #{e.message}"
  end
  got, gone = check('Ed25519 verifies against AlgoVoi-side fixture', ok == true, detail)
  pass += got; fail += gone
  fails << 'Ed25519' if gone == 1
else
  puts '  SKIP  Ed25519 not present in fixture'
end

# --- 4. PQC schemes documented out-of-scope ---
puts
puts '4. PQC schemes:'
%w[Falcon-1024 ML-DSA-65].each do |alg|
  present = artefact.dig('signatures', alg)
  if present
    puts "  SKIP  #{alg} signature is present in fixture but PQC verification is " \
         'out of scope for Ruby (no audit-grade library). See verifiers/README.md.'
  end
end

puts
puts '=== Summary ==='
puts "Runtime: ruby #{RUBY_VERSION}"
puts "Passed:  #{pass}"
puts "Failed:  #{fail}"
exit(fail.zero? ? 0 : 1)
