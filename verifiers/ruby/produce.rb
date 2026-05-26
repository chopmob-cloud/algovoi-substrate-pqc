#!/usr/bin/env ruby
# frozen_string_literal: true

# AlgoVoi substrate-pqc — Ruby producer (classical schemes only).
#
# Generates a fresh AP2 PQC v0 artefact signed with ES256 + Ed25519 over the
# cross-product canonical payload. Output goes to
# `_attestations/2026-05-26-cross-product/producers/ruby.json`.
#
# Falcon-1024 and ML-DSA-65 are out of scope: no audit-grade PQC library
# exists for Ruby. The substrate-author PQC convergence proof is established
# by the Python and TypeScript producers.

require 'base64'
require 'digest'
require 'fileutils'
require 'json'
require 'openssl'

# Same minimal JCS as verify.rb (recursive sort + RFC 8785-compatible serialize).
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
  out = +'"'
  str.each_char do |c|
    cp = c.ord
    case cp
    when 0x22 then out << '\\"'
    when 0x5c then out << '\\\\'
    when 0x08 then out << '\\b'
    when 0x09 then out << '\\t'
    when 0x0a then out << '\\n'
    when 0x0c then out << '\\f'
    when 0x0d then out << '\\r'
    when 0..0x1f then out << format('\\u%04x', cp)
    else out << c
    end
  end
  out << '"'
  out
end

def b64(bytes)
  Base64.strict_encode64(bytes)
end

PAYLOAD = {
  'amount' => { 'currency' => 'USD', 'minor_units' => 4995 },
  'constraints' => [
    { 'type' => 'merchant_id_allowlist', 'value' => ['did:web:merchant.example.com'] },
    { 'type' => 'expiry_unix_ms', 'value' => 1_782_259_200_000 }
  ],
  'issued_at' => '2026-05-21T00:00:00Z',
  'issued_at_ms' => 1_779_667_200_000,
  'issuer' => 'did:web:wallet.example.org',
  'merchant' => 'did:web:merchant.example.com',
  'nonce' => '0x7b5ce8a4f1b9a4d2',
  'schema' => 'google-agentic-commerce/AP2 PaymentMandate',
  'subject' => 'did:web:agent.example.org#agent-7',
  'vct' => 'mandate.payment.1',
  'version' => '0.1'
}.freeze

canonical = jcs(PAYLOAD).b

# --- ES256 (P-256 + SHA-256) ---
es_key  = OpenSSL::PKey::EC.generate('prime256v1')
es_pub  = es_key.public_to_der
es_sig  = es_key.sign(OpenSSL::Digest.new('SHA256'), canonical)

# --- Ed25519 ---
# OpenSSL 3.0+ supports Ed25519 keypair generation.
ed_key  = OpenSSL::PKey.generate_key('ED25519')
ed_pub  = ed_key.raw_public_key
ed_sig  = ed_key.sign(nil, canonical)

artefact = {
  'schema_version' => '1.0',
  'artefact_id' => 'cross-product-v0-ruby-side',
  'canonicalizer' => 'ruby-minimal-jcs/3.x',
  'published_at' => Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
  'anchored_to' => {
    'thread' => 'https://github.com/chopmob-cloud/algovoi-substrate-pqc',
    'schema' => 'AP2 PaymentMandate v0.1 (cross-product exemplar)',
    'rfc' => 'RFC 8785 (JCS)'
  },
  'context' => {
    'producer' => 'ruby/openssl-stdlib',
    'producer_runtime' => "ruby/#{RUBY_VERSION}",
    'purpose' => 'Ruby-side producer for the cross-product matrix; signs the ' \
                 'stable canonical payload under ES256 + Ed25519 only. PQC ' \
                 'schemes are out of scope for Ruby (no audit-grade library).'
  },
  'mandate_body' => PAYLOAD,
  'expected_jcs_bytes_b64' => b64(canonical),
  'expected_jcs_bytes_hex' => canonical.unpack1('H*'),
  'expected_jcs_bytes_length' => canonical.bytesize,
  'expected_canonical_sha256' => 'sha256:' + Digest::SHA256.hexdigest(canonical),
  'signatures' => {
    'ES256' => {
      'algorithm' => 'ES256',
      'curve' => 'P-256',
      'hash' => 'SHA-256',
      'publicKeyDer' => b64(es_pub),
      'signature_der' => b64(es_sig)
    },
    'Ed25519' => {
      'algorithm' => 'Ed25519',
      'publicKey_b64' => b64(ed_pub),
      'signature_b64' => b64(ed_sig)
    }
  }
}

default_out = File.expand_path(
  '../../_attestations/2026-05-26-cross-product/producers/ruby.json', __dir__
)
out_path = ARGV[0] || default_out
FileUtils.mkdir_p(File.dirname(out_path))
File.write(out_path, JSON.pretty_generate(artefact) + "\n")
puts "wrote #{out_path} (signatures: ES256, Ed25519)"
