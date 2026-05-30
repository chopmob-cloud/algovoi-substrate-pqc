//go:build ignore

// AlgoVoi substrate-pqc — Go producer.
//
// Generates a fresh AP2 PQC v0 artefact signed with ES256 + Ed25519 +
// ML-DSA-65 over the cross-product canonical payload. Falcon-1024 is omitted
// from the Go producer because no clean pure-Go library without CGo exists.
//
// Usage:
//
//	go run verifiers/go/produce.go [output_path]
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const expectedSHA = "sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0"

// PAYLOAD is the stable AP2 PaymentMandate cross-product exemplar.
// The JCS canonical bytes must hash to expectedSHA.
var mandateBody = map[string]interface{}{
	"amount": map[string]interface{}{
		"currency":    "USD",
		"minor_units": float64(4995),
	},
	"constraints": []interface{}{
		map[string]interface{}{
			"type":  "merchant_id_allowlist",
			"value": []interface{}{"did:web:merchant.example.com"},
		},
		map[string]interface{}{
			"type":  "expiry_unix_ms",
			"value": float64(1782259200000),
		},
	},
	"issued_at":    "2026-05-21T00:00:00Z",
	"issued_at_ms": float64(1779667200000),
	"issuer":       "did:web:wallet.example.org",
	"merchant":     "did:web:merchant.example.com",
	"nonce":        "0x7b5ce8a4f1b9a4d2",
	"schema":       "google-agentic-commerce/AP2 PaymentMandate",
	"subject":      "did:web:agent.example.org#agent-7",
	"vct":          "mandate.payment.1",
	"version":      "0.1",
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func jcsBytes(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

func main() {
	// Compute JCS canonical bytes.
	canonical, err := jcsBytes(mandateBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JCS error: %v\n", err)
		os.Exit(1)
	}

	// Verify byte-anchor SHA-256.
	digest := sha256.Sum256(canonical)
	gotSHA := "sha256:" + hex.EncodeToString(digest[:])
	if gotSHA != expectedSHA {
		fmt.Fprintf(os.Stderr, "FATAL: JCS canonical SHA mismatch\n  got:  %s\n  want: %s\n", gotSHA, expectedSHA)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "canonical_sha_ok: %s (len=%d)\n", gotSHA, len(canonical))

	sigs := map[string]interface{}{}

	// --- ES256 (P-256 + SHA-256) ---
	esKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ES256 keygen: %v\n", err)
		os.Exit(1)
	}
	// Sign canonical bytes: crypto/ecdsa hashes with SHA-256 internally when
	// using ecdsa.SignASN1 with a SHA-256 hash.
	esSigDer, err := ecdsa.SignASN1(rand.Reader, esKey, digest[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ES256 sign: %v\n", err)
		os.Exit(1)
	}
	esPubDer, err := x509.MarshalPKIXPublicKey(&esKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ES256 pub DER: %v\n", err)
		os.Exit(1)
	}
	sigs["ES256"] = map[string]interface{}{
		"algorithm":    "ES256",
		"curve":        "P-256",
		"hash":         "SHA-256",
		"publicKeyDer": b64(esPubDer),
		"signature_der": b64(esSigDer),
	}

	// --- Ed25519 ---
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ed25519 keygen: %v\n", err)
		os.Exit(1)
	}
	// Ed25519 signs raw bytes directly (no pre-hash).
	edSig := ed25519.Sign(edPriv, canonical)
	sigs["Ed25519"] = map[string]interface{}{
		"algorithm":     "Ed25519",
		"publicKey_b64": b64(edPub),
		"signature_b64": b64(edSig),
	}

	// --- ML-DSA-65 (FIPS 204, circl) ---
	mlPub, mlPriv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ML-DSA-65 keygen: %v\n", err)
		os.Exit(1)
	}
	// circl mldsa65.Sign signs raw message bytes directly (deterministic,
	// context empty). Pass canonical bytes as the message.
	mlSig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(mlPriv, canonical, nil, false, mlSig)
	mlPubBytes := mlPub.Bytes()
	sigs["ML-DSA-65"] = map[string]interface{}{
		"algorithm":              "ML-DSA-65",
		"fips":                   "FIPS 204",
		"nist_level":             float64(3),
		"publicKey_b64":          b64(mlPubBytes),
		"signature_b64":          b64(mlSig),
		"signature_length_bytes": float64(len(mlSig)),
		"publicKey_length_bytes": float64(len(mlPubBytes)),
	}

	// --- Build artefact ---
	artefact := map[string]interface{}{
		"schema_version": "1.0",
		"artefact_id":    "cross-product-v0-go-side",
		"canonicalizer":  "cyberphone/json-canonicalization (Go ref impl)",
		"published_at":   time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"anchored_to": map[string]interface{}{
			"thread": "https://github.com/chopmob-cloud/algovoi-substrate-pqc",
			"schema": "AP2 PaymentMandate v0.1 (cross-product exemplar)",
			"rfc":    "RFC 8785 (JCS)",
		},
		"context": map[string]interface{}{
			"producer":         "go/circl",
			"producer_runtime": fmt.Sprintf("go/%s", runtime.Version()),
			"purpose":          "Go-side producer for the cross-product matrix; signs the stable canonical payload under ES256 + Ed25519 + ML-DSA-65. Falcon-1024 omitted (no clean pure-Go lib without CGo).",
		},
		"mandate_body":                mandateBody,
		"expected_jcs_bytes_b64":      b64(canonical),
		"expected_jcs_bytes_hex":      hex.EncodeToString(canonical),
		"expected_jcs_bytes_length":   float64(len(canonical)),
		"expected_canonical_sha256":   gotSHA,
		"signatures":                  sigs,
	}

	out, err := json.MarshalIndent(artefact, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON marshal: %v\n", err)
		os.Exit(1)
	}

	// Determine output path.
	// When run via `go run`, os.Args[0] is a temp binary in a temp dir.
	// Use the working directory (expected: repo root) as the base.
	var outPath string
	if len(os.Args) > 1 {
		outPath = os.Args[1]
	} else {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
			os.Exit(1)
		}
		outPath = filepath.Join(wd, "_attestations", "2026-05-30-cross-product", "producers", "go.json")
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, append(out, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (signatures: Ed25519, ES256, ML-DSA-65)\n", outPath)
}
