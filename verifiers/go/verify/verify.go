//go:build ignore

// AlgoVoi substrate-pqc — Go verifier.
//
// Reads an AP2 PQC v0 artefact JSON, recomputes the JCS canonical bytes,
// confirms the canonical SHA-256 byte-anchor, and verifies each declared
// signature scheme.
//
// Supported schemes: ES256, Ed25519, ML-DSA-65
// (Falcon-1024 not supported — no pure-Go lib without CGo.)
//
// Prints one PASS/FAIL line per scheme; exits 0 iff all pass.
//
// Usage:
//
//	go run verifiers/go/verify/verify.go <artefact.json>
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

func b64d(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func jcsBytes(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

// ecdsaDSASig holds r and s for DER decoding.
type ecdsaDSASig struct {
	R, S *big.Int
}

func verifyES256(canonical []byte, sig map[string]interface{}) error {
	// Load public key — accept DER (publicKeyDer) or raw 65-byte uncompressed (publicKey_b64).
	var pub *ecdsa.PublicKey
	if derB64, ok := sig["publicKeyDer"].(string); ok {
		derBytes, err := b64d(derB64)
		if err != nil {
			return fmt.Errorf("publicKeyDer base64: %w", err)
		}
		k, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
			return fmt.Errorf("parse PKIX public key: %w", err)
		}
		var ok2 bool
		pub, ok2 = k.(*ecdsa.PublicKey)
		if !ok2 {
			return fmt.Errorf("not an ECDSA public key")
		}
	} else if rawB64, ok := sig["publicKey_b64"].(string); ok {
		rawBytes, err := b64d(rawB64)
		if err != nil {
			return fmt.Errorf("publicKey_b64 base64: %w", err)
		}
		if len(rawBytes) != 65 || rawBytes[0] != 0x04 {
			return fmt.Errorf("expected 65-byte uncompressed P-256 point")
		}
		// Wrap as SPKI DER for x509 parsing.
		spki := buildP256SPKI(rawBytes)
		k, err := x509.ParsePKIXPublicKey(spki)
		if err != nil {
			return fmt.Errorf("parse P-256 raw point: %w", err)
		}
		var ok2 bool
		pub, ok2 = k.(*ecdsa.PublicKey)
		if !ok2 {
			return fmt.Errorf("not an ECDSA public key")
		}
	} else {
		return fmt.Errorf("no publicKeyDer or publicKey_b64 field")
	}

	// Load signature — accept DER (signature_der) or compact 64-byte r||s.
	var sigDer []byte
	if derB64, ok := sig["signature_der"].(string); ok {
		var err error
		sigDer, err = b64d(derB64)
		if err != nil {
			return fmt.Errorf("signature_der base64: %w", err)
		}
	} else {
		for _, key := range []string{"signature_b64", "signature_compact_b64"} {
			if compB64, ok := sig[key].(string); ok {
				compact, err := b64d(compB64)
				if err != nil {
					return fmt.Errorf("%s base64: %w", key, err)
				}
				if len(compact) == 64 {
					r := new(big.Int).SetBytes(compact[:32])
					s := new(big.Int).SetBytes(compact[32:])
					sigDer, err = asn1.Marshal(ecdsaDSASig{R: r, S: s})
					if err != nil {
						return fmt.Errorf("compact->DER: %w", err)
					}
				} else {
					sigDer = compact
				}
				break
			}
		}
	}
	if sigDer == nil {
		return fmt.Errorf("no signature_der / signature_b64 / signature_compact_b64 field")
	}

	// ES256 hashes internally: hash canonical with SHA-256.
	digest := sha256.Sum256(canonical)
	var dsaSig ecdsaDSASig
	if _, err := asn1.Unmarshal(sigDer, &dsaSig); err != nil {
		return fmt.Errorf("unmarshal DER signature: %w", err)
	}
	if !ecdsa.Verify(pub, digest[:], dsaSig.R, dsaSig.S) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

func verifyEd25519(canonical []byte, sig map[string]interface{}) error {
	pubB64, ok := sig["publicKey_b64"].(string)
	if !ok {
		return fmt.Errorf("missing publicKey_b64")
	}
	sigB64, ok := sig["signature_b64"].(string)
	if !ok {
		return fmt.Errorf("missing signature_b64")
	}
	pubBytes, err := b64d(pubB64)
	if err != nil {
		return fmt.Errorf("publicKey_b64 base64: %w", err)
	}
	sigBytes, err := b64d(sigB64)
	if err != nil {
		return fmt.Errorf("signature_b64 base64: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("expected %d-byte Ed25519 public key, got %d", ed25519.PublicKeySize, len(pubBytes))
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sigBytes) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

func verifyMLDSA65(canonical []byte, sig map[string]interface{}) error {
	pubB64, ok := sig["publicKey_b64"].(string)
	if !ok {
		return fmt.Errorf("missing publicKey_b64")
	}
	sigB64, ok := sig["signature_b64"].(string)
	if !ok {
		return fmt.Errorf("missing signature_b64")
	}
	pubBytes, err := b64d(pubB64)
	if err != nil {
		return fmt.Errorf("publicKey_b64 base64: %w", err)
	}
	sigBytes, err := b64d(sigB64)
	if err != nil {
		return fmt.Errorf("signature_b64 base64: %w", err)
	}
	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(pubBytes); err != nil {
		return fmt.Errorf("unmarshal ML-DSA-65 public key: %w", err)
	}
	if !mldsa65.Verify(&pub, canonical, nil, sigBytes) {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

// buildP256SPKI wraps an uncompressed P-256 point (65 bytes) into a
// SubjectPublicKeyInfo DER structure compatible with x509.ParsePKIXPublicKey.
func buildP256SPKI(raw []byte) []byte {
	// Algorithm identifier OID sequence for EC P-256:
	//   SEQUENCE { OID ecPublicKey, OID prime256v1 }
	// = 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07
	algID := []byte{0x30, 0x13,
		0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	// BIT STRING: unused bits byte (0x00) + raw point
	bs := append([]byte{0x00}, raw...)
	bitStr := make([]byte, 0, 2+len(bs))
	bitStr = append(bitStr, 0x03)
	bitStr = append(bitStr, byte(len(bs)))
	bitStr = append(bitStr, bs...)
	// SEQUENCE { algID, bitStr }
	inner := append(algID, bitStr...)
	spki := make([]byte, 0, 2+len(inner))
	spki = append(spki, 0x30)
	spki = append(spki, byte(len(inner)))
	spki = append(spki, inner...)
	return spki
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verify <artefact.json>")
		os.Exit(2)
	}
	artefactPath := os.Args[1]
	data, err := os.ReadFile(artefactPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read artefact: %v\n", err)
		os.Exit(1)
	}

	var artefact map[string]interface{}
	if err := json.Unmarshal(data, &artefact); err != nil {
		fmt.Fprintf(os.Stderr, "parse JSON: %v\n", err)
		os.Exit(1)
	}

	// Recompute JCS canonical bytes from mandate_body.
	mandateBody, ok := artefact["mandate_body"]
	if !ok {
		mandateBody = artefact["payload"]
	}
	if mandateBody == nil {
		fmt.Fprintln(os.Stderr, "artefact missing mandate_body / payload")
		os.Exit(1)
	}

	canonical, err := jcsBytes(mandateBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "JCS error: %v\n", err)
		os.Exit(1)
	}

	digest := sha256.Sum256(canonical)
	gotSHA := "sha256:" + hex.EncodeToString(digest[:])
	expectedSHA, _ := artefact["expected_canonical_sha256"].(string)
	shaOK := gotSHA == expectedSHA
	fmt.Printf("canonical_sha_ok=%v\n", shaOK)
	if !shaOK {
		fmt.Fprintf(os.Stderr, "canonical SHA mismatch: got %s want %s\n", gotSHA, expectedSHA)
	}

	sigsRaw, _ := artefact["signatures"].(map[string]interface{})
	allPass := shaOK

	for alg, sigRaw := range sigsRaw {
		sig, ok := sigRaw.(map[string]interface{})
		if !ok {
			fmt.Printf("FAIL: %s: not a JSON object\n", alg)
			allPass = false
			continue
		}
		var verifyErr error
		switch alg {
		case "ES256":
			verifyErr = verifyES256(canonical, sig)
		case "Ed25519":
			verifyErr = verifyEd25519(canonical, sig)
		case "ML-DSA-65":
			verifyErr = verifyMLDSA65(canonical, sig)
		case "Falcon-1024":
			fmt.Printf("SKIP: Falcon-1024: no pure-Go verifier (no CGo)\n")
			continue
		default:
			fmt.Printf("SKIP: %s: unknown scheme\n", alg)
			continue
		}
		if verifyErr != nil {
			fmt.Printf("FAIL: %s: %v\n", alg, verifyErr)
			allPass = false
		} else {
			fmt.Printf("PASS: %s\n", alg)
		}
	}

	if !allPass {
		os.Exit(1)
	}
}
