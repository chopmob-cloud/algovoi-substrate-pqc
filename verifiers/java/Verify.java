// AlgoVoi substrate-pqc — Java verifier via Bouncy Castle.
//
// Third audit-grade PQC implementation alongside PQClean (via pqcrypto on Python)
// and @noble/post-quantum on TypeScript. Provides independent cross-implementor
// verification for ES256 + Ed25519 + ML-DSA-65 (FIPS 204) + Falcon-1024 (FIPS 206).
//
// Falcon-1024 in Bouncy Castle is "experimental" classified as of BC 1.78+ —
// the cross-impl verification is real and useful, but a hardening + audit
// pass before production use is recommended by the BC maintainers themselves.
// ML-DSA-65 is production-grade.
//
// Compile:
//   javac -cp "lib/*" -d out Verify.java
//
// Run:
//   java -cp "out;lib/*" Verify path/to/artefact.json     (Windows)
//   java -cp "out:lib/*" Verify path/to/artefact.json     (Linux/macOS)

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.json.JSONArray;
import org.json.JSONObject;

public class Verify {

    private static final String EXPECTED_ANCHOR =
        "sha256:cc8315f7696c65b2a07eb278de0e45c3149319526c8d443c7e38a17de04c28e0";

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String name, boolean ok, String detail) {
        if (ok) {
            System.out.println("  PASS  " + name);
            pass++;
        } else {
            System.out.println("  FAIL  " + name + (detail != null ? " — " + detail : ""));
            fail++;
        }
    }

    // ---------- Minimal RFC 8785 JCS over org.json values ----------

    private static String jcs(Object value) {
        if (value == null || value == JSONObject.NULL) return "null";
        if (value instanceof JSONObject obj) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Iterator<String> it = obj.keys(); it.hasNext(); ) {
                String k = it.next();
                sorted.put(k, obj.get(k));
            }
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (var e : sorted.entrySet()) {
                if (!first) sb.append(',');
                sb.append(jsonEscape(e.getKey())).append(':').append(jcs(e.getValue()));
                first = false;
            }
            return sb.append('}').toString();
        }
        if (value instanceof JSONArray arr) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < arr.length(); i++) {
                if (i > 0) sb.append(',');
                sb.append(jcs(arr.get(i)));
            }
            return sb.append(']').toString();
        }
        if (value instanceof String s) return jsonEscape(s);
        if (value instanceof Boolean b) return b ? "true" : "false";
        if (value instanceof Integer || value instanceof Long) return value.toString();
        if (value instanceof Number n) {
            // Integers-as-double sometimes come through org.json; check for whole.
            double d = n.doubleValue();
            if (d == Math.floor(d) && !Double.isInfinite(d)) {
                return Long.toString((long) d);
            }
            throw new RuntimeException("JCS: non-integer numbers not implemented in this minimal port");
        }
        throw new RuntimeException("JCS: unsupported value type " + value.getClass());
    }

    private static String jsonEscape(String s) {
        StringBuilder out = new StringBuilder(s.length() + 2);
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            int cp = s.codePointAt(i);
            if (cp >= 0x10000) {
                out.appendCodePoint(cp);
                i++; // surrogate pair
                continue;
            }
            switch (cp) {
                case 0x22 -> out.append("\\\"");
                case 0x5c -> out.append("\\\\");
                case 0x08 -> out.append("\\b");
                case 0x09 -> out.append("\\t");
                case 0x0a -> out.append("\\n");
                case 0x0c -> out.append("\\f");
                case 0x0d -> out.append("\\r");
                default -> {
                    if (cp < 0x20) {
                        out.append(String.format("\\u%04x", cp));
                    } else {
                        out.appendCodePoint(cp);
                    }
                }
            }
        }
        out.append('"');
        return out.toString();
    }

    // ---------- Base64 helpers (java.util.Base64 already handles standard) ----------

    private static byte[] b64d(String s) {
        return Base64.getDecoder().decode(s);
    }

    // ---------- Public-key + signature loaders (accept multiple shapes) ----------

    private static PublicKey loadEs256PublicKey(JSONObject sig) throws Exception {
        if (sig.has("publicKeyDer")) {
            byte[] der = b64d(sig.getString("publicKeyDer"));
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            return kf.generatePublic(new X509EncodedKeySpec(der));
        }
        if (sig.has("publicKey_b64")) {
            byte[] raw = b64d(sig.getString("publicKey_b64"));
            if (raw.length == 65 && raw[0] == 0x04) {
                // Wrap raw uncompressed P-256 point as DER SubjectPublicKeyInfo.
                // Fixed prefix for prime256v1 SPKI = 26 bytes header + the 65-byte
                // point with a 0x00 unused-bits BIT STRING marker prepended.
                byte[] prefix = hex2bin(
                    "3059301306072a8648ce3d020106082a8648ce3d030107034200"
                );
                byte[] der = new byte[prefix.length + raw.length];
                System.arraycopy(prefix, 0, der, 0, prefix.length);
                System.arraycopy(raw, 0, der, prefix.length, raw.length);
                KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                return kf.generatePublic(new X509EncodedKeySpec(der));
            }
        }
        throw new RuntimeException("ES256 signature missing publicKey_b64 / publicKeyDer");
    }

    private static byte[] loadEs256SignatureDer(JSONObject sig) {
        if (sig.has("signature_der")) {
            return b64d(sig.getString("signature_der"));
        }
        String compact = null;
        if (sig.has("signature_b64")) compact = sig.getString("signature_b64");
        else if (sig.has("signature_compact_b64")) compact = sig.getString("signature_compact_b64");
        if (compact == null) {
            throw new RuntimeException("ES256 missing signature_b64 / signature_compact_b64 / signature_der");
        }
        byte[] raw = b64d(compact);
        if (raw.length == 64) {
            return compactToDerEcdsa(raw);
        }
        return raw;
    }

    private static byte[] compactToDerEcdsa(byte[] compact) {
        byte[] r = stripLeadingZeros(Arrays.copyOfRange(compact, 0, 32));
        byte[] s = stripLeadingZeros(Arrays.copyOfRange(compact, 32, 64));
        // Prepend 0x00 if high bit is set (ASN.1 INTEGER unsigned encoding).
        if ((r[0] & 0x80) != 0) {
            byte[] rp = new byte[r.length + 1]; rp[0] = 0; System.arraycopy(r, 0, rp, 1, r.length); r = rp;
        }
        if ((s[0] & 0x80) != 0) {
            byte[] sp = new byte[s.length + 1]; sp[0] = 0; System.arraycopy(s, 0, sp, 1, s.length); s = sp;
        }
        byte[] rEnc = new byte[r.length + 2]; rEnc[0] = 0x02; rEnc[1] = (byte) r.length;
        System.arraycopy(r, 0, rEnc, 2, r.length);
        byte[] sEnc = new byte[s.length + 2]; sEnc[0] = 0x02; sEnc[1] = (byte) s.length;
        System.arraycopy(s, 0, sEnc, 2, s.length);
        byte[] body = concat(rEnc, sEnc);
        // The SEQUENCE body for a P-256 r||s is at most 2+33+2+33 = 70 bytes,
        // well within the single-byte ASN.1 length encoding range (≤ 0x7F).
        // This assumption is safe for P-256 but would need multi-byte length
        // encoding for larger curves (e.g. P-521). Checked explicitly below
        // to fail loudly rather than silently produce malformed DER.
        if (body.length > 0x7F) {
            throw new RuntimeException(
                "compactToDerEcdsa: SEQUENCE body length " + body.length
                + " exceeds single-byte encoding limit (not a P-256 signature)"
            );
        }
        byte[] der = new byte[body.length + 2]; der[0] = 0x30; der[1] = (byte) body.length;
        System.arraycopy(body, 0, der, 2, body.length);
        return der;
    }

    private static byte[] stripLeadingZeros(byte[] b) {
        int i = 0;
        while (i < b.length - 1 && b[i] == 0) i++;
        return Arrays.copyOfRange(b, i, b.length);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static byte[] hex2bin(String hex) {
        byte[] r = new byte[hex.length() / 2];
        for (int i = 0; i < r.length; i++) {
            r[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return r;
    }

    // ---------- Per-scheme verifiers ----------

    private static void verifyEs256(byte[] canonical, JSONObject sig) {
        try {
            PublicKey pub = loadEs256PublicKey(sig);
            byte[] sigDer = loadEs256SignatureDer(sig);
            Signature s = Signature.getInstance("SHA256withECDSA", "BC");
            s.initVerify(pub);
            s.update(canonical);
            check("ES256 (P-256 + SHA-256) verifies", s.verify(sigDer), null);
        } catch (Exception e) {
            check("ES256 verifies", false, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static void verifyEd25519(byte[] canonical, JSONObject sig) {
        try {
            byte[] pubRaw = b64d(sig.getString("publicKey_b64"));
            byte[] sigRaw = b64d(sig.getString("signature_b64"));
            Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(pubRaw, 0);
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(false, pub);
            signer.update(canonical, 0, canonical.length);
            check("Ed25519 verifies", signer.verifySignature(sigRaw), null);
        } catch (Exception e) {
            check("Ed25519 verifies", false, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static void verifyMldsa65(byte[] canonical, JSONObject sig) {
        try {
            byte[] pubRaw = b64d(sig.getString("publicKey_b64"));
            byte[] sigRaw = b64d(sig.getString("signature_b64"));
            // BC 1.84 distinguishes:
            //   - `pqc.crypto.crystals.dilithium.*` — the legacy CRYSTALS-Dilithium
            //     round-3 submission. NOT byte-compatible with FIPS 204 final.
            //   - `crypto.params.MLDSAParameters` + `crypto.signers.MLDSASigner` —
            //     the FIPS 204 final ML-DSA. This is what PQClean's `ml_dsa_65`
            //     produces and what we need to use for cross-impl verification.
            MLDSAPublicKeyParameters pub =
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pubRaw);
            MLDSASigner signer = new MLDSASigner();
            signer.init(false, pub);
            // MLDSASigner uses streaming-style verify: update() then
            // verifySignature(sig) — unlike DilithiumSigner which takes
            // (message, sig) in one call. This matches the FIPS 204
            // pre-hash pipeline shape.
            signer.update(canonical, 0, canonical.length);
            check("ML-DSA-65 (FIPS 204, via BC MLDSASigner) verifies",
                signer.verifySignature(sigRaw), null);
        } catch (Exception e) {
            check("ML-DSA-65 verifies", false, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static void verifyFalcon1024(byte[] canonical, JSONObject sig) {
        try {
            byte[] pubRaw = b64d(sig.getString("publicKey_b64"));
            byte[] sigRaw = b64d(sig.getString("signature_b64"));

            // PQClean / @noble emit Falcon-1024 public keys as 1793 bytes:
            //   [logn header byte (0x0a)] [1792 polynomial bytes]
            // Bouncy Castle's FalconPublicKeyParameters stores only the
            // polynomial bytes (no header). Strip the leading byte to bridge.
            // We keep the assertion explicit so a future format change blows
            // up loudly rather than silently producing 'invalid' verdicts.
            byte[] pubH;
            if (pubRaw.length == 1793 && pubRaw[0] == 0x0a) {
                pubH = Arrays.copyOfRange(pubRaw, 1, pubRaw.length);
            } else if (pubRaw.length == 1792) {
                pubH = pubRaw;
            } else {
                throw new RuntimeException(
                    "unexpected Falcon-1024 publicKey length " + pubRaw.length
                    + " (expected 1793 with 0x0a header or 1792 bare polynomial)"
                );
            }

            FalconPublicKeyParameters pub =
                new FalconPublicKeyParameters(FalconParameters.falcon_1024, pubH);
            FalconSigner signer = new FalconSigner();
            signer.init(false, pub);
            check("Falcon-1024 (FIPS 206, via BC, experimental) verifies",
                signer.verifySignature(canonical, sigRaw), null);
        } catch (Exception e) {
            check("Falcon-1024 verifies", false, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    // ---------- Main ----------

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println();
        System.out.println("=== algovoi-substrate-pqc — Java verifier (Bouncy Castle) ===");
        System.out.println("Runtime: java " + System.getProperty("java.version"));
        System.out.println("BC version (bcprov): " + new BouncyCastleProvider().getVersionStr());
        System.out.println();

        // Default fixture: AP2 PQ conformance algovoi-side.
        String[] candidates = {
            args.length > 0 ? args[0] : null,
            "C:/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json",
            "/algo/ap2-pq-conformance/algovoi-side/ap2-pqc-v0-algovoi-side.json",
        };
        Path fixturePath = null;
        for (String c : candidates) {
            if (c != null && Files.exists(Paths.get(c))) {
                fixturePath = Paths.get(c);
                break;
            }
        }
        if (fixturePath == null) {
            System.err.println("Could not locate AP2 PQ conformance fixture.");
            System.exit(2);
        }
        System.out.println("Fixture: " + fixturePath);
        System.out.println();

        String raw = Files.readString(fixturePath);
        JSONObject artefact = new JSONObject(raw);
        Object payload = artefact.get("mandate_body");

        // --- 1. Canonical-bytes anchor ---
        System.out.println("1. JCS canonical bytes anchor:");
        byte[] canonical = jcs(payload).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        String recomputed;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(canonical);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b));
            recomputed = "sha256:" + hex.toString();
        } catch (Exception e) { throw new RuntimeException(e); }
        check("canonical SHA matches published anchor", recomputed.equals(EXPECTED_ANCHOR),
            "expected " + EXPECTED_ANCHOR + ", got " + recomputed);
        check("canonical SHA matches fixture's expected_canonical_sha256",
            recomputed.equals(artefact.getString("expected_canonical_sha256")), null);

        JSONObject signatures = artefact.getJSONObject("signatures");

        // --- 2. ES256 ---
        System.out.println();
        System.out.println("2. ES256 (P-256 + SHA-256):");
        if (signatures.has("ES256")) verifyEs256(canonical, signatures.getJSONObject("ES256"));
        else System.out.println("  SKIP  ES256 not present");

        // --- 3. Ed25519 ---
        System.out.println();
        System.out.println("3. Ed25519:");
        if (signatures.has("Ed25519")) verifyEd25519(canonical, signatures.getJSONObject("Ed25519"));
        else System.out.println("  SKIP  Ed25519 not present");

        // --- 4. ML-DSA-65 ---
        System.out.println();
        System.out.println("4. ML-DSA-65 (FIPS 204, Bouncy Castle production):");
        if (signatures.has("ML-DSA-65")) verifyMldsa65(canonical, signatures.getJSONObject("ML-DSA-65"));
        else System.out.println("  SKIP  ML-DSA-65 not present");

        // --- 5. Falcon-1024 ---
        System.out.println();
        System.out.println("5. Falcon-1024 (FIPS 206, Bouncy Castle EXPERIMENTAL):");
        if (signatures.has("Falcon-1024")) verifyFalcon1024(canonical, signatures.getJSONObject("Falcon-1024"));
        else System.out.println("  SKIP  Falcon-1024 not present");

        System.out.println();
        System.out.println("=== Summary ===");
        System.out.println("Runtime: java " + System.getProperty("java.version"));
        System.out.println("BC version: " + new BouncyCastleProvider().getVersionStr());
        System.out.println("Passed: " + pass);
        System.out.println("Failed: " + fail);
        System.exit(fail == 0 ? 0 : 1);
    }
}
