# Crypto Primitives — did:webvh Java Library

Every did:webvh operation (create, update, resolve) boils down to two questions:
1. **Is this JSON identical to what was originally produced?** → deterministic hashing via JCS
2. **Was this JSON signed by the right key?** → Ed25519 Data Integrity proof

---

## Primitive 1: `JcsCanonicalizer` — RFC 8785

**File:** `crypto/JcsCanonicalizer.java`

JSON Canonicalization Scheme ensures two machines with the same logical JSON always produce byte-identical output. The four rules:

1. **No whitespace** — compact JSON, no spaces outside strings
2. **String escaping** — ECMAScript `JSON.stringify()` rules: control chars as `\uXXXX`, `"` as `\"`, `\` as `\\`; everything else as-is UTF-8. Jackson's default serializer already does this correctly.
3. **Number format** — ES2019 / Ryu algorithm (shortest round-trip IEEE 754). This is the hard part. For did:webvh it is irrelevant: all numbers are small integers (`ttl`, version numbers, threshold) for which Java and ECMAScript produce identical output with no decimal point or exponent.
4. **Key sorting** — sort object keys by UTF-16 code unit order (= Java `String.compareTo()` = `TreeMap` natural order). Applied recursively at every nesting level. Arrays are NOT reordered.

Final output: UTF-8 bytes.

**Implementation:** thin delegation to `io.github.erdtman:java-json-canonicalization:1.1` — the RFC's own reference Java implementation (co-authored by RFC author Anders Rundgren, listed in RFC Appendix G). Zero transitive dependencies.

```java
public static byte[] canonicalize(JsonNode node) {
    String json = MAPPER.writeValueAsString(node); // Jackson: JsonNode → JSON string
    return new JsonCanonicalizer(json).getEncodedUTF8(); // RFC reference impl
}
```

**Testing:** `mvn test -Djcs.test.verbose=true` to print Jackson compact JSON and JCS output per test case. Reference vectors: RFC 8785 Appendix B.

---

## Primitive 2: `Multiformats` — base58btc + multihash + multikey

**File:** `crypto/Multiformats.java`

### Two base58btc conventions (critical distinction!)

The spec uses **two different** base58btc encodings:

| Convention | Prefix | Used for | Methods |
|---|---|---|---|
| **Raw base58btc** | none | SCID, entry hash, `nextKeyHashes` | `base58btcEncode/Decode`, `sha256Multihash` |
| **Multibase base58btc** | `z` | `proofValue`, multikey `updateKeys` | `multibaseEncode/Decode` |

Hash strings (SCID, entry hash) start with `Qm` (the natural base58btc encoding of multihash prefix `0x1220`). Multikey strings start with `z6Mk` (the `z` multibase prefix + base58btc of Ed25519 multicodec prefix `0xed01`).

### Pipeline: SHA-256 → multihash → raw base58btc

`sha256Multihash(byte[])`:
1. SHA-256 → 32-byte digest
2. Multihash envelope: `[0x12, 0x20]` + digest → 34 bytes
3. Raw base58btc (NO `z` prefix) → `Qm...` string (46 chars)

### Multikey encoding

`encodeEd25519Multikey(byte[32])` → `z` + base58btc(`[0xed, 0x01]` + rawKey) → `z6Mk...`
`decodeEd25519Multikey(String)` → strips `z`, decodes, strips 2-byte prefix → raw 32-byte key

### Public API summary

| Method | Output | Usage |
|---|---|---|
| `sha256Multihash(byte[])` | `Qm...` (raw, 46 chars) | SCID, entry hash, `nextKeyHashes` |
| `base58btcEncode/Decode` | raw base58btc | Low-level raw encoding |
| `multibaseEncode/Decode` | `z...` | `proofValue`, general multibase |
| `encodeEd25519Multikey/decodeEd25519Multikey` | `z6Mk...` / raw key | `updateKeys` |
| `wrapSha256Multihash(byte[32])` | 34-byte multihash | Composition |

### Libraries

| Concern | Choice |
|---|---|
| base58btc | `Base58Btc.java` — self-contained ~100-line encoder/decoder (Bitcoin alphabet, package-private in `crypto/`) |
| SHA-256 | `java.security.MessageDigest` (JDK) |
| Multihash envelope | Local 2-byte prefix helper (`0x12`, `0x20`) |

---

## Primitive 3: `DataIntegrity` — eddsa-jcs-2022

**File:** `crypto/DataIntegrity.java`

**Spec:** [W3C vc-di-eddsa §3.3](https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022) (W3C Recommendation, May 2025)

W3C Data Integrity cryptosuite `eddsa-jcs-2022`: proves that a specific key holder authorized a specific JSON document. Used in every log entry's `proof` field.

### Exact signing flow (per §3.3.4 — proof config FIRST, document SECOND)

```
proofOptions       = { type, cryptosuite, verificationMethod, created, proofPurpose }  ← no proofValue, no @context for did:webvh
proofConfigHash    = SHA-256(JCS(proofOptions))     ← 32 bytes  ← FIRST
documentHash       = SHA-256(JCS(document))         ← 32 bytes  ← SECOND (document without proof field)
hashData           = proofConfigHash || documentHash ← 64 bytes concatenated
signature          = Ed25519.sign(hashData)          ← 64 bytes
proofValue         = encodeBase58btc(signature)      ← z-prefixed string
```

**Critical**: proofConfigHash is the FIRST 32 bytes, documentHash is SECOND 32 bytes.
This is confirmed by W3C spec §3.3.4 step 3 and the TypeScript reference impl (`concatBuffers(proofHash, dataHash)`).

### Verification flow (per §3.3.2)

1. Strip `proof` field from document → `unsecuredDocument`
2. Build `proofOptions` from proof fields, omitting `proofValue` (and `id`)
3. Compute `hashData` via same proofConfigHash || documentHash construction
4. `Ed25519.verify(hashData, decodeBase58btc(proof.proofValue), publicKey)`

### @context handling

W3C spec says: if `unsecuredDocument.@context` is present, copy it to `proofOptions.@context` before JCS-canonicalizing. For did:webvh log entries, the top-level log entry object has no `@context` (only the `state` DIDDoc inside does), so this step is a no-op and no `@context` is added to `proofOptions`.

### Signer / Verifier interfaces

The library does **not** manage private keys. Callers supply:
- `Signer` — `sign(byte[]) → byte[]`
- `Verifier` — `verify(byte[] sig, byte[] msg, String publicKeyMultibase) → boolean`

This allows callers to use hardware keys, KMS, or BouncyCastle directly in tests.

**Library:** `org.bouncycastle.crypto.signers.Ed25519Signer` for test implementations; JDK `MessageDigest` for SHA-256.

---

## Primitive 4: `DidLogEntry` helpers

**File:** `model/DidLogEntry.java`

`versionId` encodes two pieces:
```
"3-QmABCxyz..."
 ^  ^----------  entryHash()       → multihash of the entry
 |
 versionNumber()  → monotonically incrementing integer
```
Implementation: `String.indexOf('-')` split.

---

## Dependency Order

```
DidLogEntry helpers  (no deps)
      ↓
JcsCanonicalizer     (Jackson only)
      ↓
Multiformats         (java-multibase + JDK SHA-256 + 2-byte multihash prefix)
      ↓
DataIntegrity        (JcsCanonicalizer + Multiformats + Signer/Verifier)  ← IMPLEMENTED
      ↓
CreateOperation, LogValidator, ...
```
