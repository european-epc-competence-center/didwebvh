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

## Primitive 2: `Multiformats` — base58btc + multihash

**File:** `crypto/Multiformats.java`

### Pipeline: SHA-256 → multihash → base58btc

For all spec hash strings (SCID, entry hash inside `versionId`, `nextKeyHashes`):

1. **SHA-256** — hash input bytes → 32-byte digest
2. **Multihash** — prefix with `0x12` (sha2-256) + `0x20` (digest length 32) → 34 bytes (self-describing)
3. **Multibase base58btc** — encode 34 bytes with base58btc alphabet + `z` multibase prefix → final `z…` string

`Multiformats.sha256Multihash(byte[])` performs all three steps. Use `wrapSha256Multihash` + `encodeBase58btc` separately only when you already have a raw digest.

### base58btc

Bitcoin alphabet (58 chars): removes look-alike characters `0`, `O`, `I`, `l`. Multibase prefix `z` identifies base58btc.

### multikey encoding for public keys

Ed25519 public keys stored in `updateKeys`:
```
multikey = encodeBase58btc([0xed, 0x01] + raw_32_byte_public_key)
```
`[0xed, 0x01]` = Ed25519 multicodec prefix. To extract raw key: decode base58btc, skip first 2 bytes.

**`updateKeys` vs `nextKeyHashes`:** `updateKeys` stores multikey strings directly. `nextKeyHashes` stores `sha256Multihash(multikey_bytes)` — i.e. hash the multicodec-prefixed key material after multibase-decoding the multikey string.

### Public methods

| Method | What it does | Where it matters |
|--------|----------------|------------------|
| `sha256Multihash(byte[])` | SHA-256 → multihash `0x1220…` → multibase `z…` | SCID, entry hash, `nextKeyHashes` |
| `wrapSha256Multihash(byte[32])` | Prefixes an existing digest (34 bytes) | Composition / tests |
| `encodeBase58btc(byte[])` | Raw bytes → `z` + base58btc | `proofValue`, `updateKeys` multikey |
| `decodeBase58btc(String)` | `z…` → raw bytes | Verify signatures, extract raw key |

### Libraries

| Concern | Choice |
|--------|--------|
| Multibase base58btc | [java-multibase](https://github.com/multiformats/java-multibase) via JitPack — `Multibase.encode(Base58BTC, …)` |
| SHA-256 | `java.security.MessageDigest.getInstance("SHA-256")` (JDK) |
| SHA-256 multihash envelope | Local 2-byte prefix helper (`0x12`, `0x20`) |

`java-multibase` is not on Maven Central; add JitPack repository + `com.github.multiformats:java-multibase` dependency. CI must resolve JitPack over network.

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
