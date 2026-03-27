# Crypto Primitives — did:webvh Java Library

This note explains the low-level building blocks in `io.didwebvh.crypto/` for someone new to the topic.

## Why these primitives exist

Every did:webvh operation (create, update, resolve) boils down to two questions:
1. **Is this JSON identical to what was originally produced?** → answered by deterministic hashing
2. **Was this JSON signed by the right key?** → answered by digital signatures

To answer question 1 reliably, JSON must first be converted to a canonical byte sequence (JCS). Then that sequence is hashed and encoded. Question 2 uses the result of question 1 as the message to sign.

---

## Primitive 1: `JcsCanonicalizer` — RFC 8785

**File:** `crypto/JcsCanonicalizer.java`

### The problem it solves

JSON objects like `{"b":2,"a":1}` and `{"a":1,"b":2}` represent the same data but are different byte sequences. If you hash both you get different results. To hash JSON reliably, you need a rule that always produces the same bytes for the same data.

### What JCS does

JSON Canonicalization Scheme (RFC 8785):
- Sort all object keys by their Unicode codepoint value (= standard Java `String.compareTo`)
- Preserve array element order (arrays are ordered by definition)
- Use compact JSON (no spaces, no newlines)
- Serialize numbers in IEEE 754 / ES2019 format

Result: two machines with the same logical JSON always produce byte-identical output.

### Implementation

**Library:** `io.github.erdtman:java-json-canonicalization:1.1` — the RFC's reference Java implementation (co-authored by RFC author Anders Rundgren, listed in RFC Appendix G). Zero transitive dependencies.

Implementation is a thin delegation:
1. Serialize `JsonNode` → JSON string with Jackson (`MAPPER.writeValueAsString(node)`)
2. Pass to `new JsonCanonicalizer(json).getEncodedUTF8()` which handles key sorting, ES2019 number format, and string escaping

See [RFC 8785 JCS Explained](./rfc8785-jcs-explained.md) for the full deep-dive on why the number serialization part (Ryu/Grisu3) is hard and why using the reference library is the correct choice.

### Testing

To print Jackson’s compact JSON and the final JCS string for each `JcsCanonicalizerTest` case: `mvn test -Djcs.test.verbose=true` (or add the same `-D` in the IDE run config). Default runs stay quiet.

Reference: RFC 8785 Appendix B contains exact test vectors with expected byte output.

Key test cases:
- Object with reversed key order → canonical output has sorted keys
- Nested objects → all levels sorted
- Arrays → element order preserved
- Unicode keys → sorted by codepoint, not by lexicographic appearance
- Round-trip: `canonicalize(parse(canonicalize(x))) == canonicalize(x)`

---

## Primitive 2: `Multiformats` — base58btc + multihash

**File:** `crypto/Multiformats.java`

### The problem it solves

A hash is 32 raw bytes — hard to copy, type, or embed in a URL. We need a text encoding. Also, we want the encoding to be *self-describing*: a reader should be able to tell which hash algorithm was used without external context.

### base58btc

Like base64 but uses only 58 characters — the Bitcoin alphabet:
```
123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```
Removed: `0` (zero), `O` (capital o), `I` (capital i), `l` (lowercase L) — all look-alike characters. This makes the encoding safe to copy by hand or display in a UI.

**Multibase** adds a single-character prefix to identify the encoding. For base58btc the prefix is `z`. So a base58btc-encoded value always starts with `z`.

### multihash

Multihash wraps a raw hash digest with a self-describing prefix:
```
[algorithm code] [digest length] [raw digest bytes]
```
For SHA-256:
- Algorithm code: `0x12` (varint for sha2-256)
- Digest length: `0x20` (= 32)
- Raw digest: 32 bytes from SHA-256

Total: 34 bytes. The first two bytes `[0x12, 0x20]` always identify "this is a SHA-256 hash of 32 bytes".

### The canonical hash used throughout the spec

```
sha256Multihash(input) = encodeBase58btc(wrapSha256Multihash(SHA-256(input)))
```

Used for:
- SCID computation: `sha256Multihash(JCS(preliminary_log_entry))`
- Entry hash computation: `sha256Multihash(JCS(entry_without_proof))`
- Pre-rotation key hash: `sha256Multihash(multikey_public_key_bytes)`

### multikey encoding for public keys

Ed25519 public keys are stored in `updateKeys` as **multikey** strings:
```
multikey = encodeBase58btc([0xed, 0x01] + raw_32_byte_public_key)
```
Prefix bytes `[0xed, 0x01]` identify the key type as Ed25519. To extract the raw key from a multikey string: decode base58btc, skip first 2 bytes.

### Library

`org.bouncycastle.util.encoders.Base58` (in `bcprov-jdk18on:1.79`) — already a dependency.
`java.security.MessageDigest` for SHA-256 (standard JDK, no dep).

### Testing

- `encodeBase58btc` of known bytes → starts with `z`, exact known output
- `decodeBase58btc` → round-trip; wrong prefix → throws `InvalidDidException`
- `wrapSha256Multihash`: `output[0]==0x12`, `output[1]==0x20`, `output.length==34`
- `sha256Multihash("hello".getBytes())` → compare to precomputed expected value
- SCID character count: result of `sha256Multihash` is 47 chars (`z` + 46 base58 characters = 47)

---

## Primitive 3: `DataIntegrity` — eddsa-jcs-2022

**File:** `crypto/DataIntegrity.java`

### The problem it solves

Proves that a specific key holder authorized a specific JSON document. Used in every log entry's `proof` field.

### What it is

W3C Data Integrity (`eddsa-jcs-2022` cryptosuite):
- EdDSA = Edwards-curve Digital Signature Algorithm (Ed25519 is the specific curve)
- JCS = JSON Canonicalization Scheme (see above)
- 2022 = spec version

An Ed25519 signature is 64 bytes and cannot be forged without the private key. To verify, you only need the public key (which is public in `updateKeys`).

### Signing flow

```
hash(proofOptions) = SHA-256(JCS({ type, cryptosuite, proofPurpose, verificationMethod, created }))
hash(document)     = SHA-256(JCS(document_without_proof))
signingInput       = hash(proofOptions) || hash(document)   ← 64 bytes total
signature          = Ed25519.sign(signingInput)             ← 64 bytes
proofValue         = encodeBase58btc(signature)             ← z-prefixed string
```

The two-hash construction ensures the proof is bound to both the document content and the proof metadata (who signed it, for what purpose). Changing either invalidates the signature.

### verificationMethod

The `verificationMethod` field in the proof is the multikey-encoded public key string (from `updateKeys`) of the key that signed it. The verifier uses this to look up the key.

### Signer / Verifier interfaces

The library does **not** manage private keys. Callers supply:
- `Signer`: a lambda that takes `byte[]` and returns `byte[]` (raw sign)
- `Verifier`: a lambda that takes `(signature, message, publicKeyMultibase)` and returns `boolean`

This allows callers to use hardware keys, key management services, or BouncyCastle directly in tests.

### Library

`org.bouncycastle.crypto.signers.Ed25519Signer` for test `Signer` / `Verifier` implementations.
`java.security.MessageDigest` for SHA-256.
`JcsCanonicalizer` + `Multiformats` (implemented above).

### Testing

Use a test-only key pair generated by BouncyCastle in a shared `TestKeyPair` helper:
```java
Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
AsymmetricCipherKeyPair pair = gen.generateKeyPair();
```

Key test cases:
- `createProof` output has correct `type`, `cryptosuite`, `proofPurpose` constants
- `proofValue` starts with `z` (multibase base58btc)
- Round-trip: `verifyProof(doc, createProof(doc, vmId, signer), verifier)` returns `true`
- Tampered document: change one character after signing → `verifyProof` throws `LogValidationException`
- Tampered `proofValue`: flip one character → throws
- `prepareSigningInput` output is exactly 64 bytes

---

## Primitive 4: `DidLogEntry` helpers

**File:** `model/DidLogEntry.java`

Not a crypto primitive, but needed by everything. The `versionId` field encodes two pieces:
```
"3-QmABCxyz..."
 ^  ^----------  entryHash()   → the multihash of the entry
 |
 versionNumber()  → monotonically incrementing integer
```

Implementation: simple `String.indexOf('-')` split.

---

## Dependency Order

```
DidLogEntry helpers  (no deps)
      ↓
JcsCanonicalizer     (Jackson only)
      ↓
Multiformats         (BouncyCastle Base58 + JDK SHA-256)
      ↓
DataIntegrity        (JcsCanonicalizer + Multiformats + Signer/Verifier)
      ↓
CreateOperation, LogValidator, ...
```

Each layer can be implemented and tested independently before the next.
