# did:webvh Java Library — Usage Guide

This guide explains how to use `didwebvh-java` to create, update, resolve, and deactivate `did:webvh` DIDs. Every public operation is exposed through the static methods on `DidWebVh` and configured via builders.

---

## Table of Contents

1. [Installation](#installation)
2. [Key Concepts](#key-concepts)
3. [Creating a DID](#creating-a-did)
4. [Resolving a DID](#resolving-a-did)
5. [Updating a DID](#updating-a-did)
6. [Deactivating a DID](#deactivating-a-did)
7. [Working with the DID Log](#working-with-the-did-log)
8. [Advanced Topics](#advanced-topics)
9. [Error Handling](#error-handling)

---

## Installation

**Requirements:** Java 21+, Maven 3.9+

The library is not yet published to Maven Central. Install it to your local `~/.m2` repository:

```bash
cd didwebvh-java
mvn install
```

Add the dependency to your `pom.xml`:

```xml
<dependency>
  <groupId>io.didwebvh</groupId>
  <artifactId>didwebvh-java</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

---

## Key Concepts

| Concept | Description |
|---------|-------------|
| **DID Log** (`DidLog`) | An append-only sequence of log entries. This is the tamper-evident history that makes `did:webvh` verifiable. |
| **SCID** | Self-Certifying Identifier. A hash derived from the genesis log entry. It appears in the DID string: `did:webvh:{SCID}:{domain}`. |
| **Update Keys** | Multikey-encoded Ed25519 public keys that are authorised to sign log updates. Separate from the verification methods inside the DID document. |
| **Signer** | Your implementation of `Signer` that holds a private key and produces Data Integrity proofs. |
| **Verifier** | Your implementation of `Verifier` that checks signatures. The library provides `DefaultVerifier` for Ed25519. |
| **Parameter Delta** | When updating, the library computes the *difference* between the current log parameters and your new options. Only changed fields are written to the new entry. |

---

## Creating a DID

Creating a DID generates the SCID, builds the genesis log entry, and signs it with your key. You receive a `CreateResult` containing the full DID string, the resolved document, metadata, and the log.

### Minimal Example

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.CreateOptions;
import io.didwebvh.api.CreateResult;
import io.didwebvh.api.DidWebVh;
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;
import java.util.List;

// 1. Generate an Ed25519 key pair
Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();

// 2. Encode the public key as a multikey (this is what goes into updateKeys)
String publicKeyMultibase = Multiformats.encodeEd25519Multikey(publicKey.getEncoded());

// 3. Build the signer
String verificationMethodId = "did:key:" + publicKeyMultibase + "#" + publicKeyMultibase;
Signer signer = Signer.create(verificationMethodId, data -> {
    Ed25519Signer s = new Ed25519Signer();
    s.init(true, privateKey);
    s.update(data, 0, data.length);
    return s.generateSignature();
});

// 4. Build the initial DID document with {SCID} placeholders
ObjectMapper mapper = new ObjectMapper();
ObjectNode doc = mapper.createObjectNode();
doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
doc.put("id", "did:webvh:{SCID}:example.com"); // {SCID} is mandatory

// 5. Create the DID
CreateResult result = DidWebVh.create(
    CreateOptions.builder()
        .domain("example.com")
        .initialDocument(doc)
        .updateKeys(List.of(publicKeyMultibase))
        .signer(signer)
        .build()
);

// 6. Use the result
String did = result.did();               // e.g. did:webvh:Qm...:example.com
JsonNode document = result.document();   // the resolved DID document
DidLog log = result.log();               // the genesis log entry
```

### The `CreateOptions` Builder

All fields are set through the `CreateOptions.Builder`:

| Builder Method | Required | Description |
|----------------|----------|-------------|
| `.domain(String)` | **Yes** | The domain for the DID, e.g. `example.com`. |
| `.initialDocument(JsonNode)` | **Yes** | The initial DID document. Must use `{SCID}` as a placeholder wherever the DID identifier appears (e.g. in `id`, `controller`, `verificationMethod.id`). |
| `.updateKeys(List<String>)` | **Yes** | One or more multikey-encoded Ed25519 public keys authorised to sign future updates. |
| `.signer(Signer)` | **Yes** | The signing key that corresponds to one of the `updateKeys`. |
| `.portable(boolean)` | No | Whether the DID may be moved to a new domain later. Can only be set `true` at creation. Default: `false`. |
| `.nextKeyHashes(List<String>)` | No | SHA-256 multihashes of future update keys. Enables **pre-rotation** (see below). |
| `.witness(WitnessParameter)` | No | Witness configuration for multi-party approval of updates. |
| `.watchers(List<String>)` | No | URLs of watcher services that monitor the DID log. |
| `.ttl(Integer)` | No | Cache time-to-live in seconds. `null` uses the spec default. |

### Creating a `Signer`

A `Signer` wraps your private key and knows its public identifier. The recommended format for the verification method ID is `did:key:{multikey}#{multikey}`.

The example below shows the **full flow** from raw key generation to a working `Signer`, exactly as the test suite does internally:

```java
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;

// 1. Generate a fresh Ed25519 key pair
Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();

// 2. Encode the raw 32-byte public key as a multikey string (starts with z6Mk...)
String publicKeyMultibase = Multiformats.encodeEd25519Multikey(publicKey.getEncoded());

// 3. Build the verification method identifier
String verificationMethodId = "did:key:" + publicKeyMultibase + "#" + publicKeyMultibase;

// 4. Create the signer
Signer signer = Signer.create(verificationMethodId, data -> {
    Ed25519Signer s = new Ed25519Signer();
    s.init(true, privateKey);
    s.update(data, 0, data.length);
    return s.generateSignature();
});
```

> **What you need to provide:**
> - `publicKeyMultibase` — goes into `.updateKeys(...)` when creating or updating a DID.
> - `signer` — goes into `.signer(...)` to authorise the operation.

### Publishing the Log

After creation you must publish `did.jsonl` (the serialized log) to the web server that hosts your DID. The file must be reachable at:

```
https://{domain}/.well-known/did.jsonl
```

(If your domain contains a path component, the URL structure follows the `did:webvh` spec transformation rules.)

```java
import io.didwebvh.log.LogSerializer;

String jsonl = LogSerializer.serialize(result.log());
// Write jsonl to your web server's did.jsonl endpoint
```

---

## Resolving a DID

### Resolve over HTTPS

The library fetches `did.jsonl`, validates every entry (signatures, hash chain, SCID), and returns the latest DID document.

```java
import io.didwebvh.api.ResolveOptions;
import io.didwebvh.api.ResolveResult;

ResolveResult result = DidWebVh.resolve(
    "did:webvh:Qm...:example.com",
    ResolveOptions.builder().build()
);

if (result.isSuccess()) {
    JsonNode doc = result.document();
    ResolutionMetadata meta = result.metadata();
    System.out.println("Resolved version " + meta.versionId());
} else {
    System.out.println("Error: " + result.metadata().error());
}
```

> **Note:** The default `DefaultVerifier` is used automatically when you do not supply a custom verifier.

### Resolve from an Existing Log (No Network)

Use this when you already have the log (e.g. from a local file, watcher, or cache):

```java
import io.didwebvh.model.DidLog;

DidLog log = ...; // parsed from a file or received from a watcher
ResolveResult result = DidWebVh.resolveFromLog(
    "did:webvh:Qm...:example.com",
    log,
    ResolveOptions.builder().build()
);
```

### The `ResolveOptions` Builder

| Builder Method | Description |
|----------------|-------------|
| `.verifier(Verifier)` | Override the default Ed25519 verifier. |
| `.versionNumber(int)` | Resolve a specific version by its integer sequence number. |
| `.versionId(String)` | Resolve the version whose `versionId` exactly matches this string. |
| `.versionTime(Instant)` | Resolve the version that was active at the given point in time. |
| `.witnessProofs(WitnessProofCollection)` | Supply pre-fetched witness proofs from `did-witness.json`. |

Only one version filter should be used at a time. When all are absent, the latest valid version is returned.

### DID URL Fragment Dereferencing

Resolving a DID URL with a fragment (e.g. `did:webvh:Qm...:example.com#key-1`) returns the matching verification method node instead of the full document:

```java
ResolveResult result = DidWebVh.resolve(
    "did:webvh:Qm...:example.com#key-1",
    ResolveOptions.builder().build()
);

if (result.isSuccess()) {
    JsonNode verificationMethod = result.document();
    String publicKeyMultibase = verificationMethod.get("publicKeyMultibase").asText();
}
```

---

## Updating a DID

Updating appends a new entry to the log. You provide the current log, the new document, and a signer authorised by the current `updateKeys`.

### Document-Only Update

```java
import io.didwebvh.api.UpdateOptions;
import io.didwebvh.api.UpdateResult;

// Build the new document (use the real SCID, not {SCID})
ObjectNode newDoc = mapper.createObjectNode();
newDoc.putArray("@context").add("https://www.w3.org/ns/did/v1");
newDoc.put("id", did); // the real DID with SCID

UpdateResult result = DidWebVh.update(
    UpdateOptions.builder()
        .log(currentLog)
        .updatedDocument(newDoc)
        .signer(signer)
        .build()
);

DidLog updatedLog = result.log(); // currentLog + new entry
```

### The `UpdateOptions` Builder

| Builder Method | Required | Description |
|----------------|----------|-------------|
| `.log(DidLog)` | **Yes** | The current log to append to. |
| `.updatedDocument(JsonNode)` | **Yes** | The new DID document state. |
| `.signer(Signer)` | **Yes** | The signing key matching the *currently active* `updateKeys`. |
| `.updateKeys(List<String>)` | No | New authorization keys. Supply only when **rotating keys**. |
| `.nextKeyHashes(List<String>)` | No | New pre-rotation hashes. Supply only when changing pre-rotation. |
| `.witness(WitnessParameter)` | No | New witness configuration. Supply only when changing witnesses. |
| `.watchers(List<String>)` | No | New watcher URLs. Supply only when changing watchers. |
| `.ttl(Integer)` | No | New cache TTL. Supply only when changing TTL. |

> **Important:** Only supply optional fields when that aspect of the DID is actually changing. Unchanged fields are inherited automatically from the previous log entry. This produces a compact *parameter delta*.

### Key Rotation

Rotate to a new key by generating a second key pair, supplying the new public key in `updateKeys`, and signing the update with the **old** (currently authorised) private key:

```java
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;
import java.util.List;

// 1. Assume you already have an 'old' key pair from creation.
//    For completeness, here is how it was built:
Ed25519KeyPairGenerator genA = new Ed25519KeyPairGenerator();
genA.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
AsymmetricCipherKeyPair pairA = genA.generateKeyPair();
Ed25519PrivateKeyParameters privateKeyA = (Ed25519PrivateKeyParameters) pairA.getPrivate();
Ed25519PublicKeyParameters publicKeyA = (Ed25519PublicKeyParameters) pairA.getPublic();
String oldPublicKeyMultibase = Multiformats.encodeEd25519Multikey(publicKeyA.getEncoded());
Signer oldSigner = Signer.create(
    "did:key:" + oldPublicKeyMultibase + "#" + oldPublicKeyMultibase,
    data -> {
        Ed25519Signer s = new Ed25519Signer();
        s.init(true, privateKeyA);
        s.update(data, 0, data.length);
        return s.generateSignature();
    }
);

// 2. Generate the NEW key pair
Ed25519KeyPairGenerator genB = new Ed25519KeyPairGenerator();
genB.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
AsymmetricCipherKeyPair keyPairB = genB.generateKeyPair();

Ed25519PrivateKeyParameters privateKeyB = (Ed25519PrivateKeyParameters) keyPairB.getPrivate();
Ed25519PublicKeyParameters publicKeyB = (Ed25519PublicKeyParameters) keyPairB.getPublic();

// 3. Encode the new public key as a multikey
String newPublicKeyMultibase = Multiformats.encodeEd25519Multikey(publicKeyB.getEncoded());

// 4. Build the new signer (keep this for future updates)
String newVerificationMethodId = "did:key:" + newPublicKeyMultibase + "#" + newPublicKeyMultibase;
Signer newSigner = Signer.create(newVerificationMethodId, data -> {
    Ed25519Signer s = new Ed25519Signer();
    s.init(true, privateKeyB);
    s.update(data, 0, data.length);
    return s.generateSignature();
});

// 5. Rotate: old key signs the update, new key is declared as the next updateKeys
UpdateResult result = DidWebVh.update(
    UpdateOptions.builder()
        .log(currentLog)
        .updatedDocument(newDoc)
        .updateKeys(List.of(newPublicKeyMultibase)) // new key
        .signer(oldSigner)                          // old key still signs
        .build()
);

// The next update MUST be signed by newSigner
```

### Pre-Rotation

Pre-rotation lets you commit to future keys via their hashes before revealing the public keys. This protects against key-compromise attacks.

**1. Generate both key pairs:**

```java
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

// Key A (current)
Ed25519KeyPairGenerator genA = new Ed25519KeyPairGenerator();
genA.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
AsymmetricCipherKeyPair pairA = genA.generateKeyPair();
Ed25519PrivateKeyParameters privateKeyA = (Ed25519PrivateKeyParameters) pairA.getPrivate();
Ed25519PublicKeyParameters publicKeyA = (Ed25519PublicKeyParameters) pairA.getPublic();
String keyAMultibase = Multiformats.encodeEd25519Multikey(publicKeyA.getEncoded());
Signer signerA = Signer.create(
    "did:key:" + keyAMultibase + "#" + keyAMultibase,
    data -> {
        Ed25519Signer s = new Ed25519Signer();
        s.init(true, privateKeyA);
        s.update(data, 0, data.length);
        return s.generateSignature();
    }
);

// Key B (future — not revealed yet)
Ed25519KeyPairGenerator genB = new Ed25519KeyPairGenerator();
genB.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
AsymmetricCipherKeyPair pairB = genB.generateKeyPair();
Ed25519PrivateKeyParameters privateKeyB = (Ed25519PrivateKeyParameters) pairB.getPrivate();
Ed25519PublicKeyParameters publicKeyB = (Ed25519PublicKeyParameters) pairB.getPublic();
String keyBMultibase = Multiformats.encodeEd25519Multikey(publicKeyB.getEncoded());
Signer signerB = Signer.create(
    "did:key:" + keyBMultibase + "#" + keyBMultibase,
    data -> {
        Ed25519Signer s = new Ed25519Signer();
        s.init(true, privateKeyB);
        s.update(data, 0, data.length);
        return s.generateSignature();
    }
);
```

**2. Create with pre-rotation (commit to key B's hash at genesis):**

```java
// Hash the multikey string of key B — this is what goes into nextKeyHashes
String hashB = Multiformats.sha256Multihash(keyBMultibase.getBytes(StandardCharsets.UTF_8));

CreateResult created = DidWebVh.create(
    CreateOptions.builder()
        .domain("example.com")
        .initialDocument(doc)
        .updateKeys(List.of(keyAMultibase)) // current key A
        .nextKeyHashes(List.of(hashB))      // committed: key B
        .signer(signerA)
        .build()
);
```

**3. Reveal the committed key on the next update:**

```java
UpdateResult result = DidWebVh.update(
    UpdateOptions.builder()
        .log(created.log())
        .updatedDocument(newDoc)
        .updateKeys(List.of(keyBMultibase)) // reveal key B
        .signer(signerB)                    // must sign with key B
        .build()
);
```

Rules enforced by the library:
- When pre-rotation is active, the next update **must** reveal one of the committed keys.
- The update must be **signed by the revealed key**.
- To disable pre-rotation, pass `.nextKeyHashes(List.of())` in an update.

---

## Deactivating a DID

Deactivation is permanent. After deactivation, resolvers will return `deactivated: true` in the metadata and no DID document.

```java
import io.didwebvh.api.DeactivateOptions;
import io.didwebvh.api.DeactivateResult;

DeactivateResult result = DidWebVh.deactivate(
    DeactivateOptions.builder()
        .log(currentLog)
        .signer(signer)
        .build()
);

DidLog deactivatedLog = result.log();
// Publish deactivatedLog to replace did.jsonl
```

> **Restriction:** Deactivation is rejected while pre-rotation is still active. You must clear pre-rotation (`.nextKeyHashes(List.of())`) in an update before deactivating.

---

## Working with the DID Log

### Serialization (Publishing)

Convert a `DidLog` to the JSONL wire format:

```java
import io.didwebvh.log.LogSerializer;

String jsonl = LogSerializer.serialize(log);
Files.writeString(Path.of("did.jsonl"), jsonl);
```

Each entry is one compact JSON object per line, newline-terminated.

### Parsing (Receiving)

Parse a JSONL string back into a `DidLog`:

```java
import io.didwebvh.log.LogParser;

String jsonl = Files.readString(Path.of("did.jsonl"));
DidLog log = LogParser.parse(jsonl);
```

### Validation

Validate an entire log manually:

```java
import io.didwebvh.log.LogValidator;

LogValidator validator = new LogValidator(verifier);
int validCount = validator.validate(log);
// validCount == log.size() when every entry is valid
```

### Inspecting a Log

```java
DidLog log = result.log();

log.size();          // total number of entries
log.first();         // genesis entry
log.latest();        // most recent entry
log.isEmpty();       // false for any real log

for (DidLogEntry entry : log.entries()) {
    String versionId = entry.versionId();       // e.g. "2-Qm..."
    String versionTime = entry.versionTime();   // ISO-8601 timestamp
    Parameters params = entry.parameters();     // updateKeys, witness, etc.
    JsonNode state = entry.state();             // the DID document at this version
    List<DataIntegrityProof> proofs = entry.proof(); // Data Integrity proofs
}
```

---

## Advanced Topics

### Witnesses

Witnesses are third-party `did:key` DIDs that must co-sign updates before they are considered valid. Configure them at creation or in an update:

```java
WitnessParameter witness = new WitnessParameter(
    2, // threshold: at least 2 witness signatures required
    List.of(
        new WitnessParameter.WitnessEntry("did:key:z6MkWITNESS1"),
        new WitnessParameter.WitnessEntry("did:key:z6MkWITNESS2"),
        new WitnessParameter.WitnessEntry("did:key:z6MkWITNESS3")
    )
);

CreateResult result = DidWebVh.create(
    CreateOptions.builder()
        .domain("example.com")
        .initialDocument(doc)
        .updateKeys(List.of(publicKeyMultibase))
        .signer(signer)
        .witness(witness)
        .build()
);
```

> The library validates that witness DIDs use the `did:key` method, that IDs are unique, and that the threshold is between `1` and the number of witnesses.

### Portability

A portable DID can be moved to a new domain. This can only be enabled at creation time:

```java
CreateResult result = DidWebVh.create(
    CreateOptions.builder()
        // ... other options ...
        .portable(true)
        .build()
);
```

### Custom Verifier for Resolution

If you need a different cryptographic backend (e.g. HSM, AWS KMS, or a different Ed25519 provider), implement `Verifier`:

```java
import io.didwebvh.crypto.Verifier;

Verifier myVerifier = (signature, message, publicKeyMultibase) -> {
    // your verification logic
    return true;
};

ResolveResult result = DidWebVh.resolve(
    did,
    ResolveOptions.builder()
        .verifier(myVerifier)
        .build()
);
```

### Injecting a Custom HTTP Fetcher (Testing)

For unit tests, avoid real HTTP by injecting a `LogFetcher`:

```java
import io.didwebvh.resolve.HttpResolver;
import io.didwebvh.resolve.DidResolver;
import io.didwebvh.resolve.LogFetcher;

String cannedJsonl = LogSerializer.serialize(myTestLog);
LogFetcher testFetcher = url -> cannedJsonl;

DidResolver resolver = new HttpResolver(testFetcher);
ResolveResult result = resolver.resolve(did, ResolveOptions.builder().build());
```

---

## Error Handling

The library uses exceptions for programming errors and result objects for resolution failures:

- **IllegalArgumentException / NullPointerException** — missing or invalid options (e.g. missing domain, empty updateKeys, unauthorised signer).
- **IllegalStateException** — invalid operation state (e.g. updating a deactivated DID, deactivating while pre-rotation is active).
- **LogValidationException** — log integrity failure (bad signature, broken hash chain, invalid SCID).
- **ResolveResult** — resolution errors are *encoded in the result*. Always check `result.isSuccess()` and inspect `result.metadata().error()` and `result.metadata().problemDetails()`.

Example:

```java
ResolveResult result = DidWebVh.resolve(did, options);

if (!result.isSuccess()) {
    String errorCode = result.metadata().error();              // e.g. "notFound"
    ProblemDetails problem = result.metadata().problemDetails(); // RFC 9457 details
    System.err.println(errorCode + ": " + problem.title());
}
```

---

## Full Lifecycle Example

```java
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.didwebvh.api.*;
import io.didwebvh.crypto.Multiformats;
import io.didwebvh.crypto.Signer;
import io.didwebvh.log.LogSerializer;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;
import java.util.List;

// -------------------------------------------------
// Helper: generate a key pair + signer + multikey
// -------------------------------------------------
record KeyPairAndSigner(String multibase, Signer signer) {}

KeyPairAndSigner generate() {
    Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
    gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
    AsymmetricCipherKeyPair pair = gen.generateKeyPair();

    Ed25519PrivateKeyParameters priv = (Ed25519PrivateKeyParameters) pair.getPrivate();
    Ed25519PublicKeyParameters pub = (Ed25519PublicKeyParameters) pair.getPublic();

    String multibase = Multiformats.encodeEd25519Multikey(pub.getEncoded());
    String vmId = "did:key:" + multibase + "#" + multibase;
    Signer signer = Signer.create(vmId, data -> {
        Ed25519Signer s = new Ed25519Signer();
        s.init(true, priv);
        s.update(data, 0, data.length);
        return s.generateSignature();
    });
    return new KeyPairAndSigner(multibase, signer);
}

// 1. GENERATE KEYS
KeyPairAndSigner keyA = generate();
KeyPairAndSigner keyB = generate();

// 2. CREATE
ObjectMapper mapper = new ObjectMapper();
ObjectNode doc = mapper.createObjectNode();
doc.putArray("@context").add("https://www.w3.org/ns/did/v1");
doc.put("id", "did:webvh:{SCID}:example.com");

CreateResult created = DidWebVh.create(
    CreateOptions.builder()
        .domain("example.com")
        .initialDocument(doc)
        .updateKeys(List.of(keyA.multibase()))
        .signer(keyA.signer())
        .build()
);

String did = created.did();
DidLog log = created.log();

// 3. UPDATE (document change)
ObjectNode docV2 = mapper.createObjectNode();
docV2.putArray("@context").add("https://www.w3.org/ns/did/v1");
docV2.put("id", did);
docV2.put("service", "https://example.com/vc-issuer");

UpdateResult updated = DidWebVh.update(
    UpdateOptions.builder()
        .log(log)
        .updatedDocument(docV2)
        .signer(keyA.signer())
        .build()
);

// 4. ROTATE KEYS (old key signs the rotation)
UpdateResult rotated = DidWebVh.update(
    UpdateOptions.builder()
        .log(updated.log())
        .updatedDocument(docV2)
        .updateKeys(List.of(keyB.multibase()))
        .signer(keyA.signer())
        .build()
);

// 5. RESOLVE
ResolveResult resolved = DidWebVh.resolve(did, ResolveOptions.builder().build());
assert resolved.isSuccess();

// 6. DEACTIVATE (new key signs the deactivation)
DeactivateResult deactivated = DidWebVh.deactivate(
    DeactivateOptions.builder()
        .log(rotated.log())
        .signer(keyB.signer())
        .build()
);

// 7. PUBLISH FINAL LOG
String finalJsonl = LogSerializer.serialize(deactivated.log());
```

---