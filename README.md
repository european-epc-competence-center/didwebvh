# did:webvh Java Library

[![CI](https://github.com/european-epc-competence-center/didwebvh/actions/workflows/ci.yml/badge.svg)](https://github.com/european-epc-competence-center/didwebvh/actions/workflows/ci.yml)

A Java implementation of the [`did:webvh`](https://identity.foundation/didwebvh/v1.0/) DID method (DID Web + Verifiable History).

`did:webvh` enhances `did:web` with a cryptographically verifiable, tamper-evident history, self-certifying identifiers (SCIDs), and optional features such as key pre-rotation, witnesses, and DID portability.

## Specification

This library targets `did:webvh` **v1.0**:
- **Spec:** https://identity.foundation/didwebvh/v1.0/
- **Info site:** https://didwebvh.info/latest/

## Requirements

- Java 21 JDK
- Maven 3.9+

## Installation

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

## Quick Start

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

// 1. Generate an Ed25519 key pair
Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();

// 2. Encode the public key as a multikey string (starts with z6Mk...)
String publicKeyMultibase = Multiformats.encodeEd25519Multikey(publicKey.getEncoded());

// 3. Build the signer that will authorise DID operations
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
doc.put("id", "did:webvh:{SCID}:example.com");

// 5. Create the DID
CreateResult created = DidWebVh.create(
    CreateOptions.builder()
        .domain("example.com")
        .initialDocument(doc)
        .updateKeys(List.of(publicKeyMultibase))
        .signer(signer)
        .build()
);

String did = created.did();
System.out.println("Created: " + did);

// 6. Publish the log as did.jsonl
String jsonl = LogSerializer.serialize(created.log());
// ... write jsonl to https://example.com/.well-known/did.jsonl

// 7. Resolve the DID
ResolveResult resolved = DidWebVh.resolve(did, ResolveOptions.builder().build());
if (resolved.isSuccess()) {
    System.out.println("Document: " + resolved.document());
}
```

See the [Usage Guide](didwebvh-java/USAGE.md) for detailed documentation on:
- Creating, updating, resolving, and deactivating DIDs
- Using the builder API
- Key rotation and pre-rotation
- Witness configuration
- Working with `DidLog`, `LogSerializer`, and `LogParser`
- Custom signers, verifiers, and HTTP fetchers
- Error handling

## Development

```bash
cd didwebvh-java

# Compile
mvn compile

# Run tests
mvn test

# Package as JAR
mvn package
```

### Project Structure

```
didwebvh-java/
├── src/main/java/io/didwebvh/
│   ├── api/                 # Public API: DidWebVh, *Options, *Result
│   ├── crypto/              # Signer, Verifier, DefaultVerifier, canonicalization
│   ├── log/                 # LogParser, LogSerializer, LogValidator
│   ├── model/               # DidLog, DidLogEntry, Parameters, ResolutionMetadata
│   ├── operation/           # CreateOperation, UpdateOperation, DeactivateOperation
│   ├── resolve/             # HttpResolver, LogBasedResolver, LogFetcher
│   └── witness/             # Witness validation and proof collection
└── src/test/java/io/didwebvh/
    ├── operation/           # Tests for create, update, deactivate
    ├── resolve/             # Tests for HTTP and log-based resolution
    ├── crypto/              # Tests for canonicalization, multiformats, proofs
    └── support/             # Test fixtures (Ed25519 key generation)
```

## Repository Overview

```
/
├── .github/workflows/       # CI: tests on push to main (ci.yml)
├── didwebvh-java/           # Java library (Maven, Java 21)
├── spec/                    # did:webvh specification v1.0 source files
├── docs/                    # Thesis documentation
├── README.md
└── CHANGELOG.md
```

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.

---
