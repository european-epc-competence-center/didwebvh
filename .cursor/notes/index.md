# Notes Index

## Project Overview

Bachelor thesis project: security analysis of `did:webvh` (DID method combining `did:web` with verifiable hash-chained history).

- **Thesis topic**: STRIDE-based security analysis of `did:webvh` vs. `did:web`
- **Practical component**: Java library implementing `did:webvh` (log chaining, key rotation, Data Integrity Proofs)

## Folder Structure

```
/
├── .github/workflows/ci.yml  # GitHub Actions CI: mvn verify on push to main
├── docs/application.md       # Thesis application document (motivation, research question, approach)
├── README.md
├── CHANGELOG.md
├── spec/                     # did:webvh spec v1.0 source files
├── didwebvh-java/            # Java library implementation (Maven, Java 21)
│   ├── pom.xml               # io.didwebvh:didwebvh-java:0.1.0-SNAPSHOT
│   ├── src/main/java/io/didwebvh/
│   │   ├── api/              # Public facade + Options/Result types
│   │   ├── model/            # Data models (DidLog, Parameters, WitnessParameter, etc.)
│   │   ├── crypto/           # Signer/Verifier interfaces + impls
│   │   ├── log/              # JSONL parse/serialize/validate
│   │   ├── operation/        # Create/Update/Deactivate logic
│   │   ├── resolve/          # DidResolver, LogBasedResolver, HttpResolver
│   │   ├── witness/          # Witness support
│   │   └── exception/        # Typed exception hierarchy
│   └── src/test/java/io/didwebvh/
│       └── support/          # Shared test helpers (Ed25519TestFixture)
└── .cursor/
    ├── notes/                # This knowledge base
    └── rules/                # Cursor AI rules
```

## Notes Files

### Top-level

- [Architecture](./architecture.md) — Protocol overview (what did:webvh is, the log chain, SCID, Data Integrity) + full Java library architecture (packages, design decisions, dependencies)

### `knowledge/` — Detailed Reference

- [did:webvh Spec](./knowledge/did-webvh-spec.md) — Full spec reference: DID format, log structure, all cryptographic operations, all DID operations, optional features (pre-rotation, witnesses, portability, watchers), security/privacy considerations, existing implementations
- [Crypto Primitives](./knowledge/crypto-primitives.md) — `JcsCanonicalizer` (RFC 8785 / JCS four rules), `Multiformats` (SHA-256 multihash, base58btc, multikey), `DataIntegrity` (eddsa-jcs-2022 signing flow), `DidLogEntry` helpers; implementation notes and library choices
- [Research Context](./knowledge/research-context.md) — X.509 PKI vs. DID layer comparison; KERI/did:keri concepts and comparison table with did:webvh; thesis relevance
