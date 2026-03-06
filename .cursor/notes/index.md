# Notes Index

## Project Overview

Bachelor thesis project: security analysis of `did:webvh` (DID method combining `did:web` with verifiable hash-chained history).

- **Thesis topic**: STRIDE-based security analysis of `did:webvh` vs. `did:web`
- **Practical component**: Java library implementing `did:webvh` (log chaining, key rotation, Data Integrity Proofs)

## Folder Structure

```
/
├── docs/application.md     # Thesis application document (motivation, research question, approach)
├── README.md
├── CHANGELOG.md
└── .cursor/
    ├── notes/              # This knowledge base
    └── rules/              # Cursor AI rules
```

## Notes Files

- [SSI / DID Layer vs. X.509 PKI](./ssi-did-vs-x509.md) — Comparison of DID indirection layer vs. X.509 certificate model; key advantages (key rotation, no CA, hash chaining in did:webvh)
- [did:webvh spec](./did-webvh-spec.md) — Full spec summary: DID format, log structure, cryptographic operations, all DID operations, optional features, security/privacy considerations, existing implementations
- [KERI](./keri.md) — KERI (Key Event Receipt Infrastructure): AID, KEL, KERL, pre-rotation, trust modalities, did:keri method, and comparison table with did:webvh including research relevance
