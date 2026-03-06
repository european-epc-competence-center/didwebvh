# Project Notes Index

## Project Summary

Java library implementing the `did:webvh` DID method (DID Web + Verifiable History, v1.0).
- Spec source: `/spec/spec-v1.0/` (local) and https://identity.foundation/didwebvh/v1.0/
- No Java implementation exists yet; this project fills that gap.
- Typical implementation size: ~1500–2000 lines of code.

## Repository Structure

```
/
├── LICENSE
├── README.md
├── CHANGELOG.md
├── spec/                   ← did:webvh spec source files
│   ├── spec-v1.0/          ← v1.0 spec (abstract, overview, specification, definitions,
│   │                          security_and_privacy, references, version, header)
│   ├── spec-v0.3/ .. v0.5/ ← previous versions
│   ├── schemas/v1.0/       ← log_entry.json (JSON Schema for log entries)
│   └── watcherOpenAPI/     ← watcher-v1.0.0.yml (OpenAPI spec for watcher HTTP API)
└── .cursor/
    ├── notes/              ← AI knowledge base (this folder)
    └── rules/              ← Cursor AI rules
```

> Note: Java source structure (e.g. Maven/Gradle layout) not yet established.

## Notes Files

- [did-webvh-spec.md](./did-webvh-spec.md) — Comprehensive spec summary based on local `/spec/spec-v1.0/`: DID format (ABNF), DID-to-HTTPS transformation (incl. internationalized domains), log file structure and JSON schema, all parameters with defaults, cryptographic operations (SCID, entry hash, Data Integrity proofs, pre-rotation hashes), all DID operations (create/resolve/update/deactivate) with step-by-step algorithms, authorized key rules, optional features (witnesses, pre-rotation, portability, watchers, /whois, parallel did:web), resolution metadata, error codes, security and privacy considerations, and existing implementations.
