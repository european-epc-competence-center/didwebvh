# Project Knowledge Index

Bachelor thesis project: security analysis of `did:webvh` (DID Web + Verifiable History) plus a Java reference implementation.

- **Thesis topic**: STRIDE-based security analysis of `did:webvh` vs. `did:web`
- **Practical component**: Java library implementing `did:webvh` v1.0

## Repository Layout

```
/
├── .github/workflows/ci.yml   # GitHub Actions: mvn verify on push to main
├── docs/
│   ├── AGENTS.md              # Conventions for AI agents working here
│   ├── application.md         # Thesis application (motivation, research question)
│   ├── index.md               # This file
│   ├── library.md             # Java library architecture & design decisions
│   ├── protocol.md            # did:webvh essentials for implementers
│   └── work.md                # Open work packages & known gaps
├── didwebvh-java/             # Java library (Maven, Java 21)
├── spec/                      # did:webvh specification v1.0 source files
├── README.md
└── CHANGELOG.md
```

## Where to Find What

| Topic | File |
|---|---|
| Agent style guide (changelog, safety, notes hygiene) | [`AGENTS.md`](./AGENTS.md) |
| Java package structure, key classes, dependencies | [`library.md`](./library.md) |
| DID format, crypto pipeline, pre-rotation, validation rules | [`protocol.md`](./protocol.md) |
| Remaining implementation gaps & future ideas | [`work.md`](./work.md) |
| Full specification | [`spec/`](../spec/) |
| Thesis application (German/English) | [`application.md`](./application.md) |
