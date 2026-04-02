# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `LogSerializer` / `LogParser`: JSONL serialization and deserialization of `did.jsonl`
- `DataIntegrity`: `eddsa-jcs-2022` proof creation and verification (W3C Data Integrity spec)
- `Multiformats`: base58btc multibase encoding and SHA-256 multihash
- `JcsCanonicalizer`: RFC 8785 JCS canonicalization
- Java library scaffold (`didwebvh-java/`): package structure, public API facade, all data models, crypto interfaces, operation/resolution/witness stubs, typed exception hierarchy

### Changed

- Public API refactored: `Parameters` is now internal; all inputs bundled into `*Options` objects
- `update` and `deactivate` take a single options object (log moved into options)

### Fixed

- Corrected license in `pom.xml` from Apache 2.0 to GNU GPL v3.0
