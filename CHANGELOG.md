# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `CreateOperation`: genesis log entry creation following spec §6.1 (SCID generation, entry hash, Data Integrity proof, placeholder replacement)
- `UpdateOperation`: append a signed update entry to the log (document changes; optional `updateKeys` / `nextKeyHashes` / witness / watchers inherited from the previous entry when omitted); exposed as `DidWebVh#update`
- `LogValidator`: full-chain validation of a `DidLog` (SCID derivation on genesis, `versionId` hash chain, monotonic version and time, `eddsa-jcs-2022` proofs against active `updateKeys`, parameter transition rules, pre-rotation)
- `DeactivateOperation`: append a deactivation entry so resolvers treat the DID as deactivated; exposed as `DidWebVh#deactivate`
- `LogSerializer` / `LogParser`: JSONL serialization and deserialization of `did.jsonl`
- `DataIntegrity`: `eddsa-jcs-2022` proof creation and verification (W3C Data Integrity spec)
- `Multiformats`: base58btc multibase decoding/encoding and SHA-256 multihash, centralized Ed25519 multikey decoding/encoding
- `JcsCanonicalizer`: RFC 8785 JCS canonicalization
- Java library scaffold (`didwebvh-java/`): package structure, public API facade, all data models, crypto interfaces, operation/resolution/witness stubs, typed exception hierarchy
