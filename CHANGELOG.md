# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

- `DidWebImporter.toWebVhDocument(document, scid)` for dual-publish updates

### Fixed

- reject create/update documents whose `id` is not the DID (or a valid portable rename)
- portable renames must keep the `did:webvh` method and the same SCID


## [0.3.1] - 2026-05-28

### Fixed

- stricter DID URL validation


## [0.3.0] - 2026-05-22

### Changed

- path dereferencing now enforces HTTPS-only for service endpoints

### Added

- import an existing `did:web` document into a `did:webvh` via `DidWebImporter`
- add support for parallel `did:web` publishing via `DidWebPublisher`


## [0.2.1] - 2026-05-19

### Added

- domain migration is supported by UpdateOptions now
- checking for alsoKnownAs parameter after domain migration

## [0.2.0] - 2026-05-13

### Changed

- minimum required Java version raised from 17 to 21

## [0.1.0] - 2026-05-13

### Added

- **DID resolution**: resolve `did:webvh` identifiers over HTTPS with cryptographic verification
- **DID operations**: create, update, and deactivate DIDs via signed log entries
- **Cryptographic verification**: Ed25519 signature validation with built-in Bouncy Castle support
- **Log validation**: verify the complete chain of DID operations including version history, key rotation, and proof integrity
- **Customizable components**: inject custom HTTP clients and verifiers for testing and advanced use cases
- **Complete type safety**: full model definitions for DID documents, operations, and cryptographic proofs
