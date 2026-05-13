# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-13

### Added

- **DID resolution**: resolve `didweb:vh` identifiers over HTTPS with cryptographic verification
- **DID operations**: create, update, and deactivate DIDs via signed log entries
- **Cryptographic verification**: Ed25519 signature validation with built-in Bouncy Castle support
- **Log validation**: verify the complete chain of DID operations including version history, key rotation, and proof integrity
- **Customizable components**: inject custom HTTP clients and verifiers for testing and advanced use cases
- **Complete type safety**: full model definitions for DID documents, operations, and cryptographic proofs
