# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `JcsCanonicalizerTest`: optional before/after JSON lines (Jackson compact vs RFC 8785) when run with `-Djcs.test.verbose=true`
- `JcsCanonicalizer`: implemented RFC 8785 JCS canonicalization using `io.github.erdtman:java-json-canonicalization:1.1` (RFC Appendix G reference implementation); added 10 tests including the exact RFC §3.2.4 byte-vector test
- README: GitHub Actions CI status badge (links to workflow runs) and overview line for `.github/workflows/`

### Changed

- `JcsCanonicalizerTest`: simpler cases use `ObjectNode` / `ArrayNode`; RFC §3.2.4 vector uses literal JSON + `readTree` (wire path); document why `JsonNode#toString()` is not used for wire JSON
- `update` and `deactivate` now take a single options object; `DidLog` moved inside `UpdateOptions` and `DeactivateOptions`
  - `DidWebVh.update(DidLog, UpdateOptions)` → `DidWebVh.update(UpdateOptions)` (log via `UpdateOptions.builder().log(...)`)
  - `DidWebVh.deactivate(DidLog, DeactivateOptions)` → `DidWebVh.deactivate(DeactivateOptions)` (log via `DeactivateOptions.builder().log(...)`)
- Redesigned public API of `didwebvh-java` so `Parameters` is internal-only (never in a public method signature)
  - `CreateOptions` now bundles all creation inputs: `domain`, `initialDocument`, `updateKeys`, `signer`, `portable`, `nextKeyHashes`, `witness`, `watchers`
  - `UpdateOptions` now bundles all update inputs: `log`, `updatedDocument`, `signer`, and optional `updateKeys`, `nextKeyHashes`, `witness`, `watchers`, `witnessProofs`
  - `DeactivateOptions` now holds `log` and `signer`
  - `ResolveOptions` now holds `verifier` alongside the optional version filters (`versionId`, `versionTime`, `versionNumber`)
  - `DidWebVh` facade reduced to four methods: `create(CreateOptions)`, `resolve(String, ResolveOptions)`, `update(UpdateOptions)`, `deactivate(DeactivateOptions)`
  - Removed `resolveFromLog` from the public facade; `LogBasedResolver.resolveFromLog` remains available for advanced use

### Fixed

- `JcsCanonicalizer`: removed debug `System.out.println` of intermediate JSON from production code
- Corrected license declaration in `didwebvh-java/pom.xml` from Apache 2.0 to GNU GPL v3.0 to match the root `LICENSE` file

### Added

- Java library scaffold: `didwebvh-java/` Maven project (`io.didwebvh:didwebvh-java:0.1.0-SNAPSHOT`, Java 21)
  - Package structure: `api/`, `model/`, `crypto/`, `log/`, `operation/`, `resolve/`, `witness/`, `exception/`
  - Public facade `DidWebVh` with `create`, `resolve`, `resolveFromLog`, `update`, `deactivate` entry points
  - All data models: `DidLog`, `DidLogEntry`, `Parameters`, `ResolutionMetadata`, `DataIntegrityProof`, `WitnessParameter`
  - Crypto interfaces (`Signer`, `Verifier`) and stubs (`Ed25519Signer`, `DataIntegrity`, `Multiformats`, `JcsCanonicalizer`)
  - CRUD operation stubs: `CreateOperation`, `UpdateOperation`, `DeactivateOperation`
  - Resolution stubs: `LogBasedResolver`, `HttpResolver`, `DidUrlTransformer`
  - Witness stubs: `WitnessProofCollection`, `WitnessValidator`
  - Typed exception hierarchy: `DidWebVhException`, `InvalidDidException`, `ResolutionException`, `LogValidationException`
  - Cross-cutting constants: `DidWebVhConstants`
  - Architecture notes: `.cursor/notes/java-library.md`
- Initial project setup: `README.md`, `CHANGELOG.md`
- `.cursor/notes` knowledge base with `did:webvh` specification research
- Extended `docs/application.md` section 1.1 with paragraph on DID layer advantages over X.509/PKI
- Added KERI research notes (`.cursor/notes/keri.md`): KEL, pre-rotation, did:keri, comparison with `did:webvh`
- Extended `docs/application.md` section 2.1 with KERI as related research topic and design comparison
- Extended `docs/application.md` section 1.2 with two additional research questions: key compromise scenarios and implementation correctness

