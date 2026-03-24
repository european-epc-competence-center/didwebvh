# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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

