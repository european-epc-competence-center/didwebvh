# Java Library Architecture

## Installation

**Requirements:** Java 21+, Maven 3.9+

The library is published to Maven Central:  
https://central.sonatype.com/artifact/de.eecc.did/webvh

Add the dependency to your `pom.xml`:

```xml
<dependency>
  <groupId>de.eecc.did</groupId>
  <artifactId>webvh</artifactId>
  <version>0.3.0</version>
</dependency>
```

## Package Structure

```
de.eecc.did.webvh/
├── DidWebVhConstants.java     ← cross-cutting constants
├── DidDocument.java           ← immutable POJO wrapping the DID doc; hides Jackson from the public API
│                                (+ DidDocumentSerializer / DidDocumentDeserializer)
├── api/                       ← public facade — sole entry point for consumers
├── model/                     ← immutable records mirroring spec JSON
│   └── proof/
├── crypto/                    ← crypto interfaces + low-level primitives
├── didweb/                    ← did:web interop (import existing did:web + parallel publish)
├── log/                       ← JSONL parse / serialize / chain-validate
├── operation/                 ← create / update / deactivate (no I/O)
├── resolve/                   ← resolver interface + impls (log-based + HTTP) + DID-URL dereferencing
├── util/                      ← shared, pre-configured Jackson ObjectMapper
├── witness/                   ← optional witness support
└── exception/                 ← typed exception hierarchy
```

## Key Dependencies

| Dependency | Purpose |
|---|---|
| `jackson-databind` | JSON (de)serialization; backs the `DidDocument` wrapper (internal only) |
| `bouncycastle:bcprov-jdk18on` | Ed25519 signing/verification |
| `java-json-canonicalization` | RFC 8785 JCS (reference implementation) |
| `slf4j-api` | Logging interface (no impl forced on consumers) |
| `Base58Btc` (local) | Package-private base58btc encode/decode |
| `MessageDigest` (JDK) | SHA-256 |

## Package Details

### Top-level
- `DidWebVhConstants` — method prefix, SCID placeholder, method version, cross-cutting constants
- `DidDocument` — immutable POJO wrapper around the DID document; the type used throughout the public API so consumers never touch Jackson. Mutation via a nested `Builder`; `toJson()` / `fromJson()` bridge to/from raw JSON. Backed by `DidDocumentSerializer` / `DidDocumentDeserializer`

### `api/` — Public Entry Point
- `DidWebVh` — five static methods: `create`, `resolve`, `resolveFromLog`, `update`, `deactivate`
- `CreateOptions`, `UpdateOptions`, `DeactivateOptions`, `ResolveOptions` — builder-style option objects. `UpdateOptions.domain(...)` triggers a portable domain migration (rewrites `id`/`controller`, appends old DID to `alsoKnownAs`)
- `CreateResult`, `UpdateResult`, `DeactivateResult`, `ResolveResult` — immutable result records (`DidDocument` + `DidDocumentMetadata`)

### `model/` — Immutable Java Records
- `DidLog` — `List<DidLogEntry>` wrapper
- `DidLogEntry` — `versionId`, `versionTime`, `parameters`, `state` (as `DidDocument`), `proof`
- `Parameters` — all spec parameters; contains `validate(prev)` and `diff(prev)` (core spec logic)
- `WitnessParameter` — witness config (threshold + witness DIDs)
- `DidDocumentMetadata` — `didDocumentMetadata` per W3C DID Resolution (versionId/number/time, created, updated, scid, portable, deactivated, ttl, witness, watchers)
- `ResolutionMetadata` — `didResolutionMetadata` (contentType, did, driver, `error` as W3C `ProblemDetails`)
- `proof/DataIntegrityProof` — DI proof fields

### `crypto/` — Crypto Boundary
- `Signer` / `Verifier` interfaces — caller-supplied crypto
- `DefaultVerifier` — built-in `eddsa-jcs-2022` verifier (Bouncy Castle Ed25519); used when the caller supplies no custom `Verifier`
- `Multiformats` — raw base58btc + multibase encode/decode, multihash, Ed25519 multikey
- `JcsCanonicalizer` — RFC 8785 via erdtman library + Jackson bridge
- `DataIntegrity` — create and verify `eddsa-jcs-2022` proofs

### `didweb/` — `did:web` Interoperability (no I/O)
- `DidWebImporter` — converts an existing `did:web` document into a `did:webvh` genesis document (rewrites the document's own DID to the `{SCID}` placeholder, records the original in `alsoKnownAs`); ready for `DidWebVh.create`. `domainOf(...)` extracts the `CreateOptions.domain` value
- `DidWebPublisher` — generates the parallel `did:web` document (spec §3.7.10) from a resolved `did:webvh` doc: injects implicit services, text-replaces `did:webvh:<scid>:` → `did:web:`, reconciles `alsoKnownAs`. Caller publishes the result as `did.json`

### `log/` — JSONL & Chain Validation
- `LogParser` — JSONL string → `DidLog`
- `LogSerializer` — `DidLog` → JSONL string
- `LogValidator` — full chain: SCID check, entry hash chain, proof verification, parameter rules

### `operation/` — Pure Business Logic
- `CreateOperation`, `UpdateOperation`, `DeactivateOperation`
- `OperationSupport` (package-private) — effective `Parameters` from a `DidLog`; signer authorization vs active `updateKeys` / `nextKeyHashes`

### `resolve/`
- `DidResolver` interface — network-facing contract
- `LogFetcher` — injectable `@FunctionalInterface` for HTTP I/O
- `LogBasedResolver` — core resolution engine; validates entry-by-entry, applies version filters, witness gating, builds `ResolutionMetadata`
- `HttpResolver implements DidResolver` — URL transform → fetch log → auto-fetch `did-witness.json` → delegate to `LogBasedResolver`
- `DidUrlTransformer` — DID → HTTPS URL (IDNA, percent-encoding, `.well-known` fallback); `extractScid(...)`
- `ImplicitServiceInjector` — injects the implicit `#files` and `#whois` services into a resolved document
- `DidUrlPathResolver` — resolves a DID URL path to a concrete HTTPS URL via the `#whois` / `#files` services (HTTPS-enforced)
- `FragmentDereferencer` — dereferences a `#fragment` against the resolved document's verification methods and services

### `util/`
- `JsonMapper` — single shared, pre-configured (`NON_NULL`) Jackson `ObjectMapper` used for all parsing, signing, and hashing

### `witness/`
- `WitnessProofCollection` — model for `did-witness.json`
- `WitnessEpoch` — a contiguous run of log entries governed by one witness config (`config`, `firstVersion`, `lastVersion`); built by `LogBasedResolver.buildWitnessEpochs`
- `WitnessValidator` — validates DI proofs against `did:key` witness DIDs, threshold check, watermark frontier

### `exception/`
- `DidWebVhException` (base)
- `InvalidDidException` → `invalidDid`
- `LogValidationException` → `invalidDid`
- `DidNotFoundException` → `notFound`

## Design Decisions

1. **`DidLog` is source of truth** — mutations return a new `DidLog`; caller persists (no file I/O in core)
2. **Caller-supplied crypto** — `Signer`/`Verifier` interfaces; no built-in key provider or signer. A built-in `DefaultVerifier` is used for resolution when no custom `Verifier` is given
3. **`Parameters` is internal** — never in public API signatures; assembled by operations from options objects
4. **`Parameters.validate()` + `Parameters.diff()`** — encode the bulk of spec rules (pre-rotation, portable immutability, deactivation)
5. **v1.0 only** — no spec version dispatch; add `method_versions/` subpackage later if needed
6. **`HttpResolver` in `resolve/`** — same module; extract to separate Maven artifact if publishing to Maven Central
7. **Two-phase resolution** — chain validation (`LogValidator`) and witness validation (`WitnessValidator`) are separate phases
8. **`DidDocument` wrapper at the API boundary** — the public API exposes the immutable `DidDocument` POJO, not Jackson's `JsonNode`; consumers depend only on the library, not on a Jackson version
