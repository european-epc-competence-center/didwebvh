# Java Library — did:webvh

## Location

`/home/yannik/git/didwebvh/didwebvh-java/` — Maven project at repo root, separate from spec files.

## Maven Coordinates

```xml
<groupId>io.didwebvh</groupId>
<artifactId>didwebvh-java</artifactId>
<version>0.1.0-SNAPSHOT</version>
```

Java 21 LTS. Single module (no multi-module split).

## Key Dependencies

| Dependency | Purpose |
|---|---|
| `com.fasterxml.jackson.core:jackson-databind` | JSON (de)serialization, `JsonNode` for DID docs |
| `org.bouncycastle:bcprov-jdk18on` | Ed25519 signing/verification, SHA-256 |
| *(no external dep)* | JCS (RFC8785) implemented directly with Jackson in `JcsCanonicalizer` |
| `org.slf4j:slf4j-api` | Logging interface (no impl forced on consumers) |
| `org.junit.jupiter:junit-jupiter` | Tests |
| `org.assertj:assertj-core` | Fluent test assertions |

## Root Package

`io.didwebvh`

`DidWebVhConstants.java` at the root package holds cross-cutting constants: `SCID_PLACEHOLDER = "{SCID}"`, `METHOD_V1_0 = "did:webvh:1.0"`, `CRYPTOSUITE = "eddsa-jcs-2022"`, etc.

## Package Structure

```
io.didwebvh/
├── DidWebVhConstants.java        ← cross-cutting constants
├── api/                          ← public facade (sole entry point for consumers)
├── model/                        ← immutable data types
│   └── proof/
├── crypto/                       ← crypto interfaces + Bouncy Castle impl
├── log/                          ← JSONL parse / serialize / chain-validate
├── operation/                    ← create / update / deactivate (no I/O)
├── resolve/                      ← resolver interface + impls (log-based + HTTP)
├── witness/                      ← optional witness support
└── exception/                    ← typed exception hierarchy
```

## Package Details

### `api/`
Public entry point. Consumers only need this package.
- `DidWebVh.java` — four static methods: `create(CreateOptions)`, `resolve(String did, ResolveOptions)`, `update(DidLog, UpdateOptions)`, `deactivate(DidLog, DeactivateOptions)`
- `CreateOptions` — bundles `domain`, `initialDocument`, `updateKeys`, `signer`, `portable`, `nextKeyHashes`, `witness`, `watchers`
- `UpdateOptions` — bundles `updatedDocument`, `signer`, and optional `updateKeys`, `nextKeyHashes`, `witness`, `watchers`, `witnessProofs`
- `DeactivateOptions` — bundles `signer`; kept as named class for extensibility
- `ResolveOptions` — bundles `verifier` (required) plus optional version filters: `versionId`, `versionTime`, `versionNumber`
- `CreateResult` / `UpdateResult` / `ResolveResult` / `DeactivateResult` — immutable records

### `model/`
Immutable Java records mirroring the spec's JSON structure.
- `DidLog` — `List<DidLogEntry>` wrapper
- `DidLogEntry` — `versionId`, `versionTime`, `parameters`, `state` (as `JsonNode`), `proof`
- `Parameters` — all spec parameters; contains `validate(prev)` and `diff(prev)` (core spec logic)
- `ResolutionMetadata` — all resolution output metadata
- `proof/DataIntegrityProof` — DI proof fields

### `crypto/`
Defines the crypto boundary. Callers supply their own `Signer`/`Verifier` implementations — no built-in key provider.
- `Signer` interface — `sign(byte[]) -> byte[]`
- `Verifier` interface — `verify(byte[] sig, byte[] msg, String publicKeyMultibase) -> boolean`
- `Multiformats` — multibase encode/decode, multihash (SHA-256 prefix `0x1220`)
- `JcsCanonicalizer` — RFC8785 canonicalization implemented with Jackson (no external dep)
- `DataIntegrity` — create and verify `eddsa-jcs-2022` Data Integrity proofs; calls through `Signer`/`Verifier`

### `log/`
JSONL handling and chain validation. Mirrors TS's `assertions.ts` + utils log handling.
- `LogParser` — JSONL string → `DidLog`
- `LogSerializer` — `DidLog` → JSONL string
- `LogValidator` — full chain: SCID check, entry hash chain, proof verification, parameter rules
  - Calls `crypto/DataIntegrity` per entry; calls `Parameters.validate()` at each step

### `operation/`
Pure business logic — no I/O. All methods return updated `DidLog` (caller persists).
Mirrors TS `method_versions/method.v1.0.ts` (mutation side).
- `CreateOperation` — SCID placeholder flow → hash → SCID → `versionId` → sign
- `UpdateOperation` — append-only entry, `Parameters.diff`, sign
- `DeactivateOperation` — new entry with `deactivated: true`, `updateKeys: []`

### `resolve/`
Mirrors TS's `resolveDID` vs `resolveDIDFromLog` separation.
- `DidResolver` interface — `resolve(String did, ResolveOptions) -> ResolveResult`
- `LogBasedResolver` — resolves from in-memory `DidLog`, no network
- `HttpResolver` — `java.net.http.HttpClient` GET `did.jsonl` + optional `did-witness.json`, delegates to `LogBasedResolver`
- `DidUrlTransformer` — DID → HTTPS URL: IDNA normalization, percent-encoding, `.well-known` fallback

### `witness/`
Optional spec feature; isolated so it doesn't complicate the main flow.
- `WitnessProofCollection` — model for `did-witness.json`
- `WitnessValidator` — validate threshold, verify witness proof signatures

### `exception/`
Typed exception hierarchy; maps to spec error codes (`notFound`, `invalidDid`).
- `DidWebVhException` — base, holds spec error code + optional `ProblemDetails`
- `InvalidDidException`
- `ResolutionException`
- `LogValidationException`

## Key Design Decisions

1. **`DidLog` is source of truth** — mutations return a new `DidLog`; the caller persists (no file I/O in core)
2. **Caller-supplied crypto** — `Signer`/`Verifier` are interfaces only; no built-in key provider is shipped
3. **`Parameters` is internal** — never appears in public API signatures; assembled by operations from the options objects
4. **`Parameters.validate()` + `Parameters.diff()`** — encode the bulk of spec rules (pre-rotation, portable immutability, deactivation); used internally by operations and `LogValidator`
5. **v1.0 only** — no spec version dispatch for now; add `method_versions/` subpackage later if needed
6. **`HttpResolver` in `resolve/`** — same module; extract to a separate module if publishing to Maven Central later becomes a goal
