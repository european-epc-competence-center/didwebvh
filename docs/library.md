# Java Library Architecture

**Location:** `didwebvh-java/` (Maven, Java 21 LTS)

```xml
<groupId>io.didwebvh</groupId>
<artifactId>didwebvh-java</artifactId>
<version>0.1.0-SNAPSHOT</version>
```

## Package Structure

```
io.didwebvh/
├── DidWebVhConstants.java     ← cross-cutting constants
├── api/                       ← public facade — sole entry point for consumers
├── model/                     ← immutable records mirroring spec JSON
│   └── proof/
├── crypto/                    ← crypto interfaces + low-level primitives
├── log/                       ← JSONL parse / serialize / chain-validate
├── operation/                 ← create / update / deactivate (no I/O)
├── resolve/                   ← resolver interface + impls (log-based + HTTP)
├── witness/                   ← optional witness support
└── exception/                 ← typed exception hierarchy
```

## Key Dependencies

| Dependency | Purpose |
|---|---|
| `jackson-databind` | JSON (de)serialization, `JsonNode` for DID docs |
| `bouncycastle:bcprov-jdk18on` | Ed25519 signing/verification |
| `java-json-canonicalization` | RFC 8785 JCS (reference implementation) |
| `slf4j-api` | Logging interface (no impl forced on consumers) |
| `Base58Btc` (local) | Package-private base58btc encode/decode |
| `MessageDigest` (JDK) | SHA-256 |

## Package Details

### `api/` — Public Entry Point
- `DidWebVh` — five static methods: `create`, `resolve`, `resolveFromLog`, `update`, `deactivate`
- `CreateOptions`, `UpdateOptions`, `DeactivateOptions`, `ResolveOptions` — builder-style option objects
- `CreateResult`, `UpdateResult`, `DeactivateResult`, `ResolveResult` — immutable result records

### `model/` — Immutable Java Records
- `DidLog` — `List<DidLogEntry>` wrapper
- `DidLogEntry` — `versionId`, `versionTime`, `parameters`, `state` (as `JsonNode`), `proof`
- `Parameters` — all spec parameters; contains `validate(prev)` and `diff(prev)` (core spec logic)
- `WitnessParameter` — witness config (threshold + witness DIDs)
- `ResolutionMetadata` — all resolution output metadata
- `proof/DataIntegrityProof` — DI proof fields

### `crypto/` — Crypto Boundary
- `Signer` / `Verifier` interfaces — caller-supplied crypto
- `Multiformats` — raw base58btc + multibase encode/decode, multihash, Ed25519 multikey
- `JcsCanonicalizer` — RFC 8785 via erdtman library + Jackson bridge
- `DataIntegrity` — create and verify `eddsa-jcs-2022` proofs

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
- `DidUrlTransformer` — DID → HTTPS URL (IDNA, percent-encoding, `.well-known` fallback)

### `witness/`
- `WitnessProofCollection` — model for `did-witness.json`
- `WitnessValidator` — validates DI proofs against `did:key` witness DIDs, threshold check, watermark frontier

### `exception/`
- `DidWebVhException` (base)
- `InvalidDidException` → `invalidDid`
- `LogValidationException` → `invalidDid`
- `DidNotFoundException` → `notFound`

## Design Decisions

1. **`DidLog` is source of truth** — mutations return a new `DidLog`; caller persists (no file I/O in core)
2. **Caller-supplied crypto** — `Signer`/`Verifier` interfaces only; no built-in key provider
3. **`Parameters` is internal** — never in public API signatures; assembled by operations from options objects
4. **`Parameters.validate()` + `Parameters.diff()`** — encode the bulk of spec rules (pre-rotation, portable immutability, deactivation)
5. **v1.0 only** — no spec version dispatch; add `method_versions/` subpackage later if needed
6. **`HttpResolver` in `resolve/`** — same module; extract to separate Maven artifact if publishing to Maven Central
7. **Two-phase resolution** — chain validation (`LogValidator`) and witness validation (`WitnessValidator`) are separate phases
