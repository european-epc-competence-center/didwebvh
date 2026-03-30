# Architecture

## What is did:webvh?

`did:webvh` (DID Web + Verifiable History) is a W3C DID method that enhances `did:web` by adding a cryptographically verifiable, tamper-evident history — without a blockchain. Instead of a single `did.json` file, the controller publishes a `did.jsonl` (JSON Lines) file where each line is a signed log entry chained to the previous one via entry hashes.

Key properties:
- **Self-certifying identifier (SCID)**: derived from the hash of the first log entry — binds the DID to its history
- **Hash chain**: each entry's `versionId` contains a hash of the previous entry (microledger)
- **Data Integrity Proofs**: every entry is signed with `eddsa-jcs-2022` by the controller's `updateKeys`
- **Optional pre-rotation**: next key hashes committed in advance, preventing unauthorized rotation
- **Optional witnesses**: threshold of `did:key` witnesses must co-sign entries before publishing

## Protocol Flow

```
Create:  preliminary entry → SCID → entryHash → proof → publish did.jsonl
Update:  modified DIDDoc → new entry → entryHash → proof → append to did.jsonl
Resolve: GET did.jsonl → verify chain (SCID, hashes, proofs, params) → return DIDDoc
```

Detailed spec: [`knowledge/did-webvh-spec.md`](./knowledge/did-webvh-spec.md)

---

## Java Library

**Location:** `didwebvh-java/` (Maven, Java 21 LTS)

```xml
<groupId>io.didwebvh</groupId>
<artifactId>didwebvh-java</artifactId>
<version>0.1.0-SNAPSHOT</version>
```

### Package Structure

```
io.didwebvh/
├── DidWebVhConstants.java        ← cross-cutting constants (SCID_PLACEHOLDER, METHOD_V1_0, CRYPTOSUITE, …)
├── api/                          ← public facade — sole entry point for consumers
├── model/                        ← immutable records mirroring spec JSON
│   └── proof/
├── crypto/                       ← crypto interfaces + low-level primitives
├── log/                          ← JSONL parse / serialize / chain-validate
├── operation/                    ← create / update / deactivate (no I/O)
├── resolve/                      ← resolver interface + impls (log-based + HTTP)
├── witness/                      ← optional witness support
└── exception/                    ← typed exception hierarchy
```

### Key Dependencies

| Dependency | Purpose |
|---|---|
| `com.fasterxml.jackson.core:jackson-databind` | JSON (de)serialization, `JsonNode` for DID docs |
| `org.bouncycastle:bcprov-jdk18on` | Ed25519 signing/verification |
| `io.github.erdtman:java-json-canonicalization` | RFC 8785 JCS (RFC reference implementation) |
| `com.github.multiformats:java-multibase` (JitPack) | Multibase base58btc (`z…`) |
| `java.security.MessageDigest` | SHA-256 (JDK, no artifact) |
| `org.slf4j:slf4j-api` | Logging interface (no impl forced on consumers) |

### Package Details

**`api/`** — Public entry point. Consumers only need this package.
- `DidWebVh` — four static methods: `create`, `resolve`, `update`, `deactivate`
- `CreateOptions`, `UpdateOptions`, `DeactivateOptions`, `ResolveOptions` — builder-style option objects
- `CreateResult`, `UpdateResult`, `DeactivateResult`, `ResolveResult` — immutable result records

**`model/`** — Immutable Java records mirroring spec JSON.
- `DidLog` — `List<DidLogEntry>` wrapper
- `DidLogEntry` — `versionId`, `versionTime`, `parameters`, `state` (as `JsonNode`), `proof`
- `Parameters` — all spec parameters; contains `validate(prev)` and `diff(prev)` (core spec logic)
- `WitnessParameter` — witness config (threshold + witness DIDs)
- `ResolutionMetadata` — all resolution output metadata
- `proof/DataIntegrityProof` — DI proof fields

**`crypto/`** — Crypto boundary. Callers supply their own `Signer`/`Verifier`.
- `Signer` / `Verifier` interfaces — `sign(byte[])→byte[]`, `verify(sig, msg, publicKeyMultibase)→boolean`
- `Multiformats` — multibase encode/decode, multihash (SHA-256 prefix `0x1220`)
- `JcsCanonicalizer` — RFC 8785 via erdtman library + Jackson `JsonNode` bridge
- `DataIntegrity` — create and verify `eddsa-jcs-2022` proofs; calls through `Signer`/`Verifier`

**`log/`** — JSONL handling and chain validation.
- `LogParser` — JSONL string → `DidLog`
- `LogSerializer` — `DidLog` → JSONL string
- `LogValidator` — full chain: SCID check, entry hash chain, proof verification, parameter rules

**`operation/`** — Pure business logic, no I/O. All return an updated `DidLog`; caller persists.
- `CreateOperation`, `UpdateOperation`, `DeactivateOperation`

**`resolve/`**
- `DidResolver` interface
- `LogBasedResolver` — resolves from in-memory `DidLog`, no network
- `HttpResolver` — `java.net.http.HttpClient` GET `did.jsonl`, delegates to `LogBasedResolver`
- `DidUrlTransformer` — DID → HTTPS URL (IDNA normalization, percent-encoding, `.well-known` fallback)

**`witness/`** — Optional spec feature, isolated.
- `WitnessProofCollection` — model for `did-witness.json`
- `WitnessValidator` — threshold check, witness proof signature verification

**`exception/`** — Maps to spec error codes (`notFound`, `invalidDid`).
- `DidWebVhException` (base), `InvalidDidException`, `ResolutionException`, `LogValidationException`

### Key Design Decisions

1. **`DidLog` is source of truth** — mutations return a new `DidLog`; caller persists (no file I/O in core)
2. **Caller-supplied crypto** — `Signer`/`Verifier` interfaces only; no built-in key provider
3. **`Parameters` is internal** — never in public API signatures; assembled by operations from options objects
4. **`Parameters.validate()` + `Parameters.diff()`** — encode the bulk of spec rules (pre-rotation, portable immutability, deactivation); used by operations and `LogValidator`
5. **v1.0 only** — no spec version dispatch; add `method_versions/` subpackage later if needed
6. **`HttpResolver` in `resolve/`** — same module; extract to separate Maven artifact if publishing to Maven Central
