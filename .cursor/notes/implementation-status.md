# Implementation Status & Remaining Work

## Overall Rating: ~60% spec coverage

The **controller side** (create, update, deactivate) is solid and well-tested. The **resolver side** is unimplemented. Witness integration is stubbed.

## What's Done (Working & Tested)

| Area | Status | Notes |
|------|--------|-------|
| Crypto primitives (JCS, multiformats, DI proofs) | **Complete** | Thorough tests incl. RFC 8785 vectors |
| Models (DidLog, DidLogEntry, Parameters, proofs) | **Complete** | Immutable records, Jackson serialization |
| JSONL parse/serialize | **Complete** | Round-trip tested |
| Log chain validation (LogValidator) | **Complete** | SCID, entry hash, version number/time, DI proof vs updateKeys, pre-rotation |
| CreateOperation | **Complete** | Full genesis flow, SCID generation, placeholder replacement |
| UpdateOperation | **Complete** | Key rotation, pre-rotation, parameter delta |
| DeactivateOperation | **Complete** | Including pre-rotation guard |
| DID → HTTPS URL (DidUrlTransformer) | **Complete** | IDNA, port encoding, well-known path |
| Exception hierarchy | **Complete** | Maps to spec error codes |
| Public API facade (DidWebVh) | **Partial** | create/update/deactivate work; resolve is broken |

## What's NOT Done (Stubs / Missing)

### P0 — Core Spec Requirements

1. **`LogBasedResolver.resolveFromLog()`** — the core resolution engine
   - Validate log chain (delegate to LogValidator)
   - Apply version filters: `?versionId=`, `?versionTime=`, `?versionNumber=`
   - Build `ResolutionMetadata` from the validated log
   - Handle deactivated DIDs (no document returned, metadata flag)
   - Handle errors → `ResolveResult` with error metadata (not exceptions)
   - **Spec §6.2** — MUST support `versionId` and `versionTime`; SHOULD support `versionNumber`

2. **`HttpResolver.resolve()`** — HTTP fetch + delegation
   - Transform DID → URL (DidUrlTransformer — done)
   - HTTP GET `did.jsonl`
   - Parse response → `DidLog`
   - Delegate to `LogBasedResolver.resolveFromLog()`
   - **Testability done** — `LogFetcher` interface + constructor injection in `HttpResolver`; default fetcher uses `HttpClient`

3. **`WitnessValidator.validate()`** — witness proof verification
   - Verify witness proofs meet threshold
   - Verify each witness proof signature (they're `did:key` DIDs with `eddsa-jcs-2022`)
   - Integrate into `LogValidator` or `LogBasedResolver`

### P1 — Spec Compliance Gaps

4. **Witness proofs on update** — `UpdateOptions.witnessProofs` exists but `UpdateOperation` never reads it
5. **Witness file fetching** — `HttpResolver` should fetch `did-witness.json` when witnesses are configured
6. **`ResolutionMetadata` population** — metadata values should be strings per DID Resolution spec (threshold, ttl)
7. **DID URL path resolution** — implicit `#files` service (spec §6.5)
8. **`/whois` resolution** — implicit `#whois` service (spec §6.6)
9. **Parallel `did:web` publishing** — spec §6.7

### P2 — Nice-to-Have / Future

10. Watchers API integration
11. DNS-over-HTTPS (RFC 8484)
12. CORS header guidance
13. `did:web` parallel document generation
14. Method version dispatch (v0.5 compat like TS impl)

## Resolver Testability — Best Practice

### Recommended Java Approach

**Implemented:** `LogFetcher` interface + constructor injection in `HttpResolver`. See `resolve/LogFetcher.java` and `resolve/HttpResolver.java`.

Benefits:
- No mocking framework needed — use lambdas in tests
- `LogBasedResolver.resolveFromLog()` testable without HTTP at all
- `HttpResolver` testable with injected `LogFetcher` that returns canned JSONL
- Clean separation: fetch (I/O) vs validate (pure logic)

## Test Coverage Assessment

**Well-covered:** crypto, log parse/serialize/validate, create/update/deactivate operations, URL transformer
**Not covered at all:** `DidWebVh.resolve()`, `HttpResolver`, `LogBasedResolver`, `WitnessValidator`, `WitnessProofCollection`, `DidNotFoundException`, `DidWebVhException`

**No mocking frameworks** in use — all tests use real crypto (BouncyCastle). No `src/test/resources/` fixtures.
