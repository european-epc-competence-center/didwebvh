# Implementation Status & Remaining Work

## Overall Rating: ~80% spec coverage

All four DID operations (create, update, deactivate, resolve) are implemented and tested. Witness integration is stubbed.

## What's Done (Working & Tested)

| Area | Status | Notes |
|------|--------|-------|
| Crypto primitives (JCS, multiformats, DI proofs) | **Complete** | Thorough tests incl. RFC 8785 vectors |
| Models (DidLog, DidLogEntry, Parameters, proofs) | **Complete** | Immutable records, Jackson serialization |
| ResolutionMetadata | **Complete** | Record + Builder pattern + `error()` factory |
| JSONL parse/serialize | **Complete** | Round-trip tested |
| Log chain validation (LogValidator) | **Complete** | SCID, entry hash, version number/time, DI proof vs updateKeys, pre-rotation |
| SCID-to-DID binding check (LogBasedResolver) | **Complete** | SCID extracted from DID string compared against genesis `parameters.scid` (spec §resolve step 6.1, matches TS ref-impl) |
| CreateOperation | **Complete** | Full genesis flow, SCID generation, placeholder replacement |
| UpdateOperation | **Complete** | Key rotation, pre-rotation, parameter delta |
| DeactivateOperation | **Complete** | Including pre-rotation guard |
| DID → HTTPS URL (DidUrlTransformer) | **Complete** | IDNA, port encoding, well-known path |
| Exception hierarchy | **Complete** | Maps to spec error codes |
| LogBasedResolver | **Complete** | Entry-by-entry validation, version filters (versionId/versionTime/versionNumber), deactivation handling, error-to-metadata mapping |
| HttpResolver | **Complete** | URL transform → fetch → parse → delegate to LogBasedResolver |
| Public API facade (DidWebVh) | **Complete** | `create`, `resolve`, `resolveFromLog`, `update`, `deactivate` |

## Architecture: Resolver Design

- `LogBasedResolver` — standalone class (does NOT implement `DidResolver`); pure logic with `resolve(did, log, options)` signature
- `HttpResolver implements DidResolver` — HTTP fetch + delegation to `LogBasedResolver`
- `DidWebVh.resolve()` → `HttpResolver`; `DidWebVh.resolveFromLog()` → `LogBasedResolver`
- Errors are never thrown from resolve methods; always encoded in `ResolveResult.metadata()`
- Programming errors (null args, multiple version filters) throw `NullPointerException` / `IllegalArgumentException`

## What's NOT Done (Stubs / Missing)

### P0 — Core Spec Requirements

1. **`WitnessValidator.validate()`** — witness proof verification
   - Verify witness proofs meet threshold
   - Verify each witness proof signature (they're `did:key` DIDs with `eddsa-jcs-2022`)
   - Integrate into `LogBasedResolver` validation loop

### P1 — Spec Compliance Gaps

2. **Witness proofs on update** — `UpdateOptions.witnessProofs` exists but `UpdateOperation` never reads it
3. **Witness file fetching** — `HttpResolver` should fetch `did-witness.json` when witnesses are configured
4. **DID URL path resolution** — implicit `#files` service (spec §6.5)
5. **`/whois` resolution** — implicit `#whois` service (spec §6.6)
6. **Parallel `did:web` publishing** — spec §6.7

### P2 — Nice-to-Have / Future

7. Watchers API integration
8. DNS-over-HTTPS (RFC 8484)
9. CORS header guidance
10. `did:web` parallel document generation
11. Method version dispatch (v0.5 compat like TS impl)

## Test Coverage Assessment

**Well-covered:** crypto, log parse/serialize/validate, create/update/deactivate operations, URL transformer, LogBasedResolver (18 tests: latest/versioned/deactivated/SCID-binding/error cases), HttpResolver (5 tests: success/error/malformed via injected LogFetcher)

**Not covered:** `WitnessValidator`, `WitnessProofCollection`

**Total: 228 tests.**
