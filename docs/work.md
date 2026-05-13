# Open Work

## Current Status

All four DID operations (create, update, deactivate, resolve) are implemented and tested. The library targets `did:webvh` v1.0.

## Open Work Packages

### P1 — Spec Compliance Gaps

1. **Parallel `did:web` publishing** (partial)  
   Implicit `#files`/`#whois` services are injected during resolution so the resolved document is compatible, but there is no explicit publishing helper that writes a parallel `did.json`.
2. **`alsoKnownAs` validation for portability** — spec requires a moved DID's DIDDoc to contain the prior DID in `alsoKnownAs`; library checks `portable=true` and `id` change, but does not validate `alsoKnownAs`
3. **`method` version downgrade validation** — `Parameters.validateTransition()` does not enforce that `method` semver is equal to or higher than the previous entry (spec §3.6)
4. **Reject unknown parameters** — `Parameters` uses `@JsonIgnoreProperties(ignoreUnknown = true)`; spec requires the `parameters` object to only include defined properties
5. **IDNA2008 compliance** — `DidUrlTransformer` uses Java's `IDN.toASCII` (IDNA2003); spec requires IDNA2008 (RFC 9233)
6. **Deactivated DID document** — When a DID is deactivated the library returns `null` for `didDocument`. The TS test vectors include the last valid document with `deactivated: true`. Both are arguably spec-compliant (DID Resolution spec shows `null` examples, DID Core says the document should indicate deactivation). Needs community decision.

### P2 — Test Suite Cross-Resolution Findings

From [didwebvh-test-suite PR #4](https://github.com/decentralized-identity/didwebvh-test-suite/pull/4/changes/65dd6c1c81e450d60201da8180324ea784489e9a):

#### Fixed (commit `374e73e`)
- **Equal versionTime in generated logs** — Before the fix, create + update running in the same wall-clock second both got `Instant.now().truncatedTo(SECONDS)`, producing equal timestamps. The other Java implementation and Rust both have strict (`>`) validators that rejected the resulting logs:
  - Other Java impl: `Invalid DID log: versionTime must be after previous entry at entry 2`
  - Rust impl: `ValidationError("[version 2] Log truncated at 2-QmcnrouaBSCHw9tP5SDgyWiSf2KoZyEWDb6RtCyGYksePp")`
  - Fix: `OperationSupport.computeVersionTime` now auto-advances by 1 s when `now <= prev`. Test vectors in the PR need to be regenerated.

#### Other Java impl bug (ivir3zam) — not a java-eecc issue
- **pre-rotation-consume: signing key not in active updateKeys at entry 2** — the other Java impl (ivir3zam) rejects java-eecc's AND Rust's pre-rotation-consume logs with this error. Root cause: ivir3zam uses the **previous** entry's `updateKeys` to verify the proof even when pre-rotation is active. The spec (§ Authorized Keys) is explicit: when pre-rotation is active, the **current** entry's `updateKeys` are the authorized keys. Java-eecc and Rust are spec-correct; ivir3zam has the bug. Java-eecc self-tests for pre-rotation-consume all pass.

#### Open — Interop DIFFs (cosmetic, not hard failures)
- **Trailing slash on service endpoints** — java-eecc resolves `https://example.com` as `https://example.com/`
- **Service ID expansion** — java-eecc expands relative fragment `#files` to the full DID URL `did:webvh:…:example.com#files`; TypeScript/Java keep the relative form
- **`didResolutionMetadata` content** — java-eecc always includes `contentType: application/did+ld+json`; Python returns `null`

### P3 — Future Enhancements

- Watchers API integration
- DNS-over-HTTPS (RFC 8484)
- CORS header guidance
- Method version dispatch (v0.5 compat like TS impl)
