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

### P2 — Issue #1: `witness-update` / `witness-threshold` Test Suite Failures

Tracking issue: [european-epc-competence-center/didwebvh#1](https://github.com/european-epc-competence-center/didwebvh/issues/1).
Investigation harness: [WitnessTestSuiteReproTest.java](../didwebvh-java/src/test/java/de/eecc/did/webvh/resolve/WitnessTestSuiteReproTest.java).
Vectors copied from [swcurran/didwebvh-test-suite](https://github.com/swcurran/didwebvh-test-suite/tree/main/vectors) into `didwebvh-java/src/test/resources/witness-suite/`.

#### Root cause — `buildWitnessEpochs` incorrectly applied prevConfig to witness rotations (fixed)

The `witness-update` scenario rotates from `{threshold:2, witnesses:[A,B]}` at v1 to `{threshold:1, witnesses:[A]}` at v2. All five generators produce the same `did-witness.json`: v1 signed by A+B, v2 signed by A only. Three of five implementations (TS, ivir3zam-Java, Rust) expected success; we and Python expected failure. Investigation showed **our resolver was wrong**, not the test vectors.

The spec (§Witness Lists) defines three distinct cases for the `witness` parameter:

| Transition | Spec rule | Active config for the entry |
|---|---|---|
| `{}` → active (activation) | "immediately active" | **new** (currConfig) |
| active → active (rotation) | "becomes active AFTER published" | **new** (currConfig) — see below |
| active → `{}` (deactivation) | "that log entry MUST be witnessed" | **old** (prevConfig) |

The phrase "becomes active AFTER published" is about **publication ordering** (witnesses sign the entry *before* it goes live on the server), not about which config the resolver validates the entry against. The `versionId` in `did-witness.json` is "the versionId of the DID log entry to which the witness proofs apply" — the proofs cover the entry declaring the new config, so the new config's threshold is what must be satisfied. Deactivation is carved out explicitly because applying "current config governs" to a `{}` transition would mean no witnesses are needed to sign their own removal — a clear security hole.

Our old `buildWitnessEpochs` in [`LogBasedResolver.java`](../didwebvh-java/src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java) used `prevConfig` for both rotation *and* deactivation (the same `else` branch). The fix: detect deactivation (`!wasEmpty && !nowActive`) explicitly and keep `prevConfig` only there; all other cases use `currConfig`.

With the fix the epoch structure for the three-entry test log (v1:A, v2:B, v3:{}) changes from:
- Old: Epoch A `[1,2]`, Epoch B `[3,3]`
- New: Epoch A `[1,1]`, Epoch B `[2,3]`

And `witness-update-java` (ivir3zam) and `witness-update-ts` now resolve successfully.

Python's resolver has the same bug in the opposite direction — `(prev_state or state).witness_rule` picks `prev_state` (old config) and stores it at the current `version_number`, causing it to reject. Python's expected `resolutionResult.json` therefore records failure. Our old code agreed with Python's bug, which made us look "consistent" — both were wrong.

#### Remaining issues (upstream)

- **`witness-update-rust` / `witness-threshold-rust`**: Rust generator emits witness `id` as a bare multibase key (`z6Mkrv5Cm2…`) instead of a `did:key:` DID. Spec §Witness Lists line 1061 mandates `did:key`. [`WitnessParameter.validate`](../didwebvh-java/src/main/java/de/eecc/did/webvh/model/WitnessParameter.java) correctly rejects. This is a Rust generator bug to fix upstream.
- **`witness-update-java-eecc`** (test-suite harness): equal `versionTime` on entries 1 and 2 (generated in the same second, before our local `OperationSupport.computeVersionTime` fix). Vectors need to be re-generated. The resolutionResult.json was also produced under the old (buggy) strict interpretation and says "no didDocument" — it should also be regenerated to expect success.
- **`witness-update-rust`**: additionally has equal `versionTime` on entries 1 and 2 for the same reason.

### P3 — Future Enhancements

- Watchers API integration
- DNS-over-HTTPS (RFC 8484)
- CORS header guidance
- Method version dispatch (v0.5 compat like TS impl)
