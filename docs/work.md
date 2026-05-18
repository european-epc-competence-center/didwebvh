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

From [didwebvh-test-suite PR #4](https://github.com/decentralized-identity/didwebvh-test-suite/pull/4/changes/65dd6c1c81e450d60201da8180324ea784489e9a).

Investigation harness: [WitnessTestSuiteReproTest.java](../didwebvh-java/src/test/java/de/eecc/did/webvh/resolve/WitnessTestSuiteReproTest.java) (disabled on CI — enable locally to inspect cross-impl outcomes).

#### Fixed in java-eecc

**Equal `versionTime` in generated logs** (commit `374e73e`)  
`create` + `update` running in the same wall-clock second both got `Instant.now().truncatedTo(SECONDS)`, producing equal timestamps. The spec requires each entry's `versionTime` to be strictly after the previous entry's. Rust and the other Java impl (ivir3zam) both enforce this strictly and rejected our generated logs. Fix: `OperationSupport.computeVersionTime` now auto-advances by 1 s when `now <= prev`.

**Witness epoch validation** (commit `9e3eb72`)  
`buildWitnessEpochs` in [`LogBasedResolver.java`](../didwebvh-java/src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java) incorrectly applied the *previous* entry's witness config to witness rotations. The spec (§Witness Lists) defines three distinct cases:

| Transition | Spec rule | Config used to validate the entry |
|---|---|---|
| `{}` → active (activation) | "immediately active" | new config (`currConfig`) |
| active → active (rotation) | "becomes active AFTER published" | new config (`currConfig`) |
| active → `{}` (deactivation) | "that log entry MUST be witnessed" | old config (`prevConfig`) |

The "becomes active AFTER published" sentence describes publication *ordering* (witnesses sign the entry before it goes live), not which config the resolver uses to validate the entry. Because the `versionId` in `did-witness.json` identifies the entry the proofs cover, the new threshold is what must be satisfied at that entry. Deactivation is explicitly carved out: applying "current config governs" to a `{}` transition would allow witnesses to be removed without any witnessing — a clear security hole.

With the fix the epoch structure for a three-entry log (`v1:{A,B}`, `v2:{A}`, `v3:{}`) changes from:
- Old: Epoch {A,B} `[1,2]`, Epoch {A} `[3,3]`
- New: Epoch {A,B} `[1,1]`, Epoch {A} `[2,3]`

`witness-update-ts` and `witness-update-java` (ivir3zam) now resolve successfully.

#### Upstream bugs (not java-eecc issues)

**Rust generator: bare multibase key instead of `did:key:` DID in witness `id`**  
The Rust test-suite generator emits witness IDs as raw multibase keys (e.g. `z6Mkrv5Cm2…`) instead of `did:key:` DIDs. The spec (§Witness Lists) is unambiguous:  
> *id: (required) the DID of the witness. The DID MUST be a did:key DID.*

[`WitnessParameter.validate()`](../didwebvh-java/src/main/java/de/eecc/did/webvh/model/WitnessParameter.java) correctly rejects these entries. Affects `witness-update-rust` and `witness-threshold-rust`.

**Other Java impl (ivir3zam): pre-rotation-consume**  
ivir3zam uses the *previous* entry's `updateKeys` to verify proofs even when pre-rotation is active. The spec (§Authorized Keys) is explicit: when pre-rotation is active the *current* entry's `updateKeys` are the authorized keys. java-eecc and Rust are spec-correct; ivir3zam has the bug.

**Vectors generated before the equal-`versionTime` fix**  
`witness-update-java-eecc` in the test-suite was generated before the `computeVersionTime` fix. Entries 1 and 2 share the same `versionTime`, causing our resolver to reject entry 2 as a valid log chain. Those vectors need to be regenerated. The accompanying `resolutionResult.json` also reflects the old (buggy) epoch interpretation and should be updated to expect success once vectors are regenerated.


#### Open — Interop DIFFs (cosmetic, not hard failures)

- **Trailing slash on service endpoints** — java-eecc resolves `https://example.com` as `https://example.com/`
- **Service ID expansion** — java-eecc expands relative fragment `#files` to the full DID URL `did:webvh:…:example.com#files`; TypeScript/Java keep the relative form
- **`didResolutionMetadata` content** — java-eecc always includes `contentType: application/did+ld+json`; Python returns `null`

### P3 — Future Enhancements

- Watchers API integration
- DNS-over-HTTPS (RFC 8484)
- CORS header guidance
- Method version dispatch (v0.5 compat like TS impl)
