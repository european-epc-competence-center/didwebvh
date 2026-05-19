# Open Work

## Current Status

All four DID operations (create, update, deactivate, resolve) are implemented and tested. The library targets `did:webvh` v1.0.

## Open Work Packages

### P1 — Spec Compliance Gaps

1. **Parallel `did:web` publishing** (partial)  
   Implicit `#files`/`#whois` services are injected during resolution so the resolved document is compatible, but there is no explicit publishing helper that writes a parallel `did.json`.
2. **`method` version downgrade validation** — `Parameters.validateTransition()` does not enforce that `method` semver is equal to or higher than the previous entry
3. **Reject unknown parameters** — `Parameters` uses `@JsonIgnoreProperties(ignoreUnknown = true)`; spec requires the `parameters` object to only include defined properties
4. **IDNA2008 compliance** — `DidUrlTransformer` uses Java's `IDN.toASCII` (IDNA2003); spec requires IDNA2008 (RFC 9233)
5. **Deactivated DID document** — When a DID is deactivated the library returns `null` for `didDocument`. The TS test vectors include the last valid document with `deactivated: true`. Both are arguably spec-compliant (DID Resolution spec shows `null` examples, DID Core says the document should indicate deactivation). Needs community decision.

### P2 — Issue #1: `witness-update` / `witness-threshold` test-suite findings

Tracking issue: [european-epc-competence-center/didwebvh#1](https://github.com/european-epc-competence-center/didwebvh/issues/1).
Investigation harness: [WitnessTestSuiteReproTest.java](../didwebvh-java/src/test/java/de/eecc/did/webvh/resolve/WitnessTestSuiteReproTest.java) (disabled on CI — enable locally to inspect cross-impl outcomes).
Vectors copied from [swcurran/didwebvh-test-suite](https://github.com/swcurran/didwebvh-test-suite/tree/main/vectors) into `didwebvh-java/src/test/resources/witness-suite/`.

#### Which witness config governs a transition entry?

§Witness Lists describes three transitions of the `witness` parameter. Read literally:

| Transition | Spec text | Config that governs the transition entry |
|---|---|---|
| `{}` → active (activation) | *"If the witness property is updated from `{}`, the change is **immediately active**, and the corresponding log entry MUST be witnessed."* | **new** (`currConfig`) |
| active → active (rotation) | *"If a DID log entry contains a new (replacement) list of witnesses … that new list becomes active **AFTER** the new DID log has been published."* | **previous** (`prevConfig`) |
| active → `{}` (deactivation) | *"If witnesses are active when the witness parameter is set to `{}`, that log entry MUST be witnessed."* | **previous** (`prevConfig`) |

The safety theme is identical for rotation and deactivation: **a witness cannot be removed (whether by replacement or by setting `{}`) without that witness's own approval.** Activation is the explicit carve-out — there are no prior witnesses to sign.

An earlier branch of work (commit `9e3eb72`, since reverted) read "becomes active AFTER published" as a comment about HTTP publication ordering and let `currConfig` govern rotations too. That interpretation passes `witness-update-ts` and `witness-update-java` (ivir3zam) but opens a security gap: a controller plus the surviving witnesses can rotate any other witness away without that witness's consent, defeating the point of having multiple witnesses. The text says when the rule takes effect, not when it gets published over HTTP.

#### Behavior in the reference implementations

| Impl | Activation entry | Rotation entry | Deactivation entry | Model |
|---|---|---|---|---|
| **java-eecc (this lib)** | new | **prev** | prev | per-entry epoch, spec literal |
| **Python (didwebvh-py)** | (lagged — prev) | **prev** | prev | per-entry epoch, `(prev_state or state).witness_rule` |
| **Rust (didwebvh-rs)** | (lagged — prev) | **prev** | prev | per-entry, `active_witness = previous.witness.clone()` |
| **TypeScript (didwebvh-ts)** | new | **new** | (skipped) | only the **last** log entry is witness-checked |
| **ivir3zam-Java** | new | **new** | (skipped) | merged-current config per entry; `{}` skips via `!isActive()` |

Sources:
- Python: `did_webvh/core/resolver.py:418` — `witness_rule := (prev_state or state).witness_rule`
- Rust: `didwebvh-rs/src/parameters/mod.rs:428–470` — every non-genesis branch sets `active_witness = previous.witness.clone()`
- TypeScript: `didwebvh-ts/src/method_versions/method.v1.0.ts:292–305` — `verifyWitnessProofs` runs only when `i === resolutionLog.length - 1`
- ivir3zam-Java: `WitnessValidator.java:49–54` — merges entry params first, then reads `activeParams.getWitness()`

Python and Rust agree with us on rotation and deactivation. They are mildly off on activation: under their lagged-prev rule the activation entry itself is not enforced (the new threshold only kicks in at the entry after). The spec text "immediately active … MUST be witnessed" wants enforcement at the activation entry. Worth raising upstream.

TS and ivir3zam-Java are off on rotation (and ivir3zam additionally skips deactivation entirely). Both effectively let a controller rotate witnesses without the old witnesses' consent.

#### What we implement now

`buildWitnessEpochs` in [`LogBasedResolver.java`](../didwebvh-java/src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java):

- Genesis (entry 0): the entry's own effective `witness` config.
- Subsequent entries: the **previous** entry's effective config — unless the previous was empty/absent and the current is non-empty, in which case the new config governs immediately (activation rule).

For the three-entry test log `v1: witness=A → v2: witness=B → v3: witness={}`:

- Epoch A: `[1, 2]` (A governs v1 by genesis, governs v2 because rotation is published-after).
- Epoch B: `[3, 3]` (B governs v3 because deactivation must be signed by the still-active witnesses).

This is the same epoch structure we had **before** commit `9e3eb72` — that commit has been reverted.

#### How each test-suite vector behaves under this rule

All five `witness-update*` vectors have the same log shape: `v1: witness={threshold:2, witnesses:[A,B]} → v2: witness={threshold:1, witnesses:[A]}`. They differ in the proofs supplied and in the expected outcome:

| Vector | proofs v1 / v2 | expected (upstream) | java-eecc outcome | why |
|---|---|---|---|---|
| `witness-update-python` | A+B / A | invalidDid | **invalidDid (matches)** | v2 governed by A+B threshold=2; only A signed v2 → 1 < 2. |
| `witness-update-ts` | A+B / A | success | **invalidDid (diverges)** | TS generator assumes new config governs rotation → vector under-witnessed at v2 under spec literal. |
| `witness-update-java` (ivir3zam) | A+B / A | success | **invalidDid (diverges)** | same as TS — ivir3zam validator uses merged-current config. |
| `witness-update-rust` | (none) / A+B | success | invalidDid (separate bug, see below) | proofs would satisfy A+B at v2; vector content is fine, only the rust-generator's witness-`id` shape is wrong. |
| `witness-threshold-rust` | A / — | success | invalidDid (separate bug, see below) | single entry; same witness-`id` shape problem. |
| `witness-update-java-eecc` | A+B / A | success | invalidDid (input has equal `versionTime`) | self-generated under the old buggy interpretation; needs regeneration. |

Conclusion: under the spec-literal reading our resolver is now consistent with Python, and diverges from TS and ivir3zam on rotation. Neither divergence is a bug in our code — they are spec-interpretation gaps in TS/ivir3zam.

#### Remaining issues (to raise on Issue #1 and upstream)

1. **Rust generator: non-`did:key` witness `id`** — emits a bare multibase key (`z6Mkrv5Cm2…`) instead of a `did:key:` DID. Spec §Witness Lists is unambiguous: `id: (required) the DID of the witness. The DID MUST be a did:key DID.` [`WitnessParameter.validate()`](../didwebvh-java/src/main/java/de/eecc/did/webvh/model/WitnessParameter.java) correctly rejects. Affects `witness-update-rust`, `witness-threshold-rust`.
2. **`witness-update-java-eecc` (self-generated) had equal `versionTime`** — entries 1 and 2 share a timestamp because of a generator bug fixed locally in commit `374e73e` (`OperationSupport.computeVersionTime` now auto-advances by 1s when `now <= prev`). Re-generate after pulling the fix. The expected `resolutionResult.json` will need to flip too: with the proofs currently supplied (A+B at v1, A at v2), the spec-literal outcome is `invalidDid`; for the vector to expect success, the witness file needs a second signature at v2.
3. **`witness-update-rust` also has equal `versionTime`** — same root cause; needs regeneration alongside the witness-`id` fix.
4. **TS / ivir3zam-Java rotation semantics** — the TS and ivir3zam generators encode a permissive interpretation of the rotation rule. Either the spec should be tightened (preferred — it already implies the safe reading) or the upstream impls should fix the generator and validator to use prev-config for rotation entries.
5. **Activation enforcement in Python and Rust** — both fail to enforce the new threshold at the entry that introduces witnesses from `{}`. Spec says "immediately active, and the corresponding log entry MUST be witnessed". Our resolver already handles this via the `wasEmpty && nowActive` branch.

#### ivir3zam pre-rotation-consume (upstream, not ours)

ivir3zam uses the *previous* entry's `updateKeys` to verify proofs even when pre-rotation is active. The spec (§Authorized Keys) is explicit: when pre-rotation is active the *current* entry's `updateKeys` are the authorized keys. java-eecc and Rust are spec-correct; ivir3zam has the bug.

#### Open — interop diffs (cosmetic, not hard failures)

- **Trailing slash on service endpoints** — java-eecc resolves `https://example.com` as `https://example.com/`
- **Service ID expansion** — java-eecc expands relative fragment `#files` to the full DID URL `did:webvh:…:example.com#files`; TypeScript/Java keep the relative form
- **`didResolutionMetadata` content** — java-eecc always includes `contentType: application/did+ld+json`; Python returns `null`

### P3 — Future Enhancements

- Watchers API integration
- DNS-over-HTTPS (RFC 8484)
- CORS header guidance
- Method version dispatch (v0.5 compat like TS impl)
