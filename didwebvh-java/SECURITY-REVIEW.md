# Security Review — `de.eecc.did.webvh` (didwebvh-java / java-eecc)

**Scope:** `src/main/java/de/eecc/did/webvh/**` at version `0.3.1` (branch `main`).
**Method:** patch-derived review against the 10 anti-pattern categories and the 15 "Mythos"
findings from the Rust `didwebvh` audit, adapted to this Java codebase. Each candidate was
opened and traced to untrusted input before being promoted to a finding.

**Threat model.** This is a resolution/verification library. The attacker is whoever serves
`did.jsonl` / `did-witness.json` and the DID document (the DID controller or anyone who has
compromised the controller's update keys or web host). The victim is a relying party that
resolves an attacker-influenced DID. The security goal of `did:webvh` is that such a party
cannot be fooled into accepting a forged or unauthorized DID document state.

---

## Summary

| Severity | Count | Finding |
|----------|-------|---------|
| **Critical** | 1 | Witness-proof forgery via `did:key` body/fragment mismatch → witness threshold bypass |
| **Medium** | 1 | SSRF: no DNS/private-IP filtering on log fetch and on explicit service-endpoint fetch |
| **Low** | 3 | SCID not pinned across a portability transition; `LogValidator` NPEs on entries missing `state`; witness proofs skip cryptosuite/purpose field checks |

The codebase is, overall, notably well-hardened: 14 of the 15 Mythos bug patterns are
correctly defended (see [What this library gets right](#what-this-library-gets-right)). The
single critical finding is a high-impact exception in the witness path — the same `did:key`
body/fragment class as Mythos bug #1, which is correctly handled for *entry* proofs but
**not** for *witness* proofs.

---

## Critical

### [CRITICAL] Witness identity is taken from the `did:key` body, but the signature is verified against the fragment

**Location:**
- [`witness/WitnessValidator.java:165`](src/main/java/de/eecc/did/webvh/witness/WitnessValidator.java#L165) (`buildValidatedMap` → `extractBaseDid`)
- [`witness/WitnessValidator.java:171`](src/main/java/de/eecc/did/webvh/witness/WitnessValidator.java#L171) (`DataIntegrity.verifyProof`)
- [`witness/WitnessValidator.java:196-200`](src/main/java/de/eecc/did/webvh/witness/WitnessValidator.java#L196-L200) (`extractBaseDid` returns the substring **before** `#`)
- [`crypto/DataIntegrity.java:127`](src/main/java/de/eecc/did/webvh/crypto/DataIntegrity.java#L127) → [`crypto/Multiformats.java:192-202`](src/main/java/de/eecc/did/webvh/crypto/Multiformats.java#L192-L202) (`extractMultikey` returns the substring **after** `#`)

**Bug class:** Category 2 — sender/identity spoofing in a signed envelope; Category 9 — missing witness/proof binding (Mythos bug #1, witness variant).

**What:** When verifying a witness proof, the *witness identity* used for the
threshold count is derived from the `did:key` **body** (everything before `#`):

```java
// WitnessValidator.buildValidatedMap
String witnessDid = extractBaseDid(proof.verificationMethod());   // did:key:<BODY>
// ...
DataIntegrity.verifyProof(entryNode, proof, verifier);            // verifies with <FRAGMENT>
validated.put(witnessDid, new MaxProof(versionNumber, versionId));
```

…but the *signature* is verified with the key taken from the **fragment** (everything after
`#`), because `DataIntegrity.verifyProof` calls `Multiformats.extractMultikey`, which returns
the fragment. A `did:key` DID URL is only well-formed when body == fragment, but that equality
is **never enforced**. Identity and verification key therefore come from two attacker-chosen,
independent halves of the same string.

**Attack:** A malicious controller (or an attacker who compromised the update keys) wants to
publish a log entry that requires `N` witness signatures it cannot obtain. It generates its
own throwaway key `z6MkATTACKER` and, for each required witness `did:key:z6MkWITNESS_i`,
writes a `did-witness.json` entry whose proof has:

```
verificationMethod = "did:key:z6MkWITNESS_i#z6MkATTACKER"
proofValue         = <Ed25519 signature produced with z6MkATTACKER's private key>
```

During verification:
- `extractBaseDid` → `did:key:z6MkWITNESS_i` → matches a configured (trusted) witness;
- `extractMultikey` → `z6MkATTACKER` → the signature verifies (the attacker signed it);
- the proof is recorded as a **valid proof from `did:key:z6MkWITNESS_i`**.

Repeating this for `N` distinct witness DIDs satisfies any threshold without a single real
witness key. This defeats the entire purpose of witnessing (multi-party approval that the
controller cannot forge unilaterally).

**Confirmed:** A focused PoC (run against this tree, then removed to keep CI green) builds a
witness epoch requiring one proof from an honest witness, supplies a single forged proof
signed by an unrelated attacker key, and calls
`WitnessValidator.verifyEpochs(...)`. A secure implementation must throw; this implementation
**returns normally** — the forgery satisfies the threshold. PoC reproduced in the
[appendix](#appendix--witness-forgery-poc).

**Why the entry-proof path is *not* affected:** In
[`log/LogValidator.java:371-377`](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L371-L377)
the authorization key and the verification key are *both* `extractMultikey(...)` (the
fragment), and the fragment must additionally be present in `updateKeys`. Identity and
verification key are the same value, so the body is never trusted and the mismatch is
harmless there. The witness path is the lone place where identity (body) and verification key
(fragment) diverge.

**Fix:** Bind the witness identity to the key that actually verified the signature. Minimal
options (any one closes it):

1. In `WitnessValidator`, derive the witness DID from the verification key, not the body:
   ```java
   String multikey = Multiformats.extractMultikey(proof.verificationMethod()); // fragment key
   String witnessDid = "did:key:" + multikey;     // identity == verifying key
   ```
2. Or enforce `did:key` well-formedness centrally (reject when body != fragment) and apply it
   to every `verificationMethod` before use:
   ```java
   // for "did:key:<body>#<frag>" require body.equals(frag)
   ```
   This also tightens `LogValidator` and matches the `did:key` spec.

Prefer (2) so the invariant holds everywhere a `verificationMethod` is consumed.

**Regression test:** Keep the PoC as a *passing* test once fixed — construct a proof with
`verificationMethod = "did:key:" + honestWitnessKey + "#" + attackerKey`, sign with the
attacker key, and assert `verifyEpochs` throws `LogValidationException`. Use a distinctive
marker key name so the invariant survives refactors.

---

## Medium

### [MEDIUM] SSRF: host validation rejects IP *literals* only, not hostnames resolving to internal IPs; explicit service endpoints are fetched with no IP filtering

**Location:**
- [`resolve/HttpResolver.java:285-311`](src/main/java/de/eecc/did/webvh/resolve/HttpResolver.java#L285-L311) (`defaultHttpFetcher`)
- [`resolve/DidUrlTransformer.java:195-210`](src/main/java/de/eecc/did/webvh/resolve/DidUrlTransformer.java#L195-L210) (`validateHostName` — string-level IP-literal rejection)
- [`resolve/HttpResolver.java:224`](src/main/java/de/eecc/did/webvh/resolve/HttpResolver.java#L224) + [`resolve/DidUrlPathResolver.java:79-95`](src/main/java/de/eecc/did/webvh/resolve/DidUrlPathResolver.java#L79-L95) (explicit `serviceEndpoint` fetch)

**Bug class:** Category 4 — SSRF.

**What:** Two outbound-fetch surfaces are reachable from attacker-controlled input:

1. **Log/witness fetch.** The host comes from the DID. `validateHostName` rejects IPv4/IPv6
   *literals* (even percent-encoded ones — good), but a hostname such as
   `internal-svc.attacker.example` that **resolves** to `127.0.0.1`, `169.254.169.254`
   (cloud metadata), or an RFC1918 address passes validation and is fetched.
2. **DID-URL path / `#files` / `#whois` fetch.** When a path is dereferenced, the target URL
   is the service `serviceEndpoint` from the (untrusted) DID document. It is checked to start
   with `https://` ([HttpResolver.java:224](src/main/java/de/eecc/did/webvh/resolve/HttpResolver.java#L224))
   but is otherwise fetched verbatim — so an explicit `#files` service with
   `serviceEndpoint: https://169.254.169.254/latest/meta-data/` is fetched as-is.

If the library is used server-side to resolve attacker-supplied DIDs (a common deployment for
a resolver), this is a classic SSRF into the internal network / cloud metadata service.

**Mitigating factors already present (keep these):** redirects are *not* followed (Java's
`HttpClient` default is `Redirect.NEVER`, and the builder does not change it — so Mythos
bug #2 does not apply), the response body is capped at 5 MiB
([HttpResolver.java:75](src/main/java/de/eecc/did/webvh/resolve/HttpResolver.java#L75)), there
is a 10 s timeout, and only `https://` is allowed. These bound the blast radius but do not
stop the initial request to an internal address.

**Attack:** Attacker publishes `did:webvh:<scid>:internal.attacker.example` where DNS A-record
→ `169.254.169.254`; a server resolving that DID issues a GET to the metadata endpoint and may
surface the response (or its size/timing) to the attacker. Variant: a valid DID with an
explicit `#files` service pointing at an internal `https` host, dereferenced via a
`/path` DID URL.

**Fix (Category 4 shape):** After parsing the URL and **after DNS resolution**, reject the
request if the resolved IP is loopback/link-local/RFC1918/ULA or in a metadata range
(`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`, …). Apply this to *both* the log fetch
and the service-endpoint fetch. Set `.followRedirects(Redirect.NEVER)` explicitly so the safe
behaviour does not depend on a JDK default. For defence-in-depth, document that the built-in
fetcher is not SSRF-safe by itself and recommend an egress allow/deny policy when resolving
untrusted DIDs.

**Regression test:** Inject a `LogFetcher` that asserts it is never called with a URL whose
host resolves to a blocked range; feed a DID whose host/endpoint targets `169.254.169.254`
and assert resolution fails closed.

---

## Low

### [LOW] SCID is not pinned across a portability (domain-change) transition

**Location:** [`log/LogValidator.java:144-159`](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L144-L159) (portability check).

**Bug class:** Category 7(d) — self-certifying identifier binding (Mythos bug #15).

**What:** The per-entry portability check requires that, when the document `id` changes, the
previous params were `portable=true` and the new doc's `alsoKnownAs` contains the prior DID.
It does **not** assert that the **SCID segment** of the DID is unchanged across the move (the
spec allows only the domain to change). So an entry could move
`did:webvh:S:old.example` → `did:webvh:S2:new.example` (S2 ≠ S) and pass validation.

**Why it is only Low:** Resolution pins the SCID independently
([`resolve/LogBasedResolver.java:98-106`](src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java#L98-L106)):
the SCID in the requested DID must equal the genesis `parameters.scid` (which is itself
verified to be the correct hash in `validateScid`). A DID carrying a *changed* SCID therefore
cannot be resolved (its SCID won't match genesis), and resolving the *original* DID still
binds to the genesis SCID. The mis-validated entry is not exploitable for identity takeover;
it is a spec-conformance gap that should fail earlier.

**Fix:** In the portability branch, also require that the method-specific SCID segment of
`currDocId` equals that of `prevDocId`; reject if it changed.

---

### [LOW] `LogValidator` throws `NullPointerException` (not `LogValidationException`) on entries missing `state`

**Location:** [`log/LogValidator.java:145-146`](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L145-L146) and [`resolve/LogBasedResolver.java:136-137`](src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java#L136-L137) (`entry.state().getString("id")` where `state` may be `null`).

**Bug class:** Category 5(a) — unchecked failure on untrusted input (Mythos bug #8 analog).

**What:** `DidLogEntry.state` is `null` when a JSONL line omits the `state` object. The
portability and doc-id checks call `entry.state().getString(...)` without a null guard,
yielding an NPE.

**Why it is only Low:** The network entry points catch it —
`LogBasedResolver.resolve` has a `catch (Exception)`
([LogBasedResolver.java:70-75](src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java#L70-L75))
that converts it to an `invalidDid` result — so there is no crash to a resolver caller.
However: (a) callers using `LogValidator.validate()` / `validateEntry(...)` directly (a public
API) get an unchecked NPE instead of the documented `LogValidationException`; (b) the catch-all
logs the full stack trace at `WARN` ([LogBasedResolver.java:73](src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java#L73)),
so malformed input is an unauthenticated log-spam vector.

**Fix:** Add an explicit `if (entry.state() == null) throw new LogValidationException("Entry is missing 'state'")`
early in `validateEntry`, alongside the existing `parameters == null` check at
[LogValidator.java:132-134](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L132-L134).
Consider downgrading the catch-all log to `debug` (or logging only `e.getMessage()`).

---

### [LOW] Witness proofs are not subjected to `validateProofFields` (type / cryptosuite / proofPurpose)

**Location:** [`witness/WitnessValidator.java:164-186`](src/main/java/de/eecc/did/webvh/witness/WitnessValidator.java#L164-L186) vs. [`log/LogValidator.java:381-396`](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L381-L396).

**Bug class:** Category 7(c) — cryptosuite/purpose not enforced (Mythos bug #10 analog).

**What:** Entry proofs are checked to be `DataIntegrityProof` / `eddsa-jcs-2022` /
`authentication`-or-configured-purpose via `validateProofFields`. Witness proofs are only
signature-verified; their `type`, `cryptosuite`, and `proofPurpose` are not asserted.

**Why it is only Low:** The default verifier performs Ed25519 only, regardless of the declared
`cryptosuite`, and the declared value is part of the signed `proofOptions`, so there is no
algorithm-confusion path today. It is a defence-in-depth / consistency gap, not an exploit on
its own. (It becomes relevant if a multi-suite verifier is ever introduced.)

**Fix:** Call the same field-validation on witness proofs before counting them. Fold this in
with the Critical fix so the witness path validates fields *and* binds identity to the
verifying key.

---

## What this library gets right

These were checked specifically and are correctly handled — worth preserving with regression
tests. Mapped to the 15 Mythos findings:

| # | Mythos bug | Status here | Where |
|---|------------|-------------|-------|
| 1 | `did:key` body/fragment mismatch in proof auth | **Safe for entry proofs** (fragment used for both authz and verify; body ignored). **Vulnerable for witness proofs** — see Critical. | [LogValidator.java:371-377](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L371-L377) |
| 2 | HTTP redirects → SSRF | **Defended** — Java `HttpClient` default `Redirect.NEVER`; redirects never followed. (Still recommend setting it explicitly; see Medium.) | [HttpResolver.java:286-288](src/main/java/de/eecc/did/webvh/resolve/HttpResolver.java#L286-L288) |
| 3 | Duplicate witness IDs bypass threshold | **Defended** — duplicate witness `id`s rejected; threshold ∈ [1, n]; proofs de-duped by witness DID before counting. | [WitnessParameter.java:104-120](src/main/java/de/eecc/did/webvh/model/WitnessParameter.java#L104-L120) |
| 4 | Path traversal in DID→HTTP path | **Defended** — each path segment is percent-decoded then rejected if empty / `.` / `..` / contains `/` or `\`. | [DidUrlTransformer.java:217-223](src/main/java/de/eecc/did/webvh/resolve/DidUrlTransformer.java#L217-L223) |
| 5 | Lowercase `%3a` IP bypass | **Defended** — both `%3A` and `%3a` decoded; IP check runs after percent-decoding. | [DidUrlTransformer.java:136](src/main/java/de/eecc/did/webvh/resolve/DidUrlTransformer.java#L136), [:207](src/main/java/de/eecc/did/webvh/resolve/DidUrlTransformer.java#L207) |
| 6 | Fragment leaks into domain | **Defended** — host segment rejects `# / \ ? @` and whitespace. | [DidUrlTransformer.java:199-204](src/main/java/de/eecc/did/webvh/resolve/DidUrlTransformer.java#L199-L204) |
| 7 | "Later version" witness proofs unverified | **Defended** — every witness proof is cryptographically verified; proofs for versionIds not in the valid log are ignored; watermark match enforced. | [WitnessValidator.java:149-187](src/main/java/de/eecc/did/webvh/witness/WitnessValidator.java#L149-L187) |
| 8 | Panic on malformed `state.id` / versionId | **Mostly defended** — versionId format guarded before parsing; resolver catches all exceptions. Minor NPE caveat → see Low. | [LogValidator.java:194-208](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L194-L208) |
| 9 | Pre-rotation bypass via absent `updateKeys` | **Defended** — while pre-rotation active, both `updateKeys` and `nextKeyHashes` are required, and every revealed key's hash must be in the prior `nextKeyHashes`. | [Parameters.java:194-204](src/main/java/de/eecc/did/webvh/model/Parameters.java#L194-L204), [LogValidator.java:334-354](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L334-L354) |
| 10 | Cryptosuite not enforced on controller proof | **Defended for entry proofs** — `type` / `cryptosuite` / `proofPurpose` asserted. (Not for witness proofs → Low.) | [LogValidator.java:381-396](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L381-L396) |
| 11 | Cross-DID witness-proof replay | **Defended** — proofs are matched only against versionIds in *this* DID's validated log, and `versionId` is a content hash binding the entry (incl. the DID document `id`), so it is globally unique. | [WitnessValidator.java:144-155](src/main/java/de/eecc/did/webvh/witness/WitnessValidator.java#L144-L155) |
| 12 | Percent-encoded IP host bypass | **Defended** — `isIpLiteral(percentDecode(host))`. | [DidUrlTransformer.java:207](src/main/java/de/eecc/did/webvh/resolve/DidUrlTransformer.java#L207) |
| 13 | `%2E%2E` traversal bypass | **Defended** — path segment percent-decoded before the `.`/`..` check. | [DidUrlTransformer.java:218-222](src/main/java/de/eecc/did/webvh/resolve/DidUrlTransformer.java#L218-L222) |
| 14 | Genesis `state.id` SCID not bound | **Defended** — `validateScid` recomputes the SCID from the genesis entry with the SCID placeholdered; resolution then pins requested-DID SCID == genesis SCID and requires the DID to match a document `id`. | [LogValidator.java:297-328](src/main/java/de/eecc/did/webvh/log/LogValidator.java#L297-L328), [LogBasedResolver.java:98-141](src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java#L98-L141) |
| 15 | Portable entries can change SCID | **Contained** — validation does not reject an SCID change on a portable move, but resolution-time SCID pinning neutralizes it. Tighten validation → Low. | [LogBasedResolver.java:98-106](src/main/java/de/eecc/did/webvh/resolve/LogBasedResolver.java#L98-L106) |

Additional good practices observed:

- **No secret stringification (Category 1).** `Signer` holds a *signing function*, not raw key
  bytes ([Signer.java:56-70](src/main/java/de/eecc/did/webvh/crypto/Signer.java#L56-L70)); no
  private keys, tokens, or seeds are held in loggable objects, and no log statement serializes
  key material (only public DIDs/URLs at `trace`).
- **Bounded reads (Category 5b).** 5 MiB response cap + 10 s timeout in the default fetcher.
- **HTTPS-only** for log, witness, and service-endpoint fetches.
- **Strict log-chain checks**: monotonic, non-future, strictly-increasing `versionTime`;
  version numbers increment by exactly 1; entry-hash chain verified each step; deactivated DIDs
  reject further entries.
- **Standard, single-suite crypto**: Ed25519 via Bouncy Castle with RFC 8785 JCS from the
  reference implementation — no `alg:none` surface, no algorithm negotiation.

---

## Appendix — witness-forgery PoC

Drop this into `src/test/java/.../witness/`, run with
`mvn -o test -Dtest=WitnessForgeryPocTest`. Against the current tree the assertion **fails**
(no throwable raised), proving the forged proof satisfies the threshold. After the Critical fix
it should pass.

```java
@Test
void attackerForgesWitnessApprovalWithoutWitnessKey() {
    Ed25519TestFixture honestWitness = Ed25519TestFixture.generate(); // attacker lacks this private key
    String witnessDid = "did:key:" + honestWitness.publicKeyMultibase();

    Ed25519TestFixture attacker = Ed25519TestFixture.generate();
    String attackerMultikey = attacker.publicKeyMultibase();

    String versionId = "1-QmForgeryPocVersionId000000000000000000000000";

    // verificationMethod: body = honest witness, fragment = attacker key; signed by attacker.
    String forgedVm = witnessDid + "#" + attackerMultikey;
    ObjectNode unsecured = JsonMapper.INSTANCE.createObjectNode().put("versionId", versionId);
    DataIntegrityProof forged = DataIntegrity.createProof(unsecured, forgedVm, attacker.signer());

    WitnessProofCollection proofs = new WitnessProofCollection(List.of(
            new WitnessProofCollection.Entry(versionId, List.of(forged))));
    WitnessParameter config = new WitnessParameter(1,
            List.of(new WitnessParameter.WitnessEntry(witnessDid)));
    WitnessEpoch epoch = new WitnessEpoch(config, 1, 1);

    WitnessValidator validator = new WitnessValidator(Ed25519TestFixture.verifier());

    assertThatThrownBy(() ->
            validator.verifyEpochs(List.of(epoch), List.of(versionId), proofs, Integer.MAX_VALUE))
            .isInstanceOf(RuntimeException.class); // FAILS today → forgery accepted
}
```
