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

### P3 — Future Enhancements

- Watchers API integration
- DNS-over-HTTPS (RFC 8484)
- CORS header guidance
- Method version dispatch (v0.5 compat like TS impl)
