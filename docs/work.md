# Open Work

## Current Status

All four DID operations (create, update, deactivate, resolve) are implemented and tested. 
The library targets `did:webvh` v1.0.

## Open Work Packages

### P1 — Spec Compliance Gaps

1. **DID URL path resolution** — implicit `#files` service (spec §6.5)
2. **`/whois` resolution** — implicit `#whois` service (spec §6.6)
3. **Parallel `did:web` publishing** — spec §6.7
4. **`versionTime` strictness** — `LogValidator` allows equal timestamps; spec requires strictly greater
5. **IDNA2008 compliance** — `DidUrlTransformer` uses Java's `IDN.toASCII` (IDNA2003); spec requires IDNA2008 (RFC 9233)
6. **`alsoKnownAs` validation for portability** — spec requires a moved DID's DIDDoc to contain the prior DID in `alsoKnownAs`; library checks `portable=true` and `id` change, but does not validate `alsoKnownAs`
7. **Witness parameter delta handling** — ensure empty witness object `{}` vs `null` distinction is preserved during serialization when removing witnesses (spec says use defined empty values, not `null`)

### P2 — Code Quality & Architecture

1. **Consolidate ObjectMapper instances** — nearly every class creates its own `ObjectMapper`; use a shared/configured instance (or make injectable)
2. **Reuse HttpClient in HttpResolver** — currently creates a new `HttpClient` per `resolve()` call; `HttpClient` is designed for long-lived reuse in Java 11+
3. **Refine pre-rotation delta logic** — `UpdateOperation` manually forces `updateKeys`/`nextKeyHashes` back into the delta after `diff()` strips them; improve `diff()` or the parameter model to handle pre-rotation presence requirements naturally

### P3 — Future Enhancements

- Watchers API integration
- DNS-over-HTTPS (RFC 8484)
- CORS header guidance
- Method version dispatch (v0.5 compat like TS impl)
