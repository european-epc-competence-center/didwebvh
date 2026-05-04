# Open Work

## Current Status

All four DID operations (create, update, deactivate, resolve) are implemented and tested. 
The library targets `did:webvh` v1.0.

## Open Work Packages

### P1 — Spec Compliance Gaps

1. **Witness proofs on update** — `UpdateOptions.witnessProofs` exists but `UpdateOperation` never reads it
2. **DID URL path resolution** — implicit `#files` service (spec §6.5)
3. **`/whois` resolution** — implicit `#whois` service (spec §6.6)
4. **Parallel `did:web` publishing** — spec §6.7
5. **`versionTime` strictness** — `LogValidator` allows equal timestamps; spec requires strictly greater
6. **IDNA2008 compliance** — `DidUrlTransformer` uses Java's `IDN.toASCII` (IDNA2003); spec requires IDNA2008 (RFC 9233)

### P2 — API / Usability Gaps

7. **`ttl` parameter not exposed in `UpdateOptions`** — cannot change TTL via update
8. **`deactivated` parameter not exposed in `UpdateOptions`** — must use `DeactivateOperation`

### P3 — Future Enhancements

- Watchers API integration
- DNS-over-HTTPS (RFC 8484)
- CORS header guidance
- Method version dispatch (v0.5 compat like TS impl)
