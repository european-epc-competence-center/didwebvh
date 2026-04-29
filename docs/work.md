# Open Work

## Current Status

All four DID operations (create, update, deactivate, resolve) are implemented and tested. Witness validation during resolution is complete. The library targets `did:webvh` v1.0 and implements the core hash chain, SCID, Data Integrity proofs, pre-rotation, and witness support.

## Open Work Packages

### P1 — Spec Compliance Gaps

1. **Witness proofs on update** — `UpdateOptions.witnessProofs` exists but `UpdateOperation` never reads it
2. **DID URL path resolution** — implicit `#files` service (spec §6.5)
3. **`/whois` resolution** — implicit `#whois` service (spec §6.6)
4. **Parallel `did:web` publishing** — spec §6.7

### P2 — Future Enhancements

- Watchers API integration
- DNS-over-HTTPS (RFC 8484)
- CORS header guidance
- Method version dispatch (v0.5 compat like TS impl)
