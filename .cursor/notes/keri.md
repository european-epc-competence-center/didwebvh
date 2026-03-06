# KERI – Key Event Receipt Infrastructure

> Spec: https://trustoverip.github.io/tswg-keri-specification/
> DIF KERI: https://identity.foundation/keri/
> did:keri method: https://identity.foundation/keri/did_methods/

## Core Concepts

**KERI** is a decentralized public key infrastructure (DPKI) protocol providing a cryptographic root-of-trust through self-certifying identifiers (SCIDs) / autonomic identifiers (AIDs) — without requiring a blockchain or central registry.

| Concept | Description |
|---|---|
| **AID** | Autonomic Identifier — self-certifying, derived from initial key pair |
| **KEL** | Key Event Log — append-only, hash-chained log of all key events |
| **KERL** | Key Event Receipt Log — KEL + witness receipts (not hash-chained) |
| **Key State** | Current keys, witnesses, thresholds — signed snapshot of KEL |
| **Inception event** | First KEL entry; establishes AID and initial key set |
| **Rotation event** | Key rotation; reveals pre-committed next keys |

## Pre-Rotation (KERI's Core Security Feature)

At inception, two key sets are created:
1. **Current keys** — used for signing
2. **Next keys** — kept secret; only their **hash digest** is published in the KEL

On rotation, the next keys are revealed and must match the committed digest. This prevents key compromise from enabling unauthorized rotation, since the attacker would need to invert the hash to forge a valid rotation event.

This is the same concept adopted by `did:webvh` as `nextKeyHashes`.

## Trust Modalities

- **Direct mode**: one-to-one; based on verified signatures from the KEL
- **Indirect mode**: one-to-many; uses witnessed KERL as secondary root-of-trust

## did:keri Method

Transforms KERI Key State into a standard W3C DID Document. Uses event-sourcing (KEL replay) rather than JSON patches to reconstruct the current DID Document state.

## Relation to did:webvh

| Aspect | KERI / did:keri | did:webvh |
|---|---|---|
| Log structure | Hash-chained KEL | Hash-chained DID log (`did.jsonl`) |
| Self-certifying ID | AID derived from inception key | SCID derived from first log entry hash |
| Pre-rotation | Native, mandatory | Optional (`nextKeyHashes`) |
| Witnesses | KERL receipts (hash-chained) | `did-witness.json` (threshold signatures) |
| Infrastructure | Any (ambient verifiability) | Web servers (HTTPS) |
| DID Document | Derived from Key State | Embedded in each log entry |
| Trust anchor | Cryptographic (key-based) | Cryptographic + DNS (discovery only) |
| Portability | AID is location-independent | Optional (`portable: true`) |

**Key insight**: `did:webvh` independently converged on several KERI design patterns (hash-chained microledger, SCID, pre-rotation key hashes, witness threshold). KERI is the more general and infrastructure-agnostic system; `did:webvh` is a pragmatic Web-native specialization with backward compatibility to `did:web`.

**Research relevance**: KERI's formal security model (especially for pre-rotation and witness consensus) provides a theoretical foundation for evaluating `did:webvh`'s security properties. Comparing the two illuminates where `did:webvh` inherits KERI-level guarantees and where it introduces new assumptions (DNS, HTTPS, server trust).
