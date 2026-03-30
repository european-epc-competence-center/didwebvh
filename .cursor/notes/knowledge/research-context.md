# Research Context

## SSI / DID Layer vs. X.509 PKI

X.509 binds a public key directly to a subject (domain name, person). A DID adds an **indirection layer**: the DID is a persistent identifier that resolves to a DID Document containing the current public key.

| Aspect | X.509 PKI | DID Layer |
|---|---|---|
| Trust anchor | Hierarchical CA chain | Cryptographic (e.g. hash chaining) |
| Key rotation | Requires new certificate + CA involvement | Rotate key in DID Doc, identifier unchanged |
| Central authority | Mandatory CA | None required |
| Revocation | CRL / OCSP via CA | Method-specific (e.g. log entry) |
| Privacy | Full cert exposed | ZKP-based selective disclosure possible |

`did:webvh` strengthens the DID layer further by adding hash chaining, binding update keys, and Data Integrity Proofs on each log entry — eliminating the silent-manipulation risk present in `did:web` while retaining CA-independence.

Sources: [Phil Windley (2021)](https://windley.com/archives/2021/05/comparing_x509_certificates_with_ssi.shtml) · [W3C DID spec](https://w3.org/TR/did-1.1)

---

## KERI — Key Event Receipt Infrastructure

> Spec: https://trustoverip.github.io/tswg-keri-specification/  
> did:keri method: https://identity.foundation/keri/did_methods/

KERI is a decentralized PKI protocol providing a cryptographic root-of-trust through self-certifying identifiers (AIDs) — without a blockchain or central registry.

| Concept | Description |
|---|---|
| **AID** | Autonomic Identifier — self-certifying, derived from initial key pair |
| **KEL** | Key Event Log — append-only, hash-chained log of all key events |
| **KERL** | Key Event Receipt Log — KEL + witness receipts |
| **Pre-rotation** | At inception, commit to next-key hashes; reveal on rotation to prevent unauthorized rotation |

The `did:keri` method transforms KERI Key State into a W3C DID Document via KEL replay.

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

**Research relevance**: KERI's formal security model (especially for pre-rotation and witness consensus) provides a theoretical foundation for evaluating `did:webvh`'s security properties — illuminating where `did:webvh` inherits KERI-level guarantees and where it introduces new assumptions (DNS, HTTPS, server trust).
