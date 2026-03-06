# SSI / DID Layer vs. X.509 PKI

## Core Distinction

X.509 binds a public key directly to a subject (domain name, person). A DID adds an **indirection layer**: the DID is a persistent identifier that resolves to a DID Document containing the current public key.

## Key Advantages of DID Layer

| Aspect | X.509 PKI | DID Layer |
|---|---|---|
| Trust anchor | Hierarchical CA chain | Cryptographic (e.g. hash chaining) |
| Key rotation | Requires new certificate + CA involvement | Rotate key in DID Doc, identifier unchanged |
| Central authority | Mandatory CA | None required |
| Revocation | CRL / OCSP via CA | Method-specific (e.g. log entry) |
| Privacy | Full cert exposed | ZKP-based selective disclosure possible |

## Relevance to did:webvh

`did:webvh` strengthens the DID layer further by adding:
- **Hash chaining** between DID log entries (tamper-evident history)
- **Binding update keys** (only authorized keys can update)
- **Data Integrity Proofs** on each log entry

This eliminates the silent-manipulation risk present in `did:web` while retaining the CA-independence of the DID model.

## Sources
- Phil Windley: *Comparing X.509 Certificates with SSI* (2021) — https://windley.com/archives/2021/05/comparing_x509_certificates_with_ssi.shtml
- SIS: *X.509 vs. SSI* — https://sis.lt/x-509-vs-ssi/
- W3C DID spec: https://w3.org/TR/did-1.1
