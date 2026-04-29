# did:webvh Protocol Essentials

> Full spec: [`spec/`](../spec/)  
> Online: https://identity.foundation/didwebvh/v1.0/

`did:webvh` enhances `did:web` with a cryptographically verifiable, tamper-evident history via a hash-chained JSON Lines log (`did.jsonl`).

## DID Format

```abnf
webvh-did = "did:webvh:" scid ":" domain-segment 1*(".") [percent-encoded-port] *(":" path-segment)
```

- SCID is always the **first** element after `did:webvh:`
- Port colon percent-encoded as `%3A`

## DID-to-HTTPS URL

1. Remove `did:webvh:` prefix and SCID segment
2. Apply IDNA / Punycode to domain; percent-encode path segments
3. Reconstruct:
   - No path: `https://{domain}/.well-known/did.jsonl`
   - With path: `https://{domain}/{path}/did.jsonl`

Witnesses file: same URL with `did-witness.json`.

## Log Entry Structure

```json
{
  "versionId": "1-{entryHash}",
  "versionTime": "2025-01-23T04:12:36Z",
  "parameters": { ... },
  "state": { /* DIDDoc */ },
  "proof": [ /* Data Integrity proof(s) */ ]
}
```

## Parameters

| Parameter | First entry | Later entries | Default |
|---|---|---|---|
| `method` | MUST | MAY | — |
| `scid` | MUST | MUST NOT | — |
| `updateKeys` | MUST | MAY | — |
| `nextKeyHashes` | optional | retained if absent | `[]` |
| `witness` | optional | retained if absent | `{}` |
| `portable` | optional | retained (can't change false→true) | `false` |
| `deactivated` | optional | retained | `false` |
| `ttl` | optional | retained if absent | `3600` |

Rules:
- `null` MUST NOT be used (use typed empty values)
- `portable` can ONLY be set `true` in the first entry

## Cryptographic Pipeline

### Algorithms (v1.0)
- Hash: SHA-256
- Encoding: base58btc
- Hash format: multihash (`0x12 0x20` prefix)
- Signature: Data Integrity with `eddsa-jcs-2022`, `proofPurpose: assertionMethod`
- JSON canonicalization: JCS (RFC 8785)
- Key format: multikey (multibase-encoded, `z` prefix)

### SCID Generation
```
SCID = base58btc(multihash(JCS(preliminary_log_entry), SHA-256))
```
Preliminary entry uses literal `"{SCID}"` for `versionId` and all SCID placeholders.

### Entry Hash Generation
```
entryHash = base58btc(multihash(JCS(entry_without_proof), SHA-256))
```
Where `versionId` is set to the predecessor's `versionId` (or SCID for first entry).
`versionId` format: `"{version_number}-{entryHash}"`

### Data Integrity Signing Flow (eddsa-jcs-2022)

```
proofOptions    = { type, cryptosuite, verificationMethod, created, proofPurpose }
proofConfigHash = SHA-256(JCS(proofOptions))          ← FIRST 32 bytes
documentHash    = SHA-256(JCS(document_without_proof))  ← SECOND 32 bytes
hashData        = proofConfigHash || documentHash       ← 64 bytes
signature       = Ed25519.sign(hashData)
proofValue      = multibaseEncode(signature)            ← z-prefixed
```

### Multiformats Conventions

| Use | Prefix | Example | Methods |
|---|---|---|---|
| SCID, entry hash, `nextKeyHashes` | none (raw base58btc) | `Qm...` | `sha256Multihash()`, raw encode/decode |
| `proofValue`, multikey | `z` (multibase) | `z6Mk...` | `multibaseEncode/Decode` |

## Pre-rotation Keys

- Activated by non-empty `nextKeyHashes`
- Each entry's `nextKeyHashes` constrains **only the immediately next entry's** `updateKeys`
- While active: `updateKeys` and `nextKeyHashes` MUST be present in every entry
- Entry is signed by a key from the **current** entry's `updateKeys` (not previous)
- Deactivate: set `nextKeyHashes: []`; rules still apply to that entry, next entry uses normal rules
- DID deactivation with pre-rotation requires **two entries**: first stop pre-rotation, then `updateKeys: []`

## Witnesses

- Witness DIDs MUST be `did:key`
- `threshold`: integer 1..len(witnesses)
- `did-witness.json` MUST be published BEFORE the corresponding `did.jsonl` entry
- Resolver ignores proofs for unpublished log entries
- A valid witness proof implies approval of ALL prior entries

## Validation Checklist (Resolver)

For each log entry in order:
1. Merge parameters into active parameter set
2. Verify Data Integrity proof (signed by active `updateKeys`)
3. Verify `versionId`: version number increments by 1, entry hash valid
4. Verify `versionTime`: UTC ISO8601, monotonically increasing, not in future
5. First entry only: verify SCID
6. If pre-rotation active: verify `updateKeys` hashes are in previous `nextKeyHashes`
7. If witnesses active: retrieve and verify `did-witness.json`

Flag invalid entries; entries after first invalid are also invalid.
