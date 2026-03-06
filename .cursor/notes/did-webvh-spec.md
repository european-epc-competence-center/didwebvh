# did:webvh Specification Notes

> Source: `/spec/spec-v1.0/` (local copy of the v1.0 spec)
> Online: https://identity.foundation/didwebvh/v1.0/
> Info site: https://didwebvh.info/latest/

## Overview

`did:webvh` (DID Web + Verifiable History) enhances `did:web` with a cryptographically verifiable, tamper-evident history — without a ledger.

## Key Differences from did:web

| Feature | did:web | did:webvh |
|---|---|---|
| DID document file | `did.json` | `did.jsonl` (log) |
| Verifiable history | No | Yes (microledger chain) |
| SCID | No | Yes (self-certifying) |
| Key rotation proofs | No | Yes (Data Integrity proofs) |
| Pre-rotation keys | No | Optional |
| Witnesses | No | Optional |
| Portability | No | Optional |
| Watchers | No | Optional |

## DID Format (ABNF)

```abnf
webvh-did = "did:webvh:" scid ":" domain-segment 1+("." domain-segment) [percent-encoded-port] *(":" path-segment)
scid = 46(base58-alphabet)
percent-encoded-port = "%3A" ("1"|"2"|...|"9") 1*4(DIGIT)
```

- SCID is always the **first** element after `did:webvh:`
- Domain/path uses `:` as separator (same as `did:web`)
- Port colon must be percent-encoded as `%3A`

## DID-to-HTTPS Transformation

Steps (applied by both controller and resolver):
1. Remove `did:webvh:` prefix
2. Remove SCID segment
3. Transform domain: decode percent-encoded port, apply Unicode normalization (RFC3491), apply IDNA/Punycode (RFC9233)
4. Transform path: percent-encode segments (RFC3986), replace `:` with `/`
5. Reconstruct URL:
   - No path: `https://{domain}/.well-known/did.jsonl`
   - With path: `https://{domain}/{path}/did.jsonl`
   - With port: `https://{domain}:{port}/...`

Content-Type of `did.jsonl` SHOULD be `text/jsonl`.

### Examples
- `did:webvh:{SCID}:example.com` → `https://example.com/.well-known/did.jsonl`
- `did:webvh:{SCID}:example.com:dids:issuer` → `https://example.com/dids/issuer/did.jsonl`
- `did:webvh:{SCID}:example.com%3A3000:dids:issuer` → `https://example.com:3000/dids/issuer/did.jsonl`
- `did:webvh:{SCID}:jp納豆.例.jp:用户` → `https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl`

Witnesses file: same URL with `did.jsonl` → `did-witness.json`

## DID Log File (`did.jsonl`)

JSON Lines format — one compact JSON object per line (`\n` terminated, no extra whitespace).

JSON schema: `/spec/schemas/v1.0/log_entry.json`

Each log entry structure:
```json
{
  "versionId": "1-{entryHash}",
  "versionTime": "2025-01-23T04:12:36Z",
  "parameters": { ... },
  "state": { /* DIDDoc */ },
  "proof": [ /* Data Integrity proof(s) */ ]
}
```

Required fields: `versionId`, `versionTime`, `parameters`, `state`. `proof` is required after creation.

## Parameters

| Parameter | Type | First entry | Later entries | Default |
|---|---|---|---|---|
| `method` | string | MUST | MAY (to upgrade) | — |
| `scid` | string | MUST | MUST NOT | — |
| `updateKeys` | array | MUST | MAY | — |
| `nextKeyHashes` | array | optional | retained if absent | `[]` |
| `witness` | object | optional | retained if absent | `{}` |
| `watchers` | array | optional | retained if absent | `[]` |
| `portable` | boolean | optional | retained (can't change false→true) | `false` |
| `deactivated` | boolean | optional | retained | `false` |
| `ttl` | integer | optional | retained if absent | `3600` |

**Important rules:**
- `null` MUST NOT be used for any parameter (use typed empty values: `[]`, `{}`, `false`)
- Resolvers SHOULD gracefully accept legacy `null` and treat as default value
- `method` for v1.0: `"did:webvh:1.0"` — permits SHA-256 hash, `eddsa-jcs-2022` cryptosuite
- `portable` can ONLY be set `true` in the first entry; once `false`, cannot change

## Cryptographic Operations

### Algorithms (v1.0)
- Hash: **SHA-256** (RFC6234)
- Encoding: **base58btc** (draft-msporny-base58-03)
- Hash format: **multihash** (algorithm-prefixed)
- Signature: **Data Integrity** with `eddsa-jcs-2022` (DI-EDDSA-V1.0), `proofPurpose: assertionMethod`
- JSON canonicalization: **JCS** (RFC8785)
- Key format: **multikey** (multibase-encoded)

### SCID Generation
```
SCID = base58btc(multihash(JCS(preliminary_log_entry), SHA-256))
```
Preliminary log entry for SCID calculation:
- `versionId`: literal `"{SCID}"`
- `versionTime`: current UTC ISO8601 time
- `parameters`: complete initial params with `{SCID}` placeholders
- `state`: initial DIDDoc with `{SCID}` placeholders

### SCID Verification (resolver)
1. Extract first log entry, get `scid` from parameters
2. Determine hash algorithm from multihash prefix of `scid`
3. Remove `proof` from entry
4. Replace `versionId` value with `"{SCID}"`
5. Text-replace the actual SCID value with `{SCID}` throughout the entry string
6. Run Generate SCID function → result MUST match extracted `scid`

### Entry Hash Generation
```
entryHash = base58btc(multihash(JCS(entry_without_proof), SHA-256))
```
Where `entry.versionId` is set to the **predecessor's** `versionId` (or SCID for first entry).

`versionId` format: `"{version_number}-{entryHash}"` (e.g. `"1-QmXxx..."`)

### Entry Hash Verification (resolver)
1. Extract `entryHash` from `versionId` (after the `-`)
2. Determine hash algorithm from multihash prefix
3. Remove `proof` from entry
4. Set `versionId` to predecessor's `versionId` (or SCID for first entry)
5. Calculate hash → MUST match extracted `entryHash`

### Pre-rotation Key Hash
```
hash = base58btc(multihash(multikey, SHA-256))
```
Where `multikey` is the multikey-encoded public key.

## DID Operations

### Create
1. Define DID string with `{SCID}` placeholder
2. Generate authorization key pair(s) → multikey format → `updateKeys`
3. Create initial DIDDoc (with `{SCID}` placeholders everywhere)
4. Build preliminary log entry (no `proof`, `versionId = "{SCID}"`)
5. Calculate SCID → replace all `{SCID}` placeholders
6. Calculate entry hash → set `versionId = "1-{entryHash}"`
7. Generate Data Integrity proof (signed by `updateKeys` key)
8. Add proof to entry → serialize as JSON Line
9. If witnesses configured: collect threshold of witness proofs → publish `did-witness.json` FIRST
10. Publish `did.jsonl`; notify watchers via webhook

### Resolve
1. Transform DID → HTTPS URL (DID-to-HTTPS Transformation)
2. HTTPS GET `did.jsonl` (use DNS-over-HTTPS per RFC8484 to prevent tracking)
3. For each log entry in order:
   a. Merge parameters from entry into active parameter set
   b. Verify Data Integrity proof (signed by active `updateKeys`)
      - If witnesses active: retrieve and verify `did-witness.json`
   c. Verify `versionId`: version number increments by 1, entry hash is valid
   d. Verify `versionTime`: UTC ISO8601, monotonically increasing, not in future
   e. First entry only: verify SCID
   f. If pre-rotation active: verify `updateKeys` hashes are in previous `nextKeyHashes`
   g. Collect: DIDDoc, versionId, versionTime, updateKeys, nextKeyHashes, all params
4. Flag invalid entries; entries after first invalid are also invalid
5. Return: latest valid DIDDoc (or specific version via query params)

**Query parameters:**
- `?versionId=` — MUST be supported; full `versionId` string match
- `?versionTime=` — MUST be supported; ISO8601, returns DIDDoc active at that time
- `?versionNumber=` — SHOULD be supported; integer matching version number prefix

**Resolution metadata returned:**
```json
{
  "versionId": "1-Qm...", "versionTime": "...", "created": "...", "updated": "...",
  "scid": "...", "portable": false, "deactivated": false,
  "ttl": "3600",  // string (DID-RESOLUTION spec requires no integers in metadata)
  "witness": { "threshold": "2", "witnesses": [...] },  // threshold also string
  "watchers": [...]
}
```

**Error codes:**
- `notFound` — DID Log or resource not found
- `invalidDid` — any error rendering the DID invalid
- SHOULD include `problemDetails` (RFC9457) with `type`, `title`, `detail`

### Update
1. Modify DIDDoc; set new `parameters` (or `{}` if unchanged)
2. Build preliminary entry: `versionId` = previous entry's `versionId`, new `versionTime`, new `state`
3. Calculate new `versionId` (incremented version number + new entry hash)
4. Generate Data Integrity proof
5. If witnesses: collect threshold proofs → publish `did-witness.json` BEFORE `did.jsonl`
6. Append new entry to `did.jsonl`, publish; notify watchers

### Deactivate
- Add `"deactivated": true` to parameters in a new log entry
- Resolver MUST NOT return DIDDoc; MUST include `"deactivated": true` in metadata
- Alternative: set `updateKeys: []` without `deactivated: true` (DIDDoc still returned)
- If pre-rotation active: requires two entries (first to stop pre-rotation, then set `updateKeys: []`)

## Authorized Keys

- Active `updateKeys` for **first entry**: keys defined in that entry
- Active `updateKeys` **without pre-rotation**: keys from the most recent **prior** entry
- Active `updateKeys` **with pre-rotation**: keys from the **current** entry being verified

## Optional Features

### Pre-rotation Keys
- Activated by setting `nextKeyHashes` to a non-empty array
- While active: `nextKeyHashes` and `updateKeys` MUST be in every entry
- Each `updateKeys` entry's hash MUST appear in previous `nextKeyHashes`
- Deactivate: set `nextKeyHashes: []` (pre-rotation rules still apply to that entry; next entry uses normal rules)
- After rotating: revealed private key SHOULD be securely destroyed

### Witnesses
- Witness DIDs MUST be `did:key` DIDs
- `threshold`: integer 1..len(witnesses); MUST be met or exceeded
- Witness proofs file: `did-witness.json` (same base URL as `did.jsonl`)
- `did-witness.json` MUST be published BEFORE the new `did.jsonl` entry
- Resolver MUST ignore proofs for unpublished log entries
- A valid witness proof implies approval of ALL prior entries
- Witness proofs use `eddsa-jcs-2022`, `proofPurpose: assertionMethod`

`did-witness.json` structure:
```json
[{ "versionId": "1-Qm...", "proof": [{...}, {...}] }, ...]
```

### DID Portability
- `portable: true` MUST be set in first entry (only)
- To move: change `id` in DIDDoc to new domain
- Old DID MUST appear in `alsoKnownAs`
- SCID remains the same; full log history preserved
- Resolvers MUST ignore prior domain components for trust evaluation

### Watchers
- Monitor DIDs, cache verified state, detect inconsistencies
- Listed in `watchers` parameter (URLs)
- Watcher HTTP API (OpenAPI spec: `/spec/watcherOpenAPI/watcher-v1.0.0.yml`):
  - `GET <watcher>/log?scid=<SCID>` — get DID log
  - `POST <watcher>/log?did=<DID>` — notify of update
  - `POST <watcher>/log/delete?scid=<SCID>` — request deletion (Data Integrity proof in body)
  - `GET <watcher>/witness?scid=<SCID>` — get witness file
  - `GET <watcher>/resource?scid=<SCID>&path=<path>` — get resource
  - `POST <watcher>/resource?scid=<SCID>&path=<path>` — notify of resource update
  - `POST <watcher>/resource/delete?scid=<SCID>&path=<path>` — request resource deletion

### DID URL Resolution

**Path resolution** (`<did>/path/to/file`):
- Implicit `#files` service: `{ "id": "#files", "type": "relativeRef", "serviceEndpoint": "https://{domain}/" }`
- Resolves to `https://{domain}/path/to/file` (`.well-known/` removed)
- Can be overridden by explicit `#files` service in DIDDoc

**`/whois` resolution** (`<did>/whois`):
- Implicit `#whois` service: `{ "type": "LinkedVerifiablePresentation", "serviceEndpoint": "<base>/whois.vp" }`
- Returns `whois.vp` (media type `application/vp`) — a W3C VCDM Verifiable Presentation
- VP MUST be signed by the DID; MUST contain at least one VC with DID as `credentialSubject.id`
- Can be overridden by explicit `#whois` service in DIDDoc

### Publishing Parallel `did:web`
1. Start with resolved `did:webvh` DIDDoc
2. Add implicit `#files` and `#whois` services if not present
3. Text-replace `did:webvh:{SCID}:` → `did:web:` throughout
4. Add `did:webvh` DID to `alsoKnownAs`
5. Remove duplicates from `alsoKnownAs`
6. Publish as `did.json`

## JSON Schema (log_entry.json)

Key constraints from `/spec/schemas/v1.0/log_entry.json`:
- `proof` can be a single `DataIntegrityProof` object or an array of them
- `dataIntegrityProof.type` MUST be `"DataIntegrityProof"`
- `dataIntegrityProof.cryptosuite` MUST be `"eddsa-jcs-2022"`
- `dataIntegrityProof.proofPurpose` MUST be `"assertionMethod"`
- Required proof fields: `type`, `cryptosuite`, `verificationMethod`, `proofPurpose`, `proofValue`
- `witness.threshold` MUST be integer ≥ 1
- `updateKeys` and `nextKeyHashes`: unique string arrays, minItems 1

## Security Considerations (key points for implementation)

- All network communication MUST use HTTPS (TLS)
- CORS header required: `Access-Control-Allow-Origin: *`
- Resolvers SHOULD remember latest `versionId` and warn on truncated logs
- Resolvers SHOULD NOT cache DIDs that fail verification
- Conflicting parallel updates: publication MUST enforce monotonic extension
- DNS portion used only for discovery, NOT for trust/control verification
- Post-quantum: pre-rotation provides flexibility for future algorithm migration

## Privacy Considerations (key points)

- Use DNS-over-HTTPS (RFC8484) during resolution to prevent tracking
- DID Log is public — never include sensitive data
- CORS `Access-Control-Allow-Origin: *` required for browser-based resolution
- Right to erasure (GDPR): depends on watcher governance; watchers SHOULD cache indefinitely

## Existing Implementations (not Java)

- TypeScript: https://github.com/decentralized-identity/didwebvh-ts
- Python: https://github.com/decentralized-identity/trustdidweb-py
- Go: https://github.com/nuts-foundation/trustdidweb-go (v0.3 only)
- Rust: https://github.com/decentralized-identity/didwebvh-rs (WIP)
- Server (Python): https://github.com/decentralized-identity/trustdidweb-server-py
- ACA-Py Plugin: https://plugins.aca-py.org/latest/webvh/

**No Java implementation exists** — this project fills that gap.
Typical implementation size: ~1500–2000 lines of code.
