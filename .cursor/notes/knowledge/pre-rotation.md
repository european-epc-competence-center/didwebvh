# Pre-Rotation Keys in did:webvh

## What is Pre-Rotation?

Pre-rotation is an **optional** security mechanism where a DID controller **commits in advance** to the authorization keys that will be used in the *next* log entry. The commitment is a hash of each future key, stored in the `nextKeyHashes` parameter. This prevents an attacker who compromises the current signing keys from silently rotating to keys they control — because the next keys were already committed.

## How It Works

### Commitment Model: One Entry Ahead

Each entry's `nextKeyHashes` constrains **only the immediately next entry's** `updateKeys`. After that entry is published, fresh `nextKeyHashes` must be provided for the entry after that.

```
Entry N:   updateKeys=[keyA],  nextKeyHashes=[hash(keyB)]       ← commits to keyB
Entry N+1: updateKeys=[keyB],  nextKeyHashes=[hash(keyC)]       ← reveals keyB, commits to keyC
Entry N+2: updateKeys=[keyC],  nextKeyHashes=[hash(keyD)]       ← reveals keyC, commits to keyD
```

The chain ensures that at every step, the *next* key was committed before the current key was potentially compromised.

### Authorized Keys Under Pre-Rotation

Without pre-rotation, each entry is signed by a key from the **previous** entry's `updateKeys`. With pre-rotation active, each entry is signed by a key from the **current** entry's `updateKeys` — because those are the newly-revealed keys whose hashes were pre-committed.

| Scenario | Entry signed by |
|---|---|
| Genesis (first entry) | Keys in that entry's `updateKeys` |
| No pre-rotation | Previous entry's `updateKeys` |
| Pre-rotation active | Current entry's `updateKeys` |

## All Cases

### 1. Activating Pre-Rotation

Set `nextKeyHashes` to a non-empty array in any log entry. Pre-rotation takes effect *after* that entry is published — the entry itself is still signed under normal (previous-key) rules.

```
Entry 1: updateKeys=[keyA], nextKeyHashes=[hash(keyB)]    ← signed by keyA (normal rules)
Entry 2: updateKeys=[keyB], nextKeyHashes=[hash(keyC)]    ← signed by keyB (pre-rotation rules)
```

### 2. Ongoing Pre-Rotation

While active, **every entry MUST contain both `updateKeys` and `nextKeyHashes`** in its parameters — even if they haven't changed. All keys in `updateKeys` must have their hash in the previous entry's `nextKeyHashes`.

### 3. Re-Committing the Same Key

The spec says revealed keys *SHOULD* be destroyed (not MUST). So re-committing the same key is **technically valid**:

```
Entry N:   updateKeys=[keyA], nextKeyHashes=[hash(keyA)]
Entry N+1: updateKeys=[keyA], nextKeyHashes=[hash(keyA)]    ← valid but discouraged
```

This works because `hash(keyA)` is in Entry N's `nextKeyHashes`, satisfying the constraint. However, this defeats the purpose of pre-rotation (forward security) and is **strongly discouraged** by the spec.

### 4. Extra Hashes

A DID controller MAY include extra hashes in `nextKeyHashes` that are never used. They are simply ignored. This provides flexibility — e.g., committing to multiple possible future keys.

### 5. Deactivating Pre-Rotation

Set `nextKeyHashes: []` (empty array). Pre-rotation rules **still apply to that entry** (its `updateKeys` must match hashes from the previous `nextKeyHashes`). The *next* entry after that uses normal (non-pre-rotation) rules.

```
Entry N:   updateKeys=[keyB], nextKeyHashes=[hash(keyC)]    ← pre-rotation active
Entry N+1: updateKeys=[keyC], nextKeyHashes=[]              ← still follows pre-rotation rules; deactivates it
Entry N+2: updateKeys=[keyC]                                ← normal rules (signed by Entry N+1's keys)
```

### 6. Deactivation of DID with Pre-Rotation

If the DID uses pre-rotation and needs to be deactivated with `updateKeys: []`, two entries are required:
1. First entry: stop pre-rotation (`nextKeyHashes: []`)
2. Second entry: set `updateKeys: []` and `deactivated: true`

This is necessary because setting `updateKeys: []` while pre-rotation is active would require empty keys to have been pre-committed — which is contradictory.

## Validation Checks (Spec Requirements)

A resolver MUST verify the following when pre-rotation is active (previous entry had non-empty `nextKeyHashes`):

1. **`updateKeys` MUST be present** in the entry's parameters (not inherited)
2. **`nextKeyHashes` MUST be present** in the entry's parameters (not inherited)
3. **Every key in `updateKeys`** must have its hash (`base58btc(multihash(multikey, SHA-256))`) listed in the **previous** entry's `nextKeyHashes`
4. The entry's **proof must be signed** by a key from the current entry's `updateKeys` (not the previous entry's)
