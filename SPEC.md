# BottleShip Specification

## 1. Conformance models

This repository describes one state machine instantiated in two different ways.

### Weak browser demo

The browser demo stores ciphertext, manifest, and effective state in ordinary browser-controlled memory and files.

It can demonstrate the intended workflow, but it cannot enforce irreversible destruction, trusted key custody, or rollback resistance.

### Strong-model simulator / proof target

The strong model assumes an idealized **trusted component** that:

- authenticates the current manifest root and version
- unseals per-chunk keys only for accepted operations
- irreversibly destroys excluded chunk capsules during prune
- maintains rollback-resistant authoritative state

All security claims in `SECURITY_PROOF.md` refer to this strong model only.

## 2. Terminology

### Archive

A sealed collection of encrypted chunks, metadata, key capsules or capsule handles, and policy.

### Chunk

A byte range of the original input data.

```text
Di = plaintext chunk
Ci = encrypted chunk
ki = chunk encryption key
Ei = key capsule or trusted handle for ki
```

### Trusted component

The idealized component that holds authoritative BottleShip state, controls key unsealing, validates the current authenticated root, and performs irreversible capsule destruction.

### Host code

Browser or CLI code outside the trusted component.

Host code may store files, display UI, and request operations, but in the strong model it is not trusted to enforce security properties.

### Threshold

The maximum total plaintext size that may remain decryptable after pruning.

```text
threshold = n bytes
```

### Keep set

The set of chunks selected by the user for preservation and later decryption.

### Prune

The destructive operation that invalidates all chunks outside the keep set.

### Residual decryption

Decryption of only the remaining, non-destroyed chunks.

## 3. Archive structure

A BottleShip archive consists of:

```text
archive/
  manifest.json
  state.json
  chunks/
    00000001.chunk
    00000002.chunk
    ...
  capsules/
    00000001.cap
    00000002.cap
    ...
```

In the weak demo, `state.json` and `capsules/` are only simulated local state.

In the strong model, the authoritative equivalent of `state.json` and capsule validity lives inside the trusted component, even if the host mirrors some metadata for convenience.

## 4. Manifest and state

### 4.1 Manifest

Example:

```json
{
  "format": "bottleship-v0",
  "archive_id": "uuid",
  "threshold_bytes": 10485760,
  "chunk_size_bytes": 1048576,
  "created_at": "2026-04-29T00:00:00Z",
  "crypto": {
    "chunk_aead": "AES-GCM-256",
    "capsule_aead": "AES-GCM-256",
    "hash": "SHA-256"
  },
  "chunks": [
    {
      "id": "00000001",
      "index": 0,
      "plaintext_size": 1048576,
      "ciphertext_size": 1048592,
      "ciphertext_hash": "base64url-sha256",
      "capsule_hash": "base64url-sha256",
      "destroyed": false
    }
  ],
  "manifest_hash": "base64url-sha256"
}
```

In the current Go prototype, `seal` does not derive chunk keys from a manifest-declared KDF. It samples independent random 256-bit chunk keys and a random 256-bit capsule-wrap key directly from `crypto/rand`, then records the AEAD and hash identifiers above.

### 4.2 State

Example host-visible state:

```json
{
  "archive_id": "uuid",
  "state_version": 0,
  "current_manifest_hash": "base64url-sha256",
  "destroyed_chunk_ids": [],
  "remaining_plaintext_bytes": 52428800,
  "threshold_bytes": 10485760,
  "sealed": true
}
```

In the strong model, the trusted component maintains an authenticated root over the current archive state, including at least:

- archive identifier
- current manifest hash or root
- live/destroyed chunk set
- threshold
- state version or monotonic counter

If a host-visible `state.json` exists, it is only a cache or transcript. The trusted component's state is authoritative.

### 4.3 Current prototype canonical hashing

The current Go prototype authenticates archive metadata with the following concrete hash inputs:

- `manifest_hash = SHA-256(json.Marshal(Manifest))`, with the `manifest_hash` field cleared before hashing
- `ciphertext_hash = SHA-256(chunk_nonce || chunk_ciphertext)`
- `capsule_hash = SHA-256(capsule_nonce || capsule_ciphertext)`
- `current_root = SHA-256(json.Marshal({archive_id, version, remaining_chunk_ids, remaining_plaintext_bytes, threshold_bytes, manifest_hash}))`

This is acceptable for the current single-implementation prototype because the same Go code writes and verifies the archive.

It is **not** yet a cross-language canonicalization contract. A production strong-model implementation must standardize the exact canonical bytes or use an explicit canonical encoding so that authenticated roots remain stable across implementations and upgrades.

## 5. Operations

The concise idealized operation definitions are expanded in `SECURITY_PROOF.md`. This section states the implementation-facing behavior.

### 5.1 Seal

Input:

```text
plaintext files
threshold_bytes
chunk_size_bytes
```

Output:

```text
BottleShip archive
initial authenticated state root
```

Process:

```text
1. Split plaintext into chunks.
2. Generate an independent key for each chunk.
3. Encrypt each chunk with AEAD.
4. Create a capsule or trusted handle for each chunk key.
5. Write manifest and ciphertexts.
6. Initialize trusted state root and version.
```

### 5.2 Inspect

Input:

```text
archive
presented root/state
```

Output:

```text
threshold
total size
remaining size
chunk list
whether decryption is currently allowed
```

Process:

```text
1. Load manifest and presented state.
2. Validate archive_id.
3. Validate the presented state against the trusted current root.
4. Compute remaining chunk size from the authenticated live set.
5. Report whether remaining size <= threshold.
```

### 5.3 Prune

Input:

```text
archive
keep_set
presented root/state
```

Output:

```text
updated trusted state
new authenticated root
invalidated excluded capsules
```

Process:

```text
1. Load manifest and presented state.
2. Validate the presented state against the trusted current root.
3. Compute keep_set size.
4. If keep_set size > threshold, refuse.
5. For every chunk not in keep_set:
   - irreversibly destroy or invalidate its capsule/handle
   - mark the chunk as destroyed in trusted state
6. Increment state version.
7. Commit the new authenticated state root.
```

### 5.4 Decrypt

Input:

```text
archive
presented root/state
```

Output:

```text
remaining plaintext chunks
```

Process:

```text
1. Load manifest and presented state.
2. Validate the presented state against the trusted current root.
3. Compute remaining size from the authenticated live set.
4. If remaining size > threshold, refuse.
5. For each remaining chunk:
   - unseal its key through the trusted component
   - decrypt ciphertext
   - write plaintext output
6. Refuse destroyed chunks.
```

## 6. Core security properties

These properties are argued only in the strong trusted-state model.

### Capacity soundness

If the currently decryptable plaintext size is greater than the threshold, decryption is refused.

### Residual completeness

If the currently decryptable plaintext size is less than or equal to the threshold, every remaining live chunk can be decrypted.

### Destructive irrecoverability

After an accepted prune, chunks outside the keep set cannot be recovered from the accepted post-prune archive lineage.

In the weak model, this fails if the user copied the pre-pruned archive state or capsules beforehand.

### Rollback resistance

Old authenticated roots or state versions are not accepted after pruning.

This requires trusted rollback-resistant state. Ordinary local files cannot enforce it.

### Bounded disclosure

Aside from public metadata and plaintext intentionally released by accepted decrypt operations, the archive does not reveal additional plaintext about destroyed or still-encrypted chunks.

This property depends on AEAD security, authenticated metadata, trusted key unsealing, and the absence of a pre-prune copy from inside the trusted component.

## 7. Non-goals

BottleShip does not attempt to:

- prevent copying in a normal filesystem
- protect against malicious browsers or modified JavaScript
- prove the security of arbitrary hardware by documentation alone
- provide DRM after plaintext has been released
- recover plaintext from destroyed chunks
- replace legal, organizational, or system access controls

## 8. Production requirements

A production implementation requires at least:

- a trusted component such as an HSM, TPM-backed service, TEE with anti-rollback state, or remote trusted service
- authenticated manifest roots and metadata binding
- a written canonicalization/canonical-hashing specification rather than implicit dependence on one language runtime's JSON serialization
- trusted key unsealing for live chunks only
- irreversible capsule destruction or equivalent key invalidation
- monotonic counter or equivalent anti-rollback state
- AEAD misuse review and key-separation review
- audit logging and failure semantics
- explicit recovery and key-rotation policy
