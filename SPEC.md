# BottleShip Specification

## 1. Terminology

### Archive

A sealed collection of encrypted chunks, metadata, key capsules, and policy.

### Chunk

A byte range of the original input data.

```text
Di = plaintext chunk
Ci = encrypted chunk
ki = chunk encryption key
Ei = key capsule for ki
```

### Key capsule

A sealed object containing or deriving the key material required to decrypt one chunk.

In a production system, key capsules should only be opened by a trusted component.

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

## 2. Archive structure

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

## 3. Manifest

Example:

```json
{
  "format": "bottleship-v0",
  "archive_id": "uuid",
  "threshold_bytes": 10485760,
  "chunk_size_bytes": 1048576,
  "created_at": "2026-04-29T00:00:00Z",
  "crypto": {
    "aead": "AES-GCM-256",
    "kdf": "HKDF-SHA-256",
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

## 4. State

Example:

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

In a weak prototype, this file is local and user-modifiable.

In a strong model, equivalent state must be held by a trusted component and must be rollback-resistant.

## 5. Algorithms

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
```

Process:

```text
1. Split plaintext into chunks.
2. Generate a random key for each chunk.
3. Encrypt each chunk with AEAD.
4. Create a key capsule for each chunk.
5. Write manifest.
6. Write initial state.
```

### 5.2 Inspect

Input:

```text
archive
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
1. Load manifest.
2. Load state.
3. Validate archive_id.
4. Compute remaining chunk size.
5. Report whether remaining size <= threshold.
```

### 5.3 Prune

Input:

```text
archive
keep_set
```

Output:

```text
updated archive state
destroyed or invalidated capsules
```

Process:

```text
1. Load manifest and state.
2. Validate current state.
3. Compute keep_set size.
4. If keep_set size > threshold, refuse.
5. For every chunk not in keep_set:
   - destroy or invalidate its key capsule
   - mark chunk as destroyed
6. Increment state version.
7. Update current manifest hash or state root.
8. Save updated state.
```

### 5.4 Decrypt

Input:

```text
archive
```

Output:

```text
remaining plaintext chunks
```

Process:

```text
1. Load manifest and state.
2. Validate current state.
3. Compute remaining size.
4. If remaining size > threshold, refuse.
5. For each remaining chunk:
   - open its key capsule
   - decrypt ciphertext
   - write plaintext output
6. Refuse destroyed chunks.
```

## 6. Security properties

### Capacity soundness

If the remaining decryptable size is greater than the threshold, decryption is refused.

### Residual completeness

If the remaining decryptable size is less than or equal to the threshold, all remaining chunks can be decrypted.

### Destructive irrecoverability

Destroyed chunks cannot be decrypted from the remaining archive state.

In the weak model, this property only holds if the user has not copied the archive or capsules before pruning.

### Rollback resistance

Old archive states must not be accepted after pruning.

This requires trusted state storage. A local prototype cannot enforce this property.

### Copy resistance

BottleShip cannot prevent copying by itself.

Copy resistance requires trusted hardware, remote custody, or another external enforcement mechanism.

## 7. Non-goals

BottleShip does not attempt to:

- prevent copying in a normal file system
- protect against malicious browsers
- provide DRM
- protect against compromised trusted hardware
- make deleted plaintext disappear from previously exported outputs
- replace legal or organizational access controls

## 8. Production requirements

A production implementation requires:

- HSM, TPM, TEE, or remote trusted service
- monotonic counter or equivalent anti-rollback state
- authenticated manifest roots
- secure deletion of key capsules
- AEAD misuse resistance review
- side-channel review
- audit logging
- recovery policy
- key rotation policy
