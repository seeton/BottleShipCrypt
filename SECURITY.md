# Security Policy

## Experimental status

BottleShip is experimental research software.

The current repository is not suitable for protecting production secrets.

## What security claim is actually being made?

BottleShip can be argued secure **only in the strong trusted-state model** described in `SECURITY_PROOF.md`.

That argument targets an **idealized trusted component** that holds authoritative state and key-unsealing authority. It is **not** a blanket proof that browsers, filesystems, TEEs, TPMs, HSMs, operating systems, or hardware are secure in general.

Browser code, local CLI code, archive-handling code, and any other logic outside the trusted component are demonstrations or simulations of the BottleShip state machine.

## Strong-model assumptions

The proof target assumes all of the following:

- secure AEAD encryption for chunk ciphertexts
- independent chunk keys
- authenticated manifest and authenticated current root/state
- trusted key unsealing for live chunks only
- irreversible capsule destruction or equivalent key invalidation
- rollback-resistant authoritative state
- no pre-prune copy from inside the trusted component

If any of these assumptions fail, the strong BottleShip claim may fail with them.

## Weak-model warning

Ordinary filesystems, browser storage, GitHub Pages demos, and modifiable JavaScript do **not** satisfy the strong model.

The weak prototype may demonstrate:

- chunk encryption
- threshold-based refusal
- keep-set selection
- simulated capsule deletion
- residual decryption

The weak prototype cannot guarantee:

- destructive irrecoverability
- rollback resistance
- trusted key custody
- bounded disclosure against malicious local users
- protection against modified JavaScript or hostile local environments

If a user can copy pre-pruned state and later restore it, BottleShip's strong property is not achieved.

## Current Go prototype cryptographic review

This section describes the code that currently ships in the Go prototype at the repository root. It is a concrete implementation review, not a claim that the prototype already satisfies the strong model.

### AEAD usage

- `SealFile` uses AES-256-GCM for both payload chunks and chunk-key capsules.
- Each chunk gets an independent random 32-byte chunk key. Each archive gets a random 32-byte capsule-wrap key.
- Chunk AEAD associated data binds `type`, `archive_id`, `chunk_id`, `index`, and `plaintext_size`.
- Capsule AEAD associated data binds `type`, `archive_id`, and `chunk_id`.

Prototype assessment:

- Acceptable for the current single-writer prototype: chunk keys are independent, metadata binding is explicit, and chunks/capsules are validated before use.
- Not sufficient for production strong-model security by itself: weak mode stores the wrap key inside archive state, and simulated-strong mode stores it in a local JSON trusted-store file. Both are demos of state handling, not secure key custody.

Production requirement:

- keep key custody inside a real trusted boundary
- review payload-key vs capsule-key separation explicitly
- pin crypto-suite identifiers as part of the authenticated design and migration story

### Nonce generation and handling

- The prototype generates a fresh 12-byte GCM nonce with `crypto/rand` for every chunk encryption and every capsule encryption.
- Because each chunk uses a fresh random chunk key, the nonce-discipline question is mostly per-key reuse, not global nonce reuse across the whole archive.
- Archive validation now rejects malformed chunk or capsule nonce lengths, and the AES-GCM helpers return an error instead of allowing invalid nonce input to panic the process.

Prototype assessment:

- Acceptable for the current prototype: nonces are sampled from the OS CSPRNG and never intentionally reused with the same key.
- Still a prototype choice: there is no persistent nonce-allocation protocol, misuse-resistant AEAD, or re-encryption story under a long-lived key.

Production requirement:

- specify nonce discipline as a protocol rule, not just a coding convention
- consider counters or misuse-resistant AEAD if the same key can be reused across updates
- treat nonce validation failures as authenticated-format failures with clear operational handling

### Key derivation story

- The current prototype does **not** implement a KDF.
- Instead, it samples chunk keys and the archive wrap key directly from `crypto/rand`.
- The manifest therefore records AEAD and hash choices, but no KDF identifier.

Prototype assessment:

- Acceptable for a local prototype because direct random-key generation is simple and avoids accidental cross-chunk key reuse.
- Incomplete for production: there is no password-based story, no root-key derivation tree, no domain-separated subkey schedule, no rotation policy, and no hardware-bound import/export design.

Production requirement:

- specify the root of trust for archive keys
- either keep random per-chunk keys inside trusted storage or derive them with an explicit domain-separated KDF
- define rotation, recovery, and crypto-suite versioning rules

### Manifest canonicalization and canonical hashing assumptions

- `manifest_hash` is currently `SHA-256(json.Marshal(manifest-with-manifest_hash-cleared))`.
- `current_root` is currently `SHA-256(json.Marshal({archive_id, version, remaining_chunk_ids, remaining_plaintext_bytes, threshold_bytes, manifest_hash}))`.
- `ciphertext_hash` and `capsule_hash` are `SHA-256(nonce || ciphertext)`.

Prototype assessment:

- Acceptable for the current Go-only prototype because the same implementation writes and re-validates the same fixed structs and slices.
- This is **not** yet a language-independent canonicalization spec. Another implementation would need to match Go's JSON serialization behavior exactly to reproduce the same hashes.
- The strong-model proof treats authenticated manifest/root binding abstractly; the current prototype realizes that binding with Go-struct JSON hashing, which is a useful prototype mechanism but not a finalized interoperability contract.

Production requirement:

- standardize the exact canonical bytes to be hashed, or adopt an explicit canonical encoding such as a canonical JSON profile or binary transcript
- version the canonicalization rules in the authenticated crypto suite
- document exactly which metadata fields are covered so future implementations cannot diverge silently

## Security properties intended in the strong model

The core target properties are:

- Capacity Soundness
- Residual Completeness
- Destructive Irrecoverability
- Rollback Resistance
- Bounded Disclosure

These are stated informally in `SPEC.md` and argued in `SECURITY_PROOF.md`.

## Reporting vulnerabilities

Open an issue for design flaws, cryptographic misuse, implementation bugs, or mismatches between the documentation and code.

Do not use this project for real confidential data.
