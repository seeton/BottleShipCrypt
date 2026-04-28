# BottleShip Security Argument in the Strong Trusted-State Model

## 1. Claim and scope

This document gives a rigorous but readable security argument for BottleShip **only in the strong trusted-state model**.

The claim is not that the browser demo is secure. The claim is not that ordinary filesystems provide secure deletion. The claim is not that any particular TPM, TEE, HSM, browser, operating system, or hardware platform is secure merely because BottleShip is documented here.

The proof target is narrower:

> an idealized trusted component can realize the BottleShip state machine so that the core BottleShip properties hold, under explicit assumptions.

Browser and CLI code outside that trusted component are best understood as **demonstrations or simulations** of the state machine. They may be useful for UX, archive formatting, or local experimentation, but they are not the object proved secure here.

## 2. Strong trusted-state model

We divide the system into two parts.

### 2.1 Trusted component

The trusted component is assumed to:

- hold the authoritative current state for an archive
- authenticate the current manifest/root and state version
- control unsealing of per-chunk decryption keys
- irreversibly destroy or invalidate excluded chunk capsules during prune
- reject rollback to older state

### 2.2 Untrusted host

The host includes browser code, CLI code, local files, archive storage, UI, and transport.

The host may:

- store ciphertext chunks
- store or relay manifest data
- request `Seal`, `Inspect`, `Prune`, and `Decrypt`
- display outputs to the user

The host is **not** trusted to enforce irrecoverability, key custody, or rollback resistance.

### 2.3 Why the strong model matters

If the pre-pruned state can be copied and later restored, then a user can prune one copy to one subset, another copy to a different subset, and eventually recover more than the threshold. Ordinary filesystems and browser demos do not prevent that.

Accordingly, BottleShip can be argued secure only when the authoritative state and key-unsealing authority live in a trusted component with rollback resistance.

## 3. Idealized functionality

Fix an archive identifier `A`, threshold `T`, chunk index set `I`, plaintext chunk sizes `s_i`, ciphertexts `C_i`, and independent per-chunk keys `k_i`.

The trusted component maintains state:

```text
State(A) = (
  version v,
  live set L subseteq I,
  threshold T,
  authenticated root rho,
  key handles for chunks in L
)
```

Initially, `L = I`.

The authenticated root `rho` binds at least the archive identifier, manifest identity, live set, threshold, and version.

### 3.1 Seal

`Seal(M, T)` splits plaintext into chunks, samples independent chunk keys, encrypts each chunk with AEAD, creates a trusted handle for each key, sets `L = I`, initializes version `v = 0`, and commits the initial authenticated root `rho_0`.

### 3.2 Inspect

`Inspect(A, rho)` succeeds only if `rho` matches the trusted current root. It returns public metadata, the current live set or its summary, remaining plaintext size `sum_{i in L} s_i`, and whether decryption is currently allowed.

### 3.3 Prune

`Prune(A, rho, K)` accepts only if:

- `rho` is the current authenticated root
- `K subseteq L`
- `sum_{i in K} s_i <= T`

On acceptance, the trusted component irreversibly destroys or invalidates all key handles for `L \ K`, sets `L := K`, increments the version, and commits a new authenticated root.

### 3.4 Decrypt

`Decrypt(A, rho)` accepts only if:

- `rho` is the current authenticated root
- `sum_{i in L} s_i <= T`

On acceptance, the trusted component unseals keys only for chunks in `L`, and the host receives plaintext only for those chunks.

Destroyed chunks are never accepted for unsealing again in that archive lineage.

## 4. Assumptions

The argument relies on the following assumptions.

1. **AEAD security.** Chunk ciphertexts are protected by a secure AEAD scheme with correct nonce discipline and standard integrity/confidentiality guarantees.
2. **Independent chunk keys.** Distinct chunks use independent keys or equivalently strong key separation.
3. **Authenticated manifest and root.** The manifest identity and current state root are cryptographically authenticated so the host cannot substitute stale or mixed metadata without detection.
4. **Trusted key unsealing.** Only the trusted component can unseal chunk keys, and it does so only for accepted operations on currently live chunks.
5. **Irreversible capsule destruction.** When prune excludes a chunk, the corresponding capsule or trusted handle is destroyed or invalidated so later accepted operations cannot recover that key.
6. **Rollback-resistant state.** The trusted component stores authoritative state in a way that rejects older versions or roots.
7. **No pre-prune copy from inside the trusted component.** Before prune, no usable copy of future-to-be-destroyed chunk keys or capsules escapes from the trusted boundary.

These assumptions are exactly where real systems become difficult. This document argues the state machine under those assumptions; it does not prove that every candidate hardware implementation satisfies them.

## 5. Core properties

### 5.1 Capacity Soundness

If the plaintext size of the current live set exceeds `T`, then `Decrypt` is refused.

### 5.2 Residual Completeness

If the plaintext size of the current live set is at most `T`, then an honest caller with the current authenticated root can decrypt every chunk in the live set.

### 5.3 Destructive Irrecoverability

After an accepted `Prune(A, rho, K)`, no later accepted execution in that archive lineage reveals plaintext for any chunk in `L_old \ K`.

### 5.4 Rollback Resistance

After state advances from version `v` to `v + 1`, any attempt to operate using a root or state from version `v` or earlier is rejected.

### 5.5 Bounded Disclosure

Apart from public metadata and plaintext intentionally returned by accepted `Decrypt` calls on the current live set, the adversary learns no additional plaintext about destroyed or still-encrypted chunks, except with negligible probability.

## 6. Main theorem

**Theorem (informal strong-model security of BottleShip).**
Under the assumptions in Section 4, any probabilistic polynomial-time adversary interacting with a BottleShip implementation whose trusted component realizes the functionality in Section 3 can cause only the following plaintext disclosure, except with negligible probability:

- plaintext explicitly released by accepted `Decrypt` on the current live set,
- and whatever public metadata the system intentionally exposes.

Moreover, for every accepted archive lineage:

1. **Capacity Soundness:** `Decrypt` is never accepted when the authenticated live-set size exceeds `T`.
2. **Residual Completeness:** whenever the authenticated live-set size is at most `T`, accepted decryption returns every live chunk.
3. **Destructive Irrecoverability:** after an accepted prune to keep set `K`, no later accepted operation reveals plaintext for chunks outside `K` in that lineage.
4. **Rollback Resistance:** old authenticated roots are not accepted after state advances.
5. **Bounded Disclosure:** ciphertexts, manifests, and post-prune state do not reveal additional plaintext for destroyed or undecrypted chunks beyond the allowed outputs above.

## 7. Proof sketch

### 7.1 Capacity Soundness

The trusted component computes decryptability from the authenticated current live set, not from host claims. Because `Decrypt` checks `sum_{i in L} s_i <= T` before any key unsealing, no accepted decrypt can exceed the threshold.

### 7.2 Residual Completeness

For each live chunk `i in L`, the trusted component still retains a valid key handle for `k_i`. By assumption, live handles remain usable and AEAD decryption is correct, so every live chunk decrypts successfully when the size bound is satisfied.

### 7.3 Destructive Irrecoverability

After `Prune(A, rho, K)`, all handles for chunks outside `K` are irreversibly destroyed or invalidated. By trusted key-unsealing, accepted future operations can only obtain keys through the trusted component. By the no-pre-prune-copy assumption, no usable copy of excluded keys escaped beforehand. Therefore later accepted executions cannot recover excluded plaintext.

### 7.4 Rollback Resistance

Each accepted state transition commits a new authenticated root and version. Because authoritative state is rollback resistant, attempts to reuse older roots are rejected before any destructive or decrypting action is accepted.

### 7.5 Bounded Disclosure

For chunks whose keys are not unsealed, confidentiality reduces to AEAD security and metadata authentication. Independent chunk keys prevent compromise of one chunk from directly yielding another. Since the trusted component releases plaintext only for accepted decrypts of the current live set, the adversary's learned plaintext is bounded to those outputs plus public metadata.

## 8. What this theorem does not prove

This theorem does **not** prove that:

- ordinary files on disk are undeletable or uncopyable
- browser demos enforce destructive irrecoverability
- CLI code outside the trusted component is itself a secure implementation
- a particular TEE, TPM, HSM, or remote service is free of side channels, bugs, or operator compromise
- plaintext remains protected after the system intentionally releases it

Those are engineering and platform questions outside the idealized proof target.

## 9. Practical reading of the result

The right interpretation is:

- BottleShip is a plausible **strong-model** construction concept.
- Its proof target is an idealized trusted component.
- Browser and CLI implementations outside that component are useful for demonstrating or simulating the state machine.
- The current Go simulator realizes authenticated manifest/root binding with SHA-256 over Go JSON serialization of fixed structs; that is a prototype mechanism, not yet a language-independent canonicalization standard.
- Ordinary filesystems and browser demos do not satisfy the strong model, so they do not realize the full BottleShip security claim.
