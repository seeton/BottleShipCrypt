# Trusted-component exploration for the strong model

This note is a **next-step design exploration**, not an implementation claim.

It is anchored to the BottleShip strong-model state machine in `SPEC.md` and `SECURITY_PROOF.md`, and to the current local simulator in `trusted_store.go`. Today the simulator keeps only a local JSON record of:

```text
(archive_id, version, root, wrap_key)
```

That is useful for demonstrations and tests, but it is **not** the trusted component assumed by the proof. A real direction has to replace or harden that simulator boundary so that the trusted component, not the host filesystem, is authoritative for:

- current authenticated root
- current version / anti-rollback state
- key unsealing authority
- irreversible invalidation of excluded chunk keys

## What a real direction must realize

For an archive lineage, the trusted side still has to implement the same four operations:

- `Seal`: create chunk-key handles and initialize `(version, root, live set, threshold)`
- `Inspect`: report state only for the current authenticated root
- `Prune`: atomically validate current root, enforce threshold, invalidate excluded chunks, and advance state
- `Decrypt`: release plaintext only for the currently live set when the size bound is satisfied

The main evaluation questions come directly from `SECURITY_PROOF.md`:

1. **Trusted key unsealing:** can only the trusted side release live chunk material?
2. **Irreversible destruction / invalidation:** after prune, can excluded chunk handles ever be made usable again?
3. **Rollback resistance:** can the host replay older roots, metadata, or wrapped capsules?
4. **No pre-prune escape:** can future-to-be-destroyed keys leak before prune?
5. **Operational completeness:** can the direction support the BottleShip state machine without impossible latency, storage, or recovery assumptions?

## 1. Remote trusted service API

### Why it is the most actionable first exploration

This is the cleanest way to turn the current simulator boundary into a real trust boundary without pretending that local files are secure. The host can keep storing ciphertext chunks and manifests, but the service becomes authoritative for the current root, version, and key-handle policy.

### Minimal service-owned state per archive

The service should own at least:

```text
archive_id
current_version
current_root
threshold_bytes
chunk metadata summary
live chunk set or destroyed chunk set
trusted key handles or wrapped-key policy
audit log cursor
```

That is the real counterpart of the current simulator record in `trusted_store.go`, plus the live-set information that the strong model needs.

### Concrete API shape

A reasonable first API is compare-and-swap based:

#### `POST /v1/archives`

Registers a newly sealed archive.

Request should include:

- `archive_id`
- `manifest_hash` or canonical state root input
- `threshold_bytes`
- chunk identifiers and plaintext sizes
- chunk key handles or wrapped chunk keys

Response should include:

- `version = 0`
- `current_root`
- service receipt / audit record id

#### `GET /v1/archives/{archive_id}`

Returns the authoritative current state summary:

- `version`
- `current_root`
- `remaining_plaintext_bytes`
- live/destroyed chunk summary
- `decrypt_allowed`

#### `POST /v1/archives/{archive_id}/prune`

Request:

- `expected_root`
- `expected_version`
- `keep_chunk_ids`

Server behavior:

1. load authoritative state
2. reject if `expected_root` or `expected_version` is stale
3. recompute keep-set size from authoritative chunk sizes
4. reject if keep-set size exceeds threshold
5. invalidate excluded handles
6. increment version
7. commit new root
8. append audit log entry

Response:

- `new_version`
- `new_root`
- `destroyed_chunk_ids`
- audit record id

#### `POST /v1/archives/{archive_id}/decrypt`

Request:

- `expected_root`
- `expected_version`

Safer response options:

- service-side plaintext stream, or
- short-lived per-chunk decrypt session that does **not** expose a reusable archive-wide unwrap capability

Returning raw long-lived chunk keys is the weakest API choice because it enlarges what escapes the trusted boundary.

### Why it could satisfy the strong-model assumptions

It can satisfy the proof target **if**:

- the service is the only authority for current root/version
- the service never honors stale roots
- excluded handles are actually invalidated server-side
- key material never escapes before prune except through accepted decrypt behavior
- host-visible state is treated only as a cache or transcript

### Why it can fail

It fails the strong model if any of the following are true:

- the database is only advisory and old rows can still drive unwrap
- service operators can duplicate future-to-be-destroyed keys outside the policy boundary
- prune is not atomic with root/version advancement
- decrypt or inspect trusts host-provided chunk-size or live-set claims
- the audit log is informative only, but not tied to authoritative state transitions

This direction shifts trust from hardware claims to service design and operator controls. That is acceptable only if the service boundary is explicitly the trusted component.

### Actionable next steps

1. Define a canonical authenticated root format for `(archive_id, version, threshold, live set, manifest hash)`.
2. Specify `expected_root` / `expected_version` compare-and-swap semantics for `prune` and `decrypt`.
3. Decide whether decrypt returns plaintext, one-shot decrypt tickets, or wrapped live-chunk keys.
4. Add explicit failure semantics for partial prune, duplicate requests, and client retries.
5. Define the audit record schema so every accepted prune/decrypt can be tied to one authoritative root transition.

## 2. TPM monotonic state

### What TPMs are good at here

A TPM is most useful as an **anti-rollback anchor**, not as the whole BottleShip trusted component. The natural fit is storing or protecting:

- a monotonic version / NV counter
- a digest of the current authenticated root
- possibly an archive wrap key sealed to TPM policy

### How it could map to BottleShip

The practical pattern is:

1. ciphertext chunks and manifest remain host-visible
2. host-visible wrapped chunk material is encrypted under an archive wrap key
3. the archive wrap key is sealed behind TPM policy
4. prune advances TPM-backed version state and updates the authenticated root digest
5. decrypt is allowed only when the archive's presented root matches the TPM-trusted current root/version

This makes TPM state the authoritative rollback check while some other mechanism still manages chunk-key invalidation.

### Why it can help satisfy the strong model

A TPM-backed monotonic counter can directly support the assumption in `SPEC.md` that old versions are rejected after prune. It is a concrete way to replace the simulator's locally editable `version` field with something the host cannot simply rewrite in a JSON file.

### Why TPM state alone is not enough

By itself, TPM state does **not** solve trusted unsealing of all BottleShip chunk keys and does **not** guarantee irreversible destruction of excluded chunk material.

Failure modes:

- old wrapped chunk keys still exist outside the TPM and remain decryptable
- the TPM tracks version, but the key path does not enforce the same current root
- counter increment and root update are not atomic, leaving ambiguous recovery states
- NV storage limits or write-rate limits make per-prune updates impractical

So TPM monotonic state is best treated as one primitive inside a larger design, not as the whole answer.

### Actionable next steps

1. Decide whether the TPM protects only `(version, root_digest)` or also seals an archive wrap key.
2. Define the exact prune transaction: when the counter increments, when the new root digest is committed, and how crash recovery works.
3. Quantify whether one TPM update per prune is operationally acceptable.
4. Pair the TPM design with either an HSM-backed unwrap service or a TEE that actually enforces chunk-key invalidation.

## 3. HSM-backed key unsealing

### Best fit

An HSM is the strongest candidate in this list for **trusted key custody**. It is the most direct answer to the proof assumption that only the trusted component can unseal chunk keys.

### Two realistic patterns

#### Pattern A: HSM stores a non-exportable archive KEK

- host stores wrapped per-chunk keys
- HSM unwraps a chunk key only after policy approval

This is scalable, but only if some authoritative state layer tells the HSM-facing service which chunk IDs are still live.

#### Pattern B: HSM stores per-chunk objects / handles

- each chunk key is an HSM-managed object or handle
- prune deletes or disables handles for excluded chunks

This better matches irreversible invalidation, but may be heavy for large archives.

### Why it could satisfy the strong model

HSM-backed unsealing can satisfy:

- **trusted key unsealing**, because raw key custody remains inside the HSM
- **irreversible invalidation**, if excluded handles are deleted or permanently disabled inside the HSM boundary

This is much closer to the proof target than the current simulator's local `wrap_key_b64` file entry.

### Why it can still fail

An HSM alone does **not** provide authoritative rollback-resistant state unless paired with one.

Failure modes:

- the host replays old wrapped chunk keys against a stateless unwrap API
- policy about the live set lives only in a rollbackable external database
- an operator exported keys before prune or provisioned the HSM in an exportable mode
- chunk invalidation happens in external metadata, not inside the HSM trust boundary

So "put keys in an HSM" is necessary for key custody, but insufficient for the whole strong model.

### Actionable next steps

1. Choose between archive-KEK wrapping and per-chunk HSM handles.
2. Define which state must live with the HSM-facing service: `current_root`, `version`, live set, and threshold.
3. Require non-exportable key policy and explicit destroy/disable semantics for excluded chunks.
4. Combine the HSM path with either TPM-backed anti-rollback state or a remote trusted service that owns compare-and-swap root transitions.

## 4. TEE-backed rollback-resistant storage

### Best fit

A TEE is the most direct way to approximate the idealized strong model **inside one execution boundary**, because it can in principle hold both:

- authoritative BottleShip state
- key-unsealing logic

### Intended BottleShip mapping

Inside the enclave / trusted execution boundary:

- store `(archive_id, version, root, threshold, live set)`
- keep archive KEK or per-chunk handles
- verify host-presented state against enclave state
- on prune, recompute keep-set size, invalidate excluded handles, advance version, commit new root
- on decrypt, release plaintext only for the enclave-approved live set

### Why it could satisfy the strong model

If the TEE truly provides:

- confidential key custody
- authenticated code identity / attestation
- storage that resists rollback

then it can cover more of the proof assumptions in one place than TPM-only or HSM-only designs.

### Why this is also the riskiest interpretation

Many TEE deployments fail BottleShip's needs precisely on rollback resistance:

- sealed storage is often host-stored and therefore replayable
- monotonic counters may be weak, unavailable, expensive, or platform-specific
- anti-rollback often requires an external service anyway
- side-channel and patch-management risk is higher than the idealized proof model admits

A TEE without a real anti-rollback mechanism collapses back toward the weak model for the `version/root` part of the state machine.

### Actionable next steps

1. Treat rollback resistance as the gating question, not enclave confidentiality alone.
2. Define whether the TEE gets its anti-rollback guarantee from native monotonic storage, a TPM, or a remote monotonic service.
3. Keep host-visible `state.json` explicitly non-authoritative; enclave state must be the source of truth.
4. Require remote attestation in any design where another party is expected to trust the enclave as the BottleShip boundary.

## Comparison against the strong-model assumptions

| Direction | Trusted unsealing | Irreversible invalidation | Rollback resistance | Main gap |
| --- | --- | --- | --- | --- |
| Remote trusted service API | Potentially yes | Potentially yes | Potentially yes | depends on service/operator trust and atomic state transitions |
| TPM monotonic state | Partial | No, not by itself | Strong candidate | needs a separate key-custody / invalidation mechanism |
| HSM-backed unsealing | Strong candidate | Possible if handles are destroyed in-HSM | Weak alone | needs authoritative anti-rollback state |
| TEE-backed storage | Potentially yes | Potentially yes | Only if anti-rollback is real | rollback and side-channel assumptions are the hard part |

## Recommended sequence for repository follow-up

1. **First:** specify the remote trusted service API, because it is the easiest way to turn the current simulator fields into a concrete authoritative boundary.
2. **Second:** decide whether that service should use an **HSM** for key custody.
3. **Third:** evaluate **TPM monotonic state** as either a local anti-rollback anchor or as a primitive used by the service host.
4. **Fourth:** explore **TEE-backed storage** only with an explicit anti-rollback story, not as a generic "hardware security" placeholder.

That sequencing stays honest about the current repository status: the local trusted-store simulator demonstrates the state machine, while these directions are candidate ways to approach a real trusted component.
