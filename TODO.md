# TODO

## Phase 0: Repository setup

- [ ] Choose repository name: `bottleship`, `bship`, or `bottleship-crypto`
- [x] Add `README.md`
- [x] Add `SPEC.md`
- [x] Add `SECURITY.md`
- [x] Add license: Apache-2.0
- [x] Add `.gitignore`
- [x] Add `docs/` directory for GitHub Pages
- [x] Add warning banner: research prototype only

## Phase 1: Browser demo for GitHub Pages

- [x] Create static `docs/index.html`
- [x] Add file picker
- [x] Add threshold input
- [x] Split uploaded file into chunks
- [x] Encrypt chunks with Web Crypto API
- [x] Generate manifest JSON
- [x] Show total size and threshold
- [x] Disable decrypt button when total remaining size exceeds threshold
- [x] Add chunk selection UI
- [x] Implement prune operation
- [x] Mark non-selected chunks as destroyed
- [x] Delete in-memory key capsules for destroyed chunks
- [x] Allow decrypt only when remaining size <= threshold
- [x] Export decrypted remaining chunks
- [x] Export manifest for inspection
- [x] Add reset demo button

## Phase 2: Archive format prototype

- [x] Define `.bship` archive layout
- [ ] Support ZIP-like export or directory export
- [x] Store manifest JSON
- [x] Store encrypted chunks
- [x] Store simulated key capsules
- [x] Store simulated state
- [x] Add archive import
- [x] Add archive inspect
- [x] Add prune after import
- [x] Add decrypt after import

## Phase 3: CLI prototype

- [x] Choose language: Rust, Go, or Python
- [x] Implement `bship seal`
- [x] Implement `bship inspect`
- [x] Implement `bship prune`
- [x] Implement `bship decrypt`
- [ ] Add test vectors
- [ ] Add deterministic test mode
- [ ] Add corrupted manifest tests
- [x] Add destroyed capsule tests
- [x] Add threshold refusal tests
- [x] Add rollback simulation tests

## Phase 4: Strong-model simulation

Current items here refer to the local trusted-store simulator, not a real trusted component.

- [x] Implement local trusted-state simulator
- [x] Add state version
- [x] Add current root
- [x] Reject old roots
- [x] Simulate monotonic counter
- [x] Add attack demo: copy-before-prune succeeds in weak model
- [x] Add attack demo: rollback rejected in simulated strong model
- [x] Document why simulation is not production security

## Phase 5: Real trusted component exploration

- [ ] Research TPM NV counters
- [ ] Research HSM-backed key unwrap
- [ ] Research WebAuthn/secure enclave feasibility
- [ ] Research remote trusted service architecture
- [ ] Define service API
- [ ] Define threat model for server-side custody
- [ ] Add audit log model
- [ ] Add recovery and failure semantics

## Phase 6: Documentation

- [x] Add rigorous `SECURITY_PROOF.md`
- [x] Align top-level docs around weak demo vs strong-model proof target
- [ ] Add diagrams
- [ ] Add glossary
- [ ] Add examples
- [x] Add FAQ
- [ ] Add "Why not normal encryption?"
- [ ] Add "Why not secure deletion?"
- [ ] Add "Why not access control?"
- [ ] Add "Why GitHub Pages demo is weak"
- [ ] Add "Strong model requirements"

## Phase 7: Hardening

- [ ] Review AEAD usage
- [ ] Review nonce generation
- [ ] Review key derivation
- [ ] Review manifest canonicalization
- [ ] Review chunk ordering
- [ ] Review metadata authentication
- [ ] Add fuzz tests
- [ ] Add large-file tests
- [ ] Add memory-usage limits
- [ ] Add browser compatibility notes
