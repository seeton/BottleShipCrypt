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
