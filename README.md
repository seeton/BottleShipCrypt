# BottleShip

BottleShip is an experimental model for **capacity-bounded destructive residual decryption**.

An archive larger than its configured threshold cannot be decrypted as a whole. To read any part of it, the user must choose a subset to keep and prune everything else. After pruning, only the remaining subset is decryptable.

## Research prototype warning

This repository is a **weak-model browser prototype**, not a secure implementation.

It demonstrates:

- chunk encryption
- threshold-based refusal
- keep-set selection
- simulated key-capsule deletion
- residual decryption of the remaining subset

It does **not** provide:

- irreversible destruction
- rollback resistance
- copy resistance
- trusted key custody
- protection against modified JavaScript or hostile local users

Do not use this project to protect real secrets.

## Repository contents

- `README.md` — project overview
- `SPEC.md` — archive and algorithm specification
- `SECURITY.md` — prototype limitations and security policy
- `FAQ.md` — positioning and common questions
- `TODO.md` — roadmap
- `docs/` — static browser demo for GitHub Pages
- `prototype/` — space for future archive and CLI prototypes
- `test-vectors/` — space for future deterministic vectors

## First milestone

The current milestone is a GitHub Pages-friendly browser demo in `docs/index.html`.

It shows the state transition:

```text
sealed oversized archive
        |
        | choose keep set
        v
destructive prune
        |
        | if remaining size <= threshold
        v
residual decrypt
```

## Running the demo

Open `docs/index.html` in a modern browser, or publish the `docs/` directory with GitHub Pages.

The demo runs entirely in the browser with Web Crypto API and keeps simulated key capsules only in memory.

## License

Apache-2.0.
