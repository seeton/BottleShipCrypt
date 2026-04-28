# BottleShip

BottleShip is experimental research on **capacity-bounded destructive residual decryption**.

An archive larger than its configured threshold cannot be decrypted as a whole. To read any part of it, the user must choose a subset to keep and prune everything else. After pruning, only the remaining subset is intended to stay decryptable.

## Important model distinction

This repository contains two distinct artifacts:

- **Weak browser demo** (`docs/index.html`) — a GitHub Pages-friendly demonstration of the BottleShip state machine using browser-side cryptography and simulated capsule deletion.
- **Strong-model simulator / proof target** — an idealized trusted component with authenticated state, trusted key unsealing, irreversible capsule destruction, and rollback resistance. This is the only model for which BottleShip can be argued secure; see `SECURITY_PROOF.md`.

Browser code, local CLI/archive code, and other logic outside the trusted component are **demonstrations or simulations** of the state machine. They are not themselves the proof target, and they do not amount to a blanket proof of browser, OS, filesystem, TEE, TPM, HSM, or hardware security.

Ordinary filesystems, browser storage, GitHub Pages hosting, and modifiable local JavaScript do **not** satisfy the strong trusted-state model. Do not use this repository to protect real secrets.

## Repository contents

- `README.md` — project overview and model split
- `SPEC.md` — archive and operation specification
- `SECURITY.md` — security posture, limitations, and assumptions
- `SECURITY_PROOF.md` — strong-model security argument for the idealized trusted component
- `FAQ.md` — positioning and common questions
- `TODO.md` — roadmap
- `docs/` — weak browser demo for GitHub Pages
- `prototype/` — future archive, CLI, and trusted-state simulator work
- `test-vectors/` — future deterministic vectors for weak and strong-model behavior

## Current milestone

The implemented milestone is the weak browser demo in `docs/index.html`.

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

The next research milestone is a **strong-model simulator** that keeps the authoritative root, version, and key-unsealing authority inside a modeled trusted component. That simulator is the intended implementation target for the argument in `SECURITY_PROOF.md`.

## Running the demo

Open `docs/index.html` in a modern browser, or publish the `docs/` directory with GitHub Pages.

The demo runs entirely in the browser with Web Crypto API and keeps simulated key capsules only in memory. It is useful for understanding the state machine, not for enforcing the strong BottleShip property.

## License

Apache-2.0.
