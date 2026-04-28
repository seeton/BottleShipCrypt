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
- root Go package — `.bship` archive prototype, CLI logic, and local trusted-store simulator
- `cmd/bship/` — Go CLI entrypoint for `seal`, `inspect`, `prune`, and `decrypt`
- `docs/` — weak browser demo for GitHub Pages
- `prototype/` — reserved future workspace; the current Go prototype lives at the repository root
- `test-vectors/` — reserved future deterministic vectors; no formal fixtures are shipped yet

## Current state

Implemented today:

- weak browser demo in `docs/index.html`
- Go `.bship` archive and CLI prototype with `seal`, `inspect`, `prune`, and `decrypt`
- local trusted-store simulator for the simulated-strong path
- tests covering threshold refusal, destroyed capsules, weak copy-before-prune, and simulated rollback rejection
- `SECURITY_PROOF.md` for the idealized strong trusted-state model

Across the demo and simulator, the core state transition is:

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

The CLI and trusted-store path are still a **simulator**, not a real strong trusted component. They model authenticated state, versioning, and rollback checks for local experimentation, but they do not by themselves provide the strong-model security argued in `SECURITY_PROOF.md`.

## Running the demo

Open `docs/index.html` in a modern browser, or publish the `docs/` directory with GitHub Pages.

The demo runs entirely in the browser with Web Crypto API and keeps simulated key capsules only in memory. It is useful for understanding the state machine, not for enforcing the strong BottleShip property.

## Running the Go CLI simulator

Run:

```text
go run ./cmd/bship help
```

Use weak mode for archive-only behavior, or `--mode simulated-strong --trusted-store <path>` for the local trusted-store simulator. This remains a local simulator, not production security.

## License

Apache-2.0.
