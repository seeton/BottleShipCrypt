# BottleShip

BottleShip is experimental research on **capacity-bounded destructive residual decryption**.

An archive larger than its configured threshold cannot be decrypted as a whole. To read any part of it, the user must choose a subset to keep and prune everything else. After pruning, only the remaining subset is intended to stay decryptable.

## Important model distinction

This repository contains two distinct artifacts:

- **Weak browser demo** (`docs/index.html`) — a GitHub Pages-friendly visualization of the BottleShip archive structure, bottle/ship metaphor, and weak-model state transition using browser-side cryptography and simulated capsule deletion, including the same weak-model flow when exploring sample or uploaded images.
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

- redesigned weak browser demo in `docs/index.html`
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

The redesigned browser experience is intended to make the bottle/ship metaphor more explicit while still showing the weak-model mechanics: a sealed oversized archive, keep-set selection, destructive prune, and residual decrypt once the remaining bytes fit under the threshold. That same weak-model simulator can now be explored with sample images, uploaded images, or the existing archive-visualization flow. It visualizes archive chunk layout, simulated capsule presence/deletion, threshold versus remaining bytes, and archive state transitions without claiming strong-model security.

## Running the Go CLI simulator

Run:

```text
go run ./cmd/bship help
```

Use weak mode for archive-only behavior, or `--mode simulated-strong --trusted-store <path>` for the local trusted-store simulator. The older `--mode strong` spelling is still accepted as a compatibility alias, but `simulated-strong` is the preferred name. This remains a local simulator, not production security.

For reproducible demo/test artifacts, `bship seal` also supports `--deterministic` and optional `--archive-id`. That mode fixes metadata/randomness so fixtures can be regenerated exactly; it is only for testing/demo reproducibility, not for real security.

Example simulator sequence:

```text
mkdir -p example && printf 'abcdefgh' > example/plaintext.bin

go run ./cmd/bship seal \
  --in example/plaintext.bin \
  --out example/sample.bship \
  --threshold 4 \
  --chunk-size 4 \
  --mode simulated-strong \
  --trusted-store example/trusted-store.json

go run ./cmd/bship inspect \
  --archive example/sample.bship \
  --mode simulated-strong \
  --trusted-store example/trusted-store.json

go run ./cmd/bship prune \
  --archive example/sample.bship \
  --keep 0 \
  --mode simulated-strong \
  --trusted-store example/trusted-store.json

go run ./cmd/bship decrypt \
  --archive example/sample.bship \
  --out example/recovered.bin \
  --mode simulated-strong \
  --trusted-store example/trusted-store.json
```

With the `4`-byte threshold and `4`-byte chunk size above, the archive starts oversized, `prune --keep 0` keeps only the first chunk, and `decrypt` writes the remaining plaintext (`abcd`) to `example/recovered.bin`.

## License

Apache-2.0.
