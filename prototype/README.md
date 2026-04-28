# Prototype workspace

This directory is reserved for future implementation stages and design notes. It does not currently contain the active browser demo or the current non-browser simulator implementation. Those live in `docs/` and in the Go CLI at the repository root in `cmd/bship` respectively.

Planned work here includes:

- archive import and export
- `.bship` format experiments
- CLI prototype code
- trusted-state simulator work
- trusted-component design notes such as `trusted-component-exploration.md`

Anything added here before a trusted component exists should be treated as a **state-machine demonstration or simulation**.

Strong-model work in this directory is intended to model the proof target from `SECURITY_PROOF.md`, not to claim blanket security for the host machine or hardware platform.

Nothing here should claim production security without trusted key custody, irreversible capsule destruction, and rollback-resistant state.

See `trusted-component-exploration.md` for concrete next-step notes on remote trusted services, TPM-backed anti-rollback state, HSM-backed unsealing, and TEE-backed storage. That document is exploratory only; it does not claim that any real trusted component exists in this repository today.
