# Prototype workspace

This directory is reserved for future implementation stages and design notes. It does not currently contain the active browser demo or the current Go CLI/archive simulator. Those live in `docs/` and at the repository root (for example `cmd/bship`) respectively.

Planned work here includes:

- archive import and export
- `.bship` format experiments
- CLI prototype code
- trusted-state simulator work

Anything added here before a trusted component exists should be treated as a **state-machine demonstration or simulation**.

Strong-model work in this directory is intended to model the proof target from `SECURITY_PROOF.md`, not to claim blanket security for the host machine or hardware platform.

Nothing here should claim production security without trusted key custody, irreversible capsule destruction, and rollback-resistant state.
