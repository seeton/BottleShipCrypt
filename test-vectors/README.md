# Test vectors, fixtures, and reproducible attack demos

This directory now ships executable CLI demos for the two attack stories that the current repository can already show:

- `weak-copy-before-prune-demo.sh` — weak-mode attack: copying the archive before pruning lets you prune different copies and recover the full plaintext anyway.
- `simulated-strong-stale-root-demo.sh` — simulated-strong demo: a copied pre-prune archive is rejected after the trusted-store simulator advances to a newer authenticated root.
- `run-attack-demos.sh` — convenience wrapper that runs both demos in sequence.

Run both demos:

```sh
./test-vectors/run-attack-demos.sh
```

Run them individually:

```sh
./test-vectors/weak-copy-before-prune-demo.sh
./test-vectors/simulated-strong-stale-root-demo.sh
```

Each script creates a workspace under `test-vectors/workspaces/<demo-name>/` containing the generated archives, decrypted outputs, and (for the simulator path) the local trusted-store JSON file.

## What each demo proves

### Weak mode

The weak-mode archive carries all decryption material inside the archive itself. Because of that, copying the archive before prune defeats the intended one-way effect: one copy can keep chunk `0`, another can keep chunk `1`, and the attacker can combine both decryptions back into the original plaintext.

### Simulated-strong mode

Use `--mode simulated-strong` for the current local trusted-store simulator. The older `--mode strong` spelling is only a compatibility alias.

In this simulator, stale archive rejection happens only because the local `--trusted-store` file remembers the newer `(version, root)` pair after prune. A copied pre-prune archive then fails with `archive state does not match trusted store`. This is a **local simulator behavior**, not a claim that the host machine, filesystem, or hardware provides real strong-model security.

If you want to reproduce the steps manually instead of running the scripts, the scripts themselves are the authoritative command transcripts for the current CLI.

## Deterministic fixture set

This directory also ships **prototype / simulator fixtures** for the current JSON `.bship` format. They are regression-test material, not production-security artifacts.

- `weak-simulator-two-chunk/`
  - deterministic weak-mode archive before prune
  - deterministic weak-mode archive after pruning to one chunk
  - expected inspect outputs and residual plaintext
- `weak-simulator-three-chunk-tail/`
  - deterministic weak-mode archive with three chunks sized `4/4/2`
  - pruned fixture keeps the tail two chunks, so decrypt yields the residual plaintext `EFGHIJ`
  - `expected.json` also records that the sealed fixture still refuses decryption because it remains above threshold
- `simulated-strong-two-chunk/`
  - deterministic simulated-strong archive before prune
  - deterministic simulated-strong archive after pruning to one chunk
  - matching trusted-store simulator state for each archive version
  - expected inspect outputs and residual plaintext
- `simulated-strong-three-chunk-stale-copy/`
  - deterministic simulated-strong archive with three chunks sized `4/4/3`
  - pruned fixture keeps non-adjacent chunks, so decrypt yields the residual plaintext `ABCDIJK`
  - `expected.json` also records stale-store rejection for the pre-prune sealed archive when it is checked against the post-prune trusted-store simulator state

Fixture generation is stabilized with:

- fixed archive IDs
- fixed `created_at` timestamp
- deterministic pseudo-random bytes instead of real randomness
- small readable plaintexts and fixed keep-sets, including three-chunk tail and non-adjacent survivor cases

`go test ./...` runs `TestDeterministicVectorFixtures`, which regenerates these artifacts in-memory and checks that the checked-in files still match exactly, still inspect/decrypt as documented, and still exhibit the simulator-only stale trusted-store behavior described above.
