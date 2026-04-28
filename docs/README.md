# BottleShip GitHub Pages Weak-Model Demo

This directory contains the static browser demo.

The demo runs entirely in the browser using Web Crypto API.
It is a weak-model visualization of BottleShip mechanics, not the strong trusted-state model.
It now visualizes the archive structure and state transition, not just the controls, so you can see chunk-by-chunk state change as you choose a keep set, prune, and decrypt.

For the current non-browser simulator path, use the Go CLI at the repository root in [`cmd/bship/`](https://github.com/seeton/BottleShipCrypt/tree/main/cmd/bship). The [`prototype/`](https://github.com/seeton/BottleShipCrypt/tree/main/prototype) directory is reserved for future prototype notes and strong-model work only; it does not contain the current simulator implementation.

## What it demonstrates

- splitting a file into chunks and showing the resulting archive layout
- encrypting each chunk independently
- assigning a simulated key capsule to each chunk and showing whether it is still present
- comparing the remaining archive against the threshold and refusing decryption while it stays oversized
- selecting a keep set
- pruning all non-selected chunks
- showing which chunks remain available after prune and which capsules were deleted
- decrypting only the remaining chunks
- exporting a manifest for inspection

In practice, the page lets you watch chunk rows move through available/destroyed state, see capsule present/deleted markers, and see when the remaining decryptable bytes drop below the threshold so residual decrypt becomes available.

## What it does not secure

This demo does not provide real security and must not be presented as the strong model.

The browser state can be copied, modified, inspected, or rolled back.  
The JavaScript can be changed by the user.  
The key capsules are simulated in memory.  
Destruction is simulated.

## Weak browser demo vs. strong trusted-state model

### Weak browser demo

- educational visualization in user-controlled JavaScript
- threshold-refusal and prune flow are simulated locally
- no trusted custody for capsules or archive state
- no rollback resistance or irreversible destruction

### Strong trusted-state model

- a trusted component holds the capsule/state boundary
- rollback-resistant state is required across operations
- capsule destruction must be irreversible when pruning
- this is the path relevant to real security claims

A real strong-model implementation requires trusted hardware or a trusted service with rollback-resistant state and irreversible capsule destruction. For the current non-browser simulator path, use the Go CLI at the repository root in `cmd/bship`; `prototype/` remains future work.
