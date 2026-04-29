# BottleShip GitHub Pages Weak-Model Demo

This directory contains the static browser demo.

The demo runs entirely in the browser using Web Crypto API.
It is a weak-model visualization of BottleShip mechanics, not the strong trusted-state model.
The redesigned browser experience is intended to make the bottle/ship metaphor more explicit while still visualizing the archive structure and weak-model state transition, not just the controls.

For the current non-browser simulator path, use the Go CLI at the repository root in [`cmd/bship/`](https://github.com/seeton/BottleShipCrypt/tree/main/cmd/bship). The [`prototype/`](https://github.com/seeton/BottleShipCrypt/tree/main/prototype) directory is reserved for future prototype notes and strong-model work only; it does not contain the current simulator implementation.

## What it demonstrates

- splitting a file into chunks and showing the resulting archive layout
- presenting the archive through the BottleShip metaphor while keeping the simulator terminology grounded in chunks, capsules, threshold, and residual decrypt
- encrypting each chunk independently
- assigning a simulated key capsule to each chunk and showing whether it is still present
- comparing the remaining archive against the threshold and refusing decryption while it stays oversized
- walking through the weak-model archive states from sealed oversized archive to keep-set selection, prune, and residual decrypt
- selecting a keep set
- pruning all non-selected chunks
- showing which chunks remain available after prune and which capsules were deleted
- decrypting only the remaining chunks
- exporting a manifest for inspection

In practice, the redesigned page is meant to help you read the BottleShip metaphor and the archive state transition together: sealed oversized archive, keep-set choice, destructive prune, and residual decrypt once the remaining bytes fall at or below the threshold. It still shows weak-model indicators such as simulated capsule present/deleted state and remaining-bytes-versus-threshold status.

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
