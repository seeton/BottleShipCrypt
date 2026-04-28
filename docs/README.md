# BottleShip GitHub Pages Weak-Model Demo

This directory contains the static browser demo.

The demo runs entirely in the browser using Web Crypto API.
It is a weak-model visualization of BottleShip mechanics, not the strong trusted-state model.

The current non-browser BottleShip code lives at the repository root via the Go CLI in [`cmd/bship/`](https://github.com/seeton/BottleShipCrypt/tree/main/cmd/bship). The [`prototype/`](https://github.com/seeton/BottleShipCrypt/tree/main/prototype) directory is reserved for future prototype notes and strong-model work; it does not contain the current simulator implementation.

## What it demonstrates

- splitting a file into chunks
- encrypting each chunk independently
- assigning a simulated key capsule to each chunk
- refusing decryption when the remaining archive exceeds a threshold
- selecting a keep set
- pruning all non-selected chunks
- decrypting only the remaining chunks
- exporting a manifest for inspection

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

A real strong-model implementation requires trusted hardware or a trusted service with rollback-resistant state and irreversible capsule destruction. The current local CLI/archive experiments are separate Go code at the repository root, while `prototype/` remains future work.
