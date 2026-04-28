# BottleShip GitHub Pages Demo

This directory contains the static browser demo.

The demo runs entirely in the browser using Web Crypto API.

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

This demo does not provide real security.

The browser state can be copied, modified, inspected, or rolled back.  
The JavaScript can be changed by the user.  
The key capsules are simulated in memory.  
Destruction is simulated.

A real implementation requires trusted hardware or a trusted service.
