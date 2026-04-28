# FAQ

## Is BottleShip a new public-key cryptosystem?

No.

BottleShip is better described as an encrypted storage control model and state machine built around chunk encryption, destructive pruning, and threshold-gated residual decryption.

## What is actually being proved or argued?

Only this:

> an idealized trusted component can enforce BottleShip's core properties in the strong trusted-state model.

The proof target is the trusted component and its state machine, not a blanket proof of browser security, filesystem security, or hardware security.

## What are the core BottleShip properties?

The intended strong-model properties are:

- Capacity Soundness
- Residual Completeness
- Destructive Irrecoverability
- Rollback Resistance
- Bounded Disclosure

See `SECURITY_PROOF.md` for the argument and `SPEC.md` for the operational definitions.

## Why not just use normal encryption?

Normal encryption gives full decryption to anyone with the key.

BottleShip is trying to model a different rule:

> even an authorized user must choose a limited subset, and choosing that subset destroys access to the rest.

## Why not just delete files?

Deleting files after access does not prevent the user from copying them beforehand.

BottleShip is only strong when the pre-pruned state cannot be copied or restored from inside the trusted component's security boundary.

## Why not just use access control?

Access control usually answers:

> who may read this?

BottleShip asks:

> how much may still be read after a destructive choice has been made?

## Is this DRM?

No.

BottleShip does not try to control plaintext after it has already been decrypted and released.

## Can this be implemented securely in a browser?

No.

A browser demo can explain the mechanism, but ordinary browser storage and JavaScript execution do not provide irreversible destruction, trusted key custody, or rollback resistance.

## So what are the browser demo and future CLI for?

They are useful as **demonstrations or simulations** of the BottleShip state machine.

Outside the trusted component, browser and CLI code can show archive layout, manifest handling, and state transitions, but they are not the proof target.

## What is required for a real implementation?

A real implementation needs a trusted component such as:

- HSM
- TPM-backed storage or service
- TEE with anti-rollback state
- remote trusted service
- dedicated secure storage appliance

It also needs authenticated roots, trusted key unsealing, irreversible capsule destruction, and a rollback-resistant state store.

## What happens if the user copies the archive before pruning?

In the weak model, they can prune different copies and eventually recover more than the threshold.

In the strong model, the relevant assumption is that no usable pre-prune copy escapes from inside the trusted component, and old roots are rejected.

## What is the main research question?

Whether capacity-bounded destructive residual decryption is useful as a practical primitive for sealed archives, audit logs, sensitive datasets, or staged evidence disclosure when backed by a genuinely trusted state component.
