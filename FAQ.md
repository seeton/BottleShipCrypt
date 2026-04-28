# FAQ

## Is BottleShip a new public-key cryptosystem?

No.

BottleShip is better described as an encrypted storage control model.

It combines:

- chunk encryption
- key capsules
- destructive key invalidation
- capacity-bounded decryption
- rollback-resistant state

## Why not just use normal encryption?

Normal encryption gives full decryption to anyone with the key.

BottleShip tries to model a different rule:

> even an authorized user must choose a limited subset, and choosing that subset destroys access to the rest.

## Why not just delete files?

Deleting files after access does not prevent the user from copying them beforehand.

BottleShip only works strongly when the pre-pruned state cannot be copied or restored.

## Why not just use access control?

Access control usually answers:

> who may read this?

BottleShip asks:

> how much may be read before the rest becomes unrecoverable?

## Is this DRM?

No.

DRM usually attempts to stop users from copying data after access.

BottleShip does not try to control data after it has been decrypted and released.

## Can this be implemented securely in a browser?

No.

A browser demo can explain the mechanism, but it cannot enforce irreversible destruction or rollback resistance.

## What is required for a real implementation?

A real implementation needs one of:

- HSM
- TPM-backed storage
- TEE with anti-rollback storage
- remote trusted service
- dedicated secure storage appliance

## What happens if the user copies the archive before pruning?

In the weak model, they can prune different copies and eventually recover more than the threshold.

That breaks the intended strong property.

## What is the main research question?

Whether capacity-bounded destructive residual decryption is useful as a practical access-control primitive for sealed archives, audit logs, sensitive datasets, or evidence disclosure.
