# Security Policy

## Experimental status

BottleShip is experimental software.

The current implementation is not suitable for protecting production secrets.

## Main limitation

The core BottleShip property requires that the user cannot copy and later restore the pre-pruned archive state.

Normal filesystems, browser storage, and GitHub Pages demos cannot enforce this.

## Weak prototype limitations

The prototype may demonstrate:

- chunk encryption
- threshold-based refusal
- keep-set selection
- capsule deletion
- residual decryption

The prototype cannot guarantee:

- irreversible destruction
- rollback resistance
- copy resistance
- trusted key custody
- protection against malicious local users
- protection against modified JavaScript

## Reporting vulnerabilities

Open an issue for design flaws, cryptographic misuse, or implementation bugs.

Do not use this project for real confidential data.
