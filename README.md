# webauthn-sign
ECDSA digital signatures with WebAuthn

![Build Status](https://github.com/pantonov/webauthn_sign/workflows/Go/badge.svg)

---
This package implements digital signatures with WebAuthn. It depends on [DuoLabs WebAuthn library](https://github.com/duo-labs/webauthn).

## Example
For full example, see https://github.com/pantonov/webauthn-sign-example .

## Principles
WebAuthn uses ECDSA-P256 signatures to verify user credentials. However, it cannot be used for general purpose 
digital signatures as-is, because WebAuthn authenticators mix in various auxiliary data (such as origin, signature
counter, etc.) into the data prior to signing. This can be resolved by creating compound signature which carries such 
auxiliary data along with ECDSA signature. This package defines this compound signature as `Signature` type.

The verification process is also slightly different: first, we check if challenge from `Signature` matches the hash
of our data, and then we re-create full signature data (including auxiliary data from `Signature`) before checking
ECDSA signature. This works because challenge in `Signature` can't be tampered with, otherwise ECDSA verification 
will fail.

## Workflow
1. Register authenticator (hardware key) in the same way as for authentication, this provides `webauthn.Credential`
2. Use `PrepareSignatureAssertion` and `ParseSignatureCredentialsResponse` when interacting with authenticator 
 (see [example](https://github.com/pantonov/webauthn-sign-example) for details). The
 latter takes reply from authenticator and generates `Signature`
3. Use `Signature.Verify` (or `Signature.VerifySha256`) methods to verify signature of your data, 
 providing it with `Credential.PublicKey`.

## License

MIT

