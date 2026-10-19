# WebAuthn test vectors

Data for the passkey verifier's tests (M5 design O.1 and O.2) and for the software
authenticator's self-test (`tests/fakes/test_authenticator.py`). All byte values are lowercase hex.

- `16.2.json` and `16.4.json` to `16.13.json`: the test vectors of W3C Web Authentication Level 3,
  §16, one file per section.
- `known-answer.json`: our own vectors, one positive case per algorithm, with UV set.

## Source

W3C Recommendation, 25 August 2026:
<https://www.w3.org/TR/2026/REC-webauthn-3-20260825/>, fetched on 2026-10-19 from
<https://www.w3.org/TR/webauthn-3/> (the same document). Each file's `source` links its section.
§16.1 (the attestation CA), §16.3 and §16.14 to §16.16 (other attestation formats, which the
verifier never reads) and §16.17 (extensions) aren't copied. All vectors use RP ID `example.org`
and origin `https://example.org`.

## Fields

Copied from the spec unchanged (the spec's name in brackets): `credential_key` (the credential's
private key, under the spec's own field names: `credential_private_key`, `private_key`, or
`private_key_p` and `private_key_q` for RSA, whose modulus is their product and whose exponent is
65537); for both ceremonies, `challenge`, `client_data_json` (`clientDataJSON`); for
registration, `credential_id`, `aaguid` and `attestation_object` (`attestationObject`); for
authentication, `authenticator_data` (`authenticatorData`) and `signature`.

Worked out here:

- `registration.authenticator_data`: what `getAuthenticatorData()` would give, cut by hand from
  the attestation object. That object is a CTAP2-canonical CBOR map whose keys sort as `fmt`,
  `attStmt`, `authData`, so `authData` is its last entry: the text key `68 61 75 74 68 44 61 74 61`,
  a byte-string head (`58 nn` for fewer than 256 bytes, `59 nn nn` otherwise), then the
  authenticator data, which runs to the end of the object. The self-test checks every file against
  this rule, and rebuilds the bytes from their parts (RP ID hash, flags, counter, AAGUID, credential
  ID and the COSE key from the private key).
- `registration.public_key`: what `getPublicKey()` would give, the SPKI DER of the credential's
  public key, made from `credential_key` with `cryptography`.
- `algorithm`: the COSE `alg` in the vector's credential public key; `flags`: byte 32 of each
  `authenticator_data`.
- `expected`: the outcome under our verifier (design D.3), a refusal `reason` or `accepted`.

## Expected outcomes

The verifier requires UV and runs D.3's checks in order: client data, then flags, then the key.
Each registration is checked with the vector's challenge, RP ID and origin. Each assertion is
checked against a credential record made from the vector (its credential ID and key, the
registration's BE, a stored counter of 0), as a step-up with an empty or matching allow list: the
vectors carry no user handle, which a login requires (`user_handle`). `null` means no assertion is
run, because no credential of that algorithm can be enrolled.

| § | Vector | Algorithm | Registration flags | Registration | Assertion flags | Assertion |
| --- | --- | --- | --- | --- | --- | --- |
| 16.2 | no attestation | ES256 (-7) | `0x59` UP BE BS AT | `not_verified` | `0x19` UP BE BS | `not_verified` |
| 16.4 | `"crossOrigin": true` | ES256 (-7) | `0x45` UP UV AT | `cross_origin` | `0x05` UP UV | `cross_origin` |
| 16.5 | `topOrigin` | ES256 (-7) | `0x41` UP AT | `cross_origin` | `0x05` UP UV | `cross_origin` |
| 16.6 | 1023-byte credential ID | ES256 (-7) | `0x49` UP BE AT | `not_verified` | `0x0d` UP UV BE | `accepted` |
| 16.7 | packed | ES256 (-7) | `0x4d` UP UV BE AT | `accepted` | `0x0d` UP UV BE | `accepted` |
| 16.8 | packed | ES384 (-35) | `0x59` UP BE BS AT | `not_verified` | `0x0d` UP UV BE | `null` |
| 16.9 | packed | ES512 (-36) | `0x4d` UP UV BE AT | `key_encoding` | `0x19` UP BE BS | `null` |
| 16.10 | packed | RS256 (-257) | `0x5d` UP UV BE BS AT | `accepted` | `0x19` UP BE BS | `not_verified` |
| 16.11 | packed | EdDSA, Ed25519 (-8) | `0x41` UP AT | `not_verified` | `0x01` UP | `not_verified` |
| 16.12 | packed | Ed448 (-53) | `0x59` UP BE BS AT | `not_verified` | `0x1d` UP UV BE BS | `null` |
| 16.13 | TPM | ES256 (-7) | `0x4d` UP UV BE AT | `accepted` | `0x0d` UP UV BE | `accepted` |

Notes:

- §16.4 and §16.5 are refused on their client data before their flags are read. §16.5 carries
  both `"crossOrigin": true` and `topOrigin`, and the `crossOrigin` check comes first.
- §16.6's registration has UV clear, so only its assertion is a positive case.
- §16.9 passes the flag checks; its 146-byte P-521 key matches no template.
- §16.10's key has a 3482-bit modulus (n is 436 bytes, the COSE key 452 bytes, the template's
  len + 16), within the verifier's 2048 to 4096 bits. Its registration has UV set, its assertion
  doesn't.
- §16.12's registration has UV clear, so it is refused as `not_verified` before its key is
  looked at; its 68-byte Ed448 key alone would be `key_encoding`.
- The ES384, ES512 and Ed448 keys (110, 146 and 68 bytes) match none of the templates; every
  ES256 key is 77 bytes and the Ed25519 key 42.
- Every vector's counter is 0, and no vector sets ED.

## Our known answers

`known-answer.json` has one case per algorithm for RP ID `localhost` and origin
`http://localhost:8081`, each accepted at registration and at assertion. Inputs: the credential's
private key (made from fixed labels with SHA-256; the RSA 2048 primes were generated once with
`cryptography`), the credential ID, AAGUID, user handle, challenges and the authenticator's
backup and counter behaviour. Outputs: what the page would post (`client_data_json`,
`authenticator_data`, `public_key`, `public_key_algorithm`, `signature`, `user_handle`). ECDSA
signs with RFC 6979 nonces, so every output is fixed; the self-test makes each case again with
`tests/fakes/authenticator.py` and compares every byte.

| Case | Algorithm | Registration flags | Assertion flags | Counter |
| --- | --- | --- | --- | --- |
| `es256-synced` | ES256 (-7) | `0x5d` UP UV BE BS AT | `0x1d` UP UV BE BS | 0 |
| `eddsa-security-key` | EdDSA (-8) | `0x45` UP UV AT | `0x05` UP UV | 1 |
| `rs256-platform` | RS256 (-257), 2048 bits | `0x45` UP UV AT | `0x05` UP UV | 1 |
