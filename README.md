# Go JOSE

<p>
  <a href="https://pkg.go.dev/authelia.com/provider/jose"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/go-reference-blue.svg?logo=go&logoColor=%2300add8&mode=dark&size=sm&variant=outline"><img alt="Go Reference" src="https://shieldcn.dev/badge/go-reference-blue.svg?logo=go&logoColor=%2300add8&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/jose-provider/actions/workflows/go.yml"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Factions%2Fworkflow%2Fstatus%2Fauthelia%2Fjose-provider%2Fgo.yml.json%3Fbranch%3Dmaster&query=%24.message&label=build&logo=githubactions&logoColor=%232088ff&mode=dark&size=sm&variant=outline"><img alt="Build" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Factions%2Fworkflow%2Fstatus%2Fauthelia%2Fjose-provider%2Fgo.yml.json%3Fbranch%3Dmaster&query=%24.message&label=build&logo=githubactions&logoColor=%232088ff&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/jose-provider/tags"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fv%2Ftag%2Fauthelia%2Fjose-provider.json%3Fsort%3Dsemver&query=%24.message&label=release&logo=github&mode=dark&size=sm&variant=outline"><img alt="Release" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fv%2Ftag%2Fauthelia%2Fjose-provider.json%3Fsort%3Dsemver&query=%24.message&label=release&logo=github&logoColor=%23181717&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://github.com/authelia/jose-provider/blob/master/go.mod"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fgo-mod%2Fgo-version%2Fauthelia%2Fjose-provider.json&query=%24.message&label=go&logo=go&logoColor=%2300add8&mode=dark&size=sm&variant=outline"><img alt="Go Version" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fgithub%2Fgo-mod%2Fgo-version%2Fauthelia%2Fjose-provider.json&query=%24.message&label=go&logo=go&logoColor=%2300add8&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://codecov.io/gh/authelia/jose-provider"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fcodecov%2Fc%2Fgithub%2Fauthelia%2Fjose-provider.json&query=%24.message&label=coverage&logo=codecov&logoColor=%23f01f7a&mode=dark&size=sm&variant=outline"><img alt="Codecov" src="https://shieldcn.dev/badge/dynamic/json.svg?url=https%3A%2F%2Fimg.shields.io%2Fcodecov%2Fc%2Fgithub%2Fauthelia%2Fjose-provider.json&query=%24.message&label=coverage&logo=codecov&logoColor=%23f01f7a&mode=light&size=sm&variant=outline"></picture></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><picture><source media="(prefers-color-scheme: dark)" srcset="https://shieldcn.dev/github/authelia/jose-provider/license.svg?logo=apache&logoColor=%23d22128&mode=dark&size=sm&variant=outline"><img alt="License" src="https://shieldcn.dev/github/authelia/jose-provider/license.svg?logo=apache&logoColor=%23d22128&mode=light&size=sm&variant=outline"></picture></a>
</p>

<p align="center">
  <img src=".github/logo.svg" width="200" alt="Go JOSE gopher">
</p>

This library implements the JavaScript Object Signing and Encryption (JOSE) family of specifications for Go: JSON Web
Signature ([RFC 7515]), JSON Web Encryption ([RFC 7516]), JSON Web Key ([RFC 7517]), the JSON Web Algorithms
([RFC 7518]) and JSON Web Token ([RFC 7519]). It is maintained by the [Authelia] team.

It is a fork of [go-jose] which holds itself closely to the specifications and to the guidance which accompanies them,
such as the JSON Web Token Best Current Practices ([RFC 8725]). It aims to accept anything it produces, and to refuse
anything a specification does not permit, both when parsing and when producing a token or key. This makes it stricter
than many other implementations, so it may reject input which they accept.

Forked from [go-jose] at commit [8d4e64d](https://github.com/go-jose/go-jose/commit/8d4e64dd6193f330ff4babb4038c99c56974abff).

## Go Version Support Policy

This library officially supports the latest minor version of Go only, which is currently **Go 1.27**. Earlier versions
are not supported, and features such as ML-DSA are only available with Go 1.27 or later. These rules apply at the time
of a published release.

This library is intended to be used with [Go Toolchains](https://go.dev/doc/toolchain) as indicated by the `toolchain`
directive in the `go.mod`.

This library handles a critical element of security in a dependent project, so where backwards compatibility and
security are at odds we will choose security. We consider this especially reasonable in Go, where upgrading the
toolchain is rarely a breaking change.

## Feature Support

### Serialization

| Feature                                    |  JWS  | JWE  | Specification          |
|:-------------------------------------------|:-----:|:----:|:-----------------------|
| Compact Serialization                      |  ✅   |  ✅  | [RFC 7515], [RFC 7516] |
| JSON Serialization (General and Flattened) |  ✅   |  ✅  | [RFC 7515], [RFC 7516] |
| Multiple Signatures / Recipients           |  ✅   |  ✅  | [RFC 7515], [RFC 7516] |
| Detached Payload                           |  ✅   |  -   | [RFC 7515] Appendix F  |
| Unencoded Payload (`b64`)                  |  ✅   |  -   | [RFC 7797]             |
| Additional Authenticated Data (`aad`)      |   -   |  ✅  | [RFC 7516]             |
| Compression (`zip`: `DEF`)                 |   -   |  ✅  | [RFC 7516], [RFC 7518] |
| Critical Header Parameters (`crit`)        |  ✅   |  ✅  | [RFC 7515], [RFC 7516] |
| Critical Extensions Supported              | `b64` | None | [RFC 7515], [RFC 7516] |

### Signature Algorithms (JWS)

| Algorithm                             | Supported | Specification          | Notes                                                 |
|:--------------------------------------|:---------:|:-----------------------|:------------------------------------------------------|
| `HS256`, `HS384`, `HS512`             |    ✅     | [RFC 7518]             | Key at least as long as the hash output               |
| `RS256`, `RS384`, `RS512`             |    ✅     | [RFC 7518]             | RSA modulus of at least 2048 bits                     |
| `PS256`, `PS384`, `PS512`             |    ✅     | [RFC 7518]             | RSA modulus of at least 2048 bits                     |
| `ES256`, `ES384`, `ES512`             |    ✅     | [RFC 7518]             | P-256, P-384 and P-521 respectively                   |
| `EdDSA`                               |    ✅     | [RFC 8037], [RFC 9864] | Ed25519 only; deprecated, supported for compatibility |
| `Ed25519`                             |    ✅     | [RFC 9864]             | Fully specified; preferred for new integrations       |
| `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` |    ✅     | [RFC 9964]             | Requires Go 1.27                                      |
| `ES256K`                              |    ❌     | [RFC 8812]             |                                                       |
| `Ed448`                               |    ❌     | [RFC 8037], [RFC 9864] |                                                       |
| `none`                                |    ❌     | [RFC 7518]             | Unsecured JWS is not supported by design              |

### Key Management Algorithms (JWE)

| Algorithm                                                        | Supported | Specification | Notes                                         |
|:-----------------------------------------------------------------|:---------:|:--------------|:----------------------------------------------|
| `RSA1_5`                                                         |    ✅     | [RFC 7518]    | RSA modulus of at least 2048 bits             |
| `RSA-OAEP`, `RSA-OAEP-256`                                       |    ✅     | [RFC 7518]    | RSA modulus of at least 2048 bits             |
| `A128KW`, `A192KW`, `A256KW`                                     |    ✅     | [RFC 7518]    |                                               |
| `A128GCMKW`, `A192GCMKW`, `A256GCMKW`                            |    ✅     | [RFC 7518]    |                                               |
| `dir`                                                            |    ✅     | [RFC 7518]    | Single recipient only                         |
| `ECDH-ES`                                                        |    ✅     | [RFC 7518]    | P-256, P-384 and P-521; single recipient only |
| `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`             |    ✅     | [RFC 7518]    | P-256, P-384 and P-521                        |
| `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW` |    ✅     | [RFC 7518]    | `p2c` of 1,000 to 1,000,000                   |
| `RSA-OAEP-384`, `RSA-OAEP-512`                                   |    ❌     |               |                                               |
| `ECDH-ES` with `X25519` or `X448`                                |    ❌     | [RFC 8037]    |                                               |

### Content Encryption Algorithms (JWE)

| Algorithm                                         | Supported | Specification |
|:--------------------------------------------------|:---------:|:--------------|
| `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` |    ✅     | [RFC 7518]    |
| `A128GCM`, `A192GCM`, `A256GCM`                   |    ✅     | [RFC 7518]    |

### Keys (JWK)

| Feature                                              | Supported | Specification | Notes                          |
|:-----------------------------------------------------|:---------:|:--------------|:-------------------------------|
| `RSA` keys                                           |    ✅     | [RFC 7518]    | Two prime keys only            |
| `EC` keys                                            |    ✅     | [RFC 7518]    | P-256, P-384 and P-521         |
| `OKP` keys                                           |    ✅     | [RFC 8037]    | Ed25519 only                   |
| `oct` keys                                           |    ✅     | [RFC 7518]    |                                |
| `AKP` keys                                           |    ✅     | [RFC 9964]    | ML-DSA; requires Go 1.27       |
| JWK Sets                                             |    ✅     | [RFC 7517]    |                                |
| `use`, `key_ops` and `alg` enforcement               |    ✅     | [RFC 7517]    |                                |
| Certificate chains (`x5c`, `x5t`, `x5t#S256`, `x5u`) |    ✅     | [RFC 7517]    | `x5u` is not dereferenced      |
| Thumbprints                                          |    ✅     | [RFC 7638]    | Not computed for `oct` keys    |
| Opaque and hardware backed keys                      |    ✅     |               | See the `cryptosigner` package |

### Tokens (JWT)

| Feature                                                                       | Supported | Specification |
|:------------------------------------------------------------------------------|:---------:|:--------------|
| Signed tokens                                                                 |    ✅     | [RFC 7519]    |
| Encrypted tokens                                                              |    ✅     | [RFC 7519]    |
| Nested (signed then encrypted) tokens                                         |    ✅     | [RFC 7519]    |
| Registered claim validation (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) |    ✅     | [RFC 7519]    |

## Credits

The gopher mascot is inspired by the Go gopher, designed by [Renée French](https://reneefrench.blogspot.com/) and
licensed under the [Creative Commons 4.0 Attribution License](https://creativecommons.org/licenses/by/4.0/).

[Authelia]: https://www.authelia.com
[go-jose]: https://github.com/go-jose/go-jose
[RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
[RFC 7516]: https://www.rfc-editor.org/rfc/rfc7516
[RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
[RFC 7518]: https://www.rfc-editor.org/rfc/rfc7518
[RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC 7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC 7797]: https://www.rfc-editor.org/rfc/rfc7797
[RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
[RFC 8725]: https://www.rfc-editor.org/rfc/rfc8725
[RFC 8812]: https://www.rfc-editor.org/rfc/rfc8812
[RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
[RFC 9964]: https://www.rfc-editor.org/rfc/rfc9964
