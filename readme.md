Decentralized Identity Authentication via JOSE
===
`did-auth-jose` is a library that provides JOSE encryption, decryption, signing, and verifying capabilities through a key and algorithm extensible model, as well as two authentication flows for use with decentralized identities (DIDs).

OIDC Authentication Flow
---

OIDC Authentication is loosely based off of OpenID Connect Self-Issued ID Token Protocol. The `AuthenticationRequest` and `AuthenticationResponse` objects are modeled after OIDC request and response objects. We have proposed an authentication protocol flow in [this OIDC Authentication document](./docs/OIDCAuthentication.md).

Authentication Flow
---

DID Authentication uses two to three [JSON Web Tokens](https://jwt.io/) (JWT) per request. The first is an outer JSON Web Encryption (JWE), and the second is an inner JSON Web Signature (JWS), both utilizing the public private key pair of each DID retrieved from their DID Document. An optional third JWT access token may be included in a JWS header. This format ensures the content is encrypted end to end and independently verifiable. Each JWS contains a nonce header to associate requests with responses.

Authentication is encapsilated in an [Authentication](docs/api.md#Authentication) containing private keys for decryption, cryptographic algorithms, and a Universal Resolver. Due to the extensible model, implementations for algorithms and a universal resolver must be passed in. A [standard set of algorithms](docs/Authentication.md#signature-and-encryption-algorithms) will be used by default. **Currently RSA, AES, and Secp256k1 is supported**.

DID Documents are retrieved by the Universal Resolver. All documents are expected to conform to the [DID spec](https://w3c-ccg.github.io/did-spec/). An simple `http-resolver` is included in the [hub-node-core](https://github.com/decentralized-identity/hub-node-core) package, utilizing a remote Universal Resolver listening over http.

The flow can be invoked by three methods, starting with the sender:
```typescript
async getAuthenticatedRequest (
  content: string,
  privateKey: PrivateKey,
  recipient: string,
  accessToken?: string
): Promise<Buffer>
```
which takes the message content, the private key used for signing, the did this message is intended for, and optionally an access token JWT to include in the JWS header.

Upon receipt of the encrypted request, the receiver uses:
```typescript
async getVerifiedRequest (
  request: Buffer,
  accessTokenCheck: boolean = true
): Promise<VerifiedRequest | Buffer>
```
which decrypts the request using `Authentication`'s private keys, retrieves the sender's DID Document and signing key, and verifys the signature of the JWS. If `accessTokenCheck` is `true`, it will require the JWS contain an access token in the JWS header and verify the token. If no token was included, the returned `Promise` will resolve to a `Buffer` containing a message back to the sender with an appropriate access token. **This behavior may change in the future upon defining a specific endpoint for recieving acces tokens**. If successful, a `VerifiedRequest` option is returned, containing the plaintext request in the `VerifiedRequest.request` property, along with additional metadata.

The reciever may then respond to the message using the same keys with the `getAuthenticatedResponse` method:
```typescript
async getAuthenticatedResponse (
  request: VerifiedRequest,
  response: string
): Promise<Buffer>
```
This method takes the original request for public key metadata, and the plaintext response, and returns a `Buffer` using the same keys if possible.

The sender may decrypt the response using the same `getVerifiedRequest` method with the `accessTokenCheck` set to `false`.

The authentication flow is explained in greater detail in the [Authentication](docs/Authentication.md) document.

Extensible JOSE
---
This package includes JWS and JWE classes (`JwsToken` and `JweToken` respectively) which utilize an extensible cryptographic model, `CryptoFactory`. This factory is constructed from `CryptoSuite` which implement specific public private key pair generation, encryption, decryption, signing, and verifying algorithms. To add support for an algorithm, simply include the `CryptoSuite` that implements that algorithm to the `CryptoFactory` constructor. 

JOSE extensions are explained in greater detail in the [CryptoSuite](docs/CryptoSuite.md) document.