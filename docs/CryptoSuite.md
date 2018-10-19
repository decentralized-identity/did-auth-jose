# Cryptographic Algorithm Extensibility
This section describes how to add additional cryptographic algorithm support in the Server.

## did-auth-jose package
Authentication is handled by the `did-auth-jose` package, such that application may use this package without needing the entire Server-node-core. 
This module contains definitions for `CryptoSuite`, `PublicKey`, and `PrivateKey` which are required for cryptogrpahic support. By implementing a `CryptoSuite`, one may pass it to the auth package directly, or
through the Server via the `Context`'s `cryptoSuites` array. 

### CryptoSuite
CryptoSuite contains three methods returning dictionaries. These dictionaries map the algorithm name or DID Document's PublicKey type (Cryptographic suite name) 
to their `Encrypter`s, `Signer`s, and constructors. By overriding these methods, a `CryptoSuite` can be added to the Authentication's supported libraries.

#### Encrypters
An encrypter is an object containing two methods, `encrypt` and `decrypt`. These methods are given the data to 
encrypt or decrypt, and the corresponding `Publickey` or `PrivateKey`. They are expected to return a Buffer 
of the encrypted or decrypted content.

#### Signers
a signer is an object containing two methods, `sign` and `verify`. `sign` is given the content to sign, and 
a `PrivateKey` used to sign it with. It is expected to return a compact JWS string.
`verify` is given the signed content, the signature, and the `PublicKey`, and is expected to return true if 
valid, else false.

#### constructors
In the map of Cryptographic suite names to constructors, the constructors must match a single signature:
```Typescript
constructor (data: DidPublicKey) => PublicKey
```
where `data` is the entire public key object found on the DID Document as a JSON object. Additional parameters 
specified by the Cryptographic suite will be found in this object, if provided.

### PublicKey
`PublicKey` is a JWK representation of a public key. In addition to required JWK parameters per the used key type, 
`PublicKey` required a `defaultEncryptionAlgorithm` to indicate which encryption algorithm to use. These algorithm names **MUST** match Encrypter algorithm names.

### PrivateKey
`PrivateKey` is a JWK representation of a private key. In addition to required JWK parameters per the used key type, 
`PrivateKey` required a `defaultSignAlgorithm` to indicate which signature algorithm to use. These algorithm names **MUST** match Signer algorithm names.
