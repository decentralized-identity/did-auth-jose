**Jose DID Authentication Library Documentation**
============================================

# Overview
This document describes everything you need know about the DID Authentication Library.

# End-To-End Authenticated Encryption
Authenticated encryption ensures the confidentiality and integrity of the messages being exchanged. The Server requires and enforces end-to-end (two-way) authenticated encryption for all requests and responses using the JWE scheme.

> TODO: Consider moving the description of the authentication encryption scheme to Server specification or generic DID authentication specification.
> TODO: Test hooks will be provided to bypass message encryption and decryption for test and development purposes.

```sequence
Requester -> Requester: Creates the request.
Requester -> Requester: Encrypts the request as a JWE using Server's public-key.
Requester -> Server:       JWE encrypted request
Server -> Server:             Decrypts the JWE using its corresponding private-key.
Server -> Server:             Processes the request then generates the Server Response.
Server -> Server:             Encrypts the response as a JWE using requester's public-key.
Server --> Requester:      JWE encrypted response
Requester -> Requester: Decrypts the JWE using its corresponding private-key.
Requester -> Requester: Handles the response.

```

Specifically, every request sent to the Server must be JWE encrypted using a public-key specified in the Server's DID Document. The ID of the public-key must be specified in the ```kid``` JWE header parameter as a DID fragment (see https://w3c-ccg.gitServer.io/did-spec/#fragments).

## Example JWE header:

```json
{
  "kid": "did:example:123456789abcdefghi#keys-1",
  "alg": "RSA-OAEP-256",
  "enc": "A128GCM",
}
```
> NOTE: The requester needs to be identified and authenticated for Server to send the encrypted response. This will be discussed in the end-to-end authentication section of this document.

# End-To-End Authentication
The Server requires end-to-end (two-way) authentication for all request-response exchanges using the JWS scheme. Because of the additional message confidentiality requirement described earlier, all requests and responses are first JWS signed, then JWE encrypted.

The following sequence diagram shows the complete end-to-end authentication (and encryption) flow:

```sequence
Requester -> Requester:  Creates signed access request + nonce as a JWS.
Requester -> Requester:  Encrypts the JWS as a JWE using Server's public-key.
Requester -> Server:        JWE encrypted access request

Server -> Server:        Decrypts JWE blob.
Server -> Server:        Verifies requester-signed JWS.
Server -> Server:        Creates signed JWT.
Server -> Server:        Wraps signed JWT + requester-issued nonce as a JWS.
Server -> Server:        Encrypts JWS as a JWE using requester's public-key.
Server --> Requester: JWE encrypted Server-signed JWT

Requester -> Requester:  Decrypts JWE blob.
Requester -> Requester:  Verifies requester-issued nonce in JWS.
Requester -> Requester:  Verifies Server-signed JWS.
Note right of Requester: Note: Server is authenticated at this point.
Requester -> Requester:  The requester caches the JWT for future communication.
Note right of Requester: Note: the cached JWT can be reused until expiry.
Requester -> Requester:  Creates Server request and new nonce.
Requester -> Requester:  Signs Server request + Server-issued JWT + nonce as a JWS.
Requester -> Requester:  Encrypts JWS as a JWE using Server's public-key.
Requester -> Server:        JWE encrypted Server request.

Server -> Server:        Decrypts JWE blob.
Server -> Server:        Verifies requester-signed JWS.
Server -> Server:        Verifies Server-issued JWT.
Note right of Server: Note: requester is authenticated at this point.
Server -> Server:        Processes the request.
Server -> Server:        Signs Server response + requester-issued nonce as a JWS.
Server -> Server:        Encrypts JWS as a JWE using requester's public-key.
Server --> Requester: JWE encrypted Server response

Requester -> Requester: Decrypts JWE blob.
Requester -> Requester: Verifies requester-issued nonce.
Requester -> Requester: Verifies Server-signed JWS.
Requester -> Requester: Parses Server response.

```

>Since all messages exchanged are protected by JWE, JWE encryption and decryption steps are intentionally omitted to highlight the authentication steps in the description below.

1. The requester creates a self-signed access request as a JWS. A request to the Server is considered an "access request" if the JWS header does not contain the ```did-access-token``` parameter. A nonce must be added to the ```did-requester-nonce``` JWS header parameter for every request sent to the Server, the Server must then include the same nonce header in the response to protect the requester from response replays. The requester nonce is included in the header rather than the payload to decouple authentication data from the request or response data. The Server will ignore the actual payload in the JWS during this phase of the authentication flow.

1. Requester sends the JWS to the Server.

1. The Server verifies the JWS by resolving the requester's DID then obtaining the public key needed for verification. The requester's DID and the public-key ID can be derived from ```kid``` JWS header parameter. The same public-key must be used for encrypting the response.
> Public key resolution is pending real implementation.

4. The Server generates a time-bound token for the requester to use in future communication. This token technically can be of any opaque format, however in the DID Server Core Library implementation, the token is a signed JWT.

1. The Server signs/wraps the token (in our case a signed JWT) as the payload of a JWS. The Server must also copy the ```did-requester-nonce``` JWS header parameter from the request into the JWS header.

> Note: Currently the DID Server Core library authentication implementation is stateless, thus it is subject to request replays within the time-bound window allowed by the JWT. However the requester nonce can be cached on the Server in the future to prevent all request replays.

6. The Server sends the JWS back to the requester.

1. The requester verifies the value in the ```did-requester-nonce``` JWT header parameter matches its requester-issued nonce.

1. The requester verifies that JWS is signed by the Server by resolving the Server's DID then obtaining the public key needed for verification. The Server's DID and the public-key ID can be derived from ```kid``` header parameter.

1. The Server is authenticated after the step above. The requester caches the Server-issued token (signed JWT) locally and reuse it for all future requests to the Server until the Server rejects it, most commonly due to token expiry, at which point the requester would request a new access token.

1. The requester crafts the actual Server request, and creates a new nonce.

1. The requester signs the Server request as a JWS, including the new nonce in the ```did-requester-nonce``` header parameter and the Server-signed JWT in the ```did-access-token``` header parameter.

1. The requester sends the signed Server request to the Server.

1. The Server verifies the JWS by resolving the requester's DID then obtaining the public key needed for verification. The same public-key must be used for encrypting the response.

1. The Server verifies the signed JWT given in the ```did-access-token``` header parameter.

1. The requester is authenticated after the step above. The Server process the request and generates an in-memory response.

1. The Server signs the Server response as a JWS, including the ```did-requester-nonce``` header parameter from the request in the JWS header.

1. The Server sends the signed Server response back to the requester.

1. The requester verifies that the value in the ```did-requester-nonce``` JWS header parameter matches its requester-issued nonce.

1. The requester verifies that JWT is signed by the Server by resolving Server's DID and obtaining the public key specified by the ```kid``` header in the JWT.

## Example Server JWT Payload
```json
{
  "jti": "3e2c9b3a-da11-47e2-a5d8-12a23a9d41e4",
  "iss": "did:example:Server-did",
  "sub": "did:example:requester-did",
  "iat": 1533168455,
  "exp": 1533172655
}
```

## Example JWS header
```json
{
  "kid": "did:example:123456789abcdefghi#keys-1",
  "alg": "RS256",
  "did-requester-nonce": "p6OLLpeRafCWbOAEYpuGVTKNkcq8l",
  "did-access-token": "..."
}
```


# Signature and Encryption Algorithms
This section lists the signature and encryption algorithms currently supported (implemented and tested).

## JWS Support
| Serialization         | Support |
| --------------------- | ------- |
| Compact Serialization | Yes     |
| JSON Serialization    | No      |

### Server Response and Token Signing
| Algorithm          | Support           | JOSE specified | JWK specified | 
| ------------------ | ----------------- | -------------- | ------------- |
| RS256              | Yes               | Yes            | Yes           |
| ED25519            | To be implemented | To be added    | Yes           |
| SECP256K1          | To be implemented | To be added    | To be added   |

### Request Signature Verification
| Algorithm          | Support           | JOSE specified | JWK specified | 
| ------------------ | ----------------- | -------------- | ------------- |
| RS256              | Yes               | Yes            | Yes           |
| RS512              | Yes               | Yes            | Yes           |
| ED25519            | To be implemented | To be added    | Yes           |
| SECP256K1          | To be implemented | To be added    | To be added   |
> Note: ED25519 is defined in JWK specification, while SECP256K1 is not. Neither algorithms are listed in the JOSE signature and encryption algorithms, (https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms), and are not implemented in the node-jose NPM package used in the current implementation.


## JWE Support
| Serialization         | Support |
| --------------------- | ------- |
| Compact Serialization | Yes     |
| JSON Serialization    | No      |

> Discussion: Current implementation assumes Compact Serialization in the HTTP POST body and payload. We might want to support JSON serialization for POST body instead/in addition.

### Key Encryption
Asymmetric algorithms that can be used by the Server to encrypt the symmetric content encryption key in the Server response JWE:  
| Algorithm                | Support           | JOSE specified | JWK specified |
| ------------------------ | ----------------- | -------------- | ------------- |
| RSA-OAEP                 | Yes               | Yes            | Yes           |
| ED25519                  | To be implemented | To be added    | Yes           |
| SECP256K1                | To be implemented | To be added    | To be added   |

### Key Decryption
Asymmetric algorithms that can be used by the Server to decrypt the symmetric content encryption key in the Server request JWE:  
| Algorithm                | Support           | JOSE specified | JWK specified |
| ------------------------ | ----------------- | -------------- | ------------- |
| RSA-OAEP                 | Yes               | Yes            | Yes           |
| RSA-OAEP-256             | Yes               | Yes            | Yes           |
| ED25519                  | To be implemented | To be added    | Yes           |
| SECP256K1                | To be implemented | To be added    | To be added   |

### Content Encryption
Symmetric algorithms that can be used by the Server to encrypt the content of the Server response JWE:  
| Algorithm                     | Support            | JOSE specified |
| ----------------------------- | ------------------ | -------------- |
| A128GCM                       | Yes                | Yes            |
| XSalsa20-Poly1305             | To be implemented  | To be added    |

### Content Decryption
Symmetric algorithms that can be used by the Server to decrypt the content of the Server request JWE:  
| Algorithm                     | Support            | JOSE specified |
| ----------------------------- | ------------------ | -------------- |
| A128GCM                       | Yes                | Yes            |
| XSalsa20-Poly1305             | To be implemented  | To be added    |

# Future Work
- Stateful authentication scheme to prevent any replay attack.
- Stateful ephemeral key / forward secrecy support.
