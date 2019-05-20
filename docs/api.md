## Classes

<dl>
<dt><a href="#Authentication">Authentication</a></dt>
<dd><p>Class for decrypting and verifying, or signing and encrypting content in an End to End DID Authentication format</p></dd>
<dt><a href="#Constants">Constants</a></dt>
<dd><p>Class containing constants used in Authentication.</p></dd>
<dt><a href="#AesCryptoSuite">AesCryptoSuite</a></dt>
<dd><p>Encrypter plugin for Advanced Encryption Standard symmetric keys</p></dd>
<dt><a href="#EcPrivateKey">EcPrivateKey</a> ⇐ <code><a href="#PrivateKey">PrivateKey</a></code></dt>
<dd><p>Represents an Elliptic Curve private key</p></dd>
<dt><a href="#EcPublicKey">EcPublicKey</a> ⇐ <code>PublicKey</code></dt>
<dd><p>Represents an Elliptic Curve public key</p></dd>
<dt><a href="#Secp256k1CryptoSuite">Secp256k1CryptoSuite</a></dt>
<dd><p>Encrypter plugin for Elliptic Curve P-256K1</p></dd>
<dt><a href="#RsaCryptoSuite">RsaCryptoSuite</a></dt>
<dd><p>Encrypter plugin for RsaSignature2018</p></dd>
<dt><a href="#RsaPrivateKey">RsaPrivateKey</a> ⇐ <code><a href="#PrivateKey">PrivateKey</a></code></dt>
<dd><p>Represents an Rsa private key</p></dd>
<dt><a href="#RsaPublicKey">RsaPublicKey</a> ⇐ <code>PublicKey</code></dt>
<dd><p>Represents an Rsa public key</p></dd>
<dt><a href="#CryptoFactory">CryptoFactory</a></dt>
<dd><p>Utility class to handle all CryptoSuite dependency injection</p></dd>
<dt><a href="#KeyStoreMem">KeyStoreMem</a></dt>
<dd><p>Class defining methods and properties for a light KeyStore</p></dd>
<dt><a href="#Protect">Protect</a></dt>
<dd><p>Class to model protection mechanisms</p></dd>
<dt><a href="#JoseToken">JoseToken</a></dt>
<dd><p>Base class for containing common operations for JWE and JWS tokens.
Not intended for creating instances of this class directly.</p></dd>
<dt><a href="#JweToken">JweToken</a></dt>
<dd><p>Class for performing JWE encryption operations.
This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.</p></dd>
<dt><a href="#JwsToken">JwsToken</a></dt>
<dd><p>Class for containing JWS token operations.
This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.</p></dd>
<dt><a href="#PrivateKey">PrivateKey</a></dt>
<dd><p>Represents a Private Key in JWK format.</p></dd>
<dt><a href="#KeyOperation">KeyOperation</a></dt>
<dd></dd>
<dt><a href="#Base64Url">Base64Url</a></dt>
<dd><p>Class for performing various Base64 URL operations.</p></dd>
</dl>

## Members

<dl>
<dt><a href="#ProtectionFormat">ProtectionFormat</a></dt>
<dd><p>Enum to define different protection formats</p></dd>
<dt><a href="#RecommendedKeyType">RecommendedKeyType</a></dt>
<dd><p>JWA recommended KeyTypes to be implemented</p></dd>
<dt><a href="#RecommendedKeyType">RecommendedKeyType</a></dt>
<dd><p>JWK key operations</p></dd>
<dt><a href="#iss">iss</a></dt>
<dd><p>DID of the issuer of the request. This should match the signature</p></dd>
<dt><a href="#response_type">response_type</a></dt>
<dd><p>MUST be set as 'id_token' in order to match OIDC self-issued protocol</p></dd>
<dt><a href="#client_id">client_id</a></dt>
<dd><p>The redirect url as specified in the OIDC self-issued protocol</p></dd>
<dt><a href="#scope">scope</a></dt>
<dd><p>MUST be set to 'openid'</p></dd>
<dt><a href="#state">state</a></dt>
<dd><p>Opaque value used by issuer for state</p></dd>
<dt><a href="#nonce">nonce</a></dt>
<dd><p>Request Nonce</p></dd>
<dt><a href="#claims">claims</a></dt>
<dd><p>Claims that are requested</p></dd>
</dl>

<a name="Authentication"></a>

## Authentication
<p>Class for decrypting and verifying, or signing and encrypting content in an End to End DID Authentication format</p>

**Kind**: global class  

* [Authentication](#Authentication)
    * [new Authentication(options)](#new_Authentication_new)
    * [.signAuthenticationRequest(request)](#Authentication+signAuthenticationRequest) ⇒
    * [.verifyAuthenticationRequest(request)](#Authentication+verifyAuthenticationRequest)
    * [.formAuthenticationResponse(authRequest, responseDid, claims, expiration, keyReference)](#Authentication+formAuthenticationResponse)
    * [.getKeyReference(iss)](#Authentication+getKeyReference)
    * [.getKey(did)](#Authentication+getKey) ⇒
    * [.verifySignature(jwsToken)](#Authentication+verifySignature) ⇒
    * [.verifyAuthenticationResponse(authResponse)](#Authentication+verifyAuthenticationResponse) ⇒
    * [.getVerifiedRequest(request, accessTokenCheck)](#Authentication+getVerifiedRequest) ⇒
    * [.getAuthenticatedResponse(request, response)](#Authentication+getAuthenticatedResponse) ⇒
    * [.getAuthenticatedRequest(content, privateKey, recipient, accessToken)](#Authentication+getAuthenticatedRequest)
    * [.getPrivateKeyForJwe(jweToken)](#Authentication+getPrivateKeyForJwe) ⇒
    * [.getPublicKey(request)](#Authentication+getPublicKey) ⇒
    * [.getRequesterNonce(jwsToken)](#Authentication+getRequesterNonce) ⇒
    * [.signThenEncryptInternal(nonce, requesterkey, content)](#Authentication+signThenEncryptInternal) ⇒
    * [.issueNewAccessToken(subjectDid, nonce, issuerKeyReference, requesterKey)](#Authentication+issueNewAccessToken) ⇒
    * [.createAccessToken(subjectDid, privateKeyReference, validDurationInMinutes)](#Authentication+createAccessToken) ⇒
    * [.verifyJwt(publicKey, signedJwtString, expectedRequesterDid)](#Authentication+verifyJwt) ⇒

<a name="new_Authentication_new"></a>

### new Authentication(options)
<p>Authentication constructor</p>


| Param | Description |
| --- | --- |
| options | <p>Arguments to a constructor in a named object</p> |

<a name="Authentication+signAuthenticationRequest"></a>

### authentication.signAuthenticationRequest(request) ⇒
<p>Signs the AuthenticationRequest with the private key of the Requester and returns the signed JWT.</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>the signed compact JWT.</p>  

| Param | Description |
| --- | --- |
| request | <p>well-formed AuthenticationRequest object</p> |

<a name="Authentication+verifyAuthenticationRequest"></a>

### authentication.verifyAuthenticationRequest(request)
<p>Verifies signature on request and returns AuthenticationRequest.</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  

| Param | Description |
| --- | --- |
| request | <p>Authentiation Request as a buffer or string.</p> |

<a name="Authentication+formAuthenticationResponse"></a>

### authentication.formAuthenticationResponse(authRequest, responseDid, claims, expiration, keyReference)
<p>Given a challenge, forms a signed response using a given DID that expires at expiration, or a default expiration.</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  

| Param | Description |
| --- | --- |
| authRequest | <p>Challenge to respond to</p> |
| responseDid | <p>The DID to respond with</p> |
| claims | <p>Claims that the requester asked for</p> |
| expiration | <p>optional expiration datetime of the response</p> |
| keyReference | <p>pointing to the signing key</p> |

<a name="Authentication+getKeyReference"></a>

### authentication.getKeyReference(iss)
<p>Return a reference to the private key that was passed by caller.
If the key was passed in by value, it will be stored in the store and a reference is returned</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  

| Param | Description |
| --- | --- |
| iss | <p>Issuer identifier</p> |

<a name="Authentication+getKey"></a>

### authentication.getKey(did) ⇒
<p>Private method that gets the private key of the DID from the key mapping.</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>private key of the DID.</p>  

| Param | Description |
| --- | --- |
| did | <p>the DID whose private key is used to sign JWT.</p> |

<a name="Authentication+verifySignature"></a>

### authentication.verifySignature(jwsToken) ⇒
<p>helper method that verifies the signature on jws and returns the payload if signature is verified.</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>the payload if jws signature is verified.</p>  

| Param | Description |
| --- | --- |
| jwsToken | <p>signed jws token whose signature will be verified.</p> |

<a name="Authentication+verifyAuthenticationResponse"></a>

### authentication.verifyAuthenticationResponse(authResponse) ⇒
<p>Verifies the signature on a AuthenticationResponse and returns a AuthenticationResponse object</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>the authenticationResponse as a AuthenticationResponse Object</p>  

| Param | Description |
| --- | --- |
| authResponse | <p>AuthenticationResponse to verify as a string or buffer</p> |

<a name="Authentication+getVerifiedRequest"></a>

### authentication.getVerifiedRequest(request, accessTokenCheck) ⇒
<p>Given a JOSE Authenticated Request, will decrypt the request, resolve the requester's did, and validate the signature.</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>The content of the request as a VerifiedRequest, or a response containing an access token</p>  

| Param | Default | Description |
| --- | --- | --- |
| request |  | <p>The JOSE Authenticated Request to decrypt and validate</p> |
| accessTokenCheck | <code>true</code> | <p>Check the validity of the access token</p> |

<a name="Authentication+getAuthenticatedResponse"></a>

### authentication.getAuthenticatedResponse(request, response) ⇒
<p>Given the verified request, uses the same keys and metadata to sign and encrypt the response</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>An encrypted and signed form of the response</p>  

| Param | Description |
| --- | --- |
| request | <p>The original JOSE Verified Request request</p> |
| response | <p>The plaintext response to be signed and encrypted</p> |

<a name="Authentication+getAuthenticatedRequest"></a>

### authentication.getAuthenticatedRequest(content, privateKey, recipient, accessToken)
<p>Creates an encrypted and authenticated JOSE request</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  

| Param | Description |
| --- | --- |
| content | <p>the content of the request</p> |
| privateKey | <p>the private key to sign with</p> |
| recipient | <p>the DID the request is indended for</p> |
| accessToken | <p>an access token to be used with the other party</p> |

<a name="Authentication+getPrivateKeyForJwe"></a>

### authentication.getPrivateKeyForJwe(jweToken) ⇒
<p>Given a JWE, retrieves the PrivateKey to be used for decryption</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>The PrivateKey corresponding to the JWE's encryption</p>  

| Param | Description |
| --- | --- |
| jweToken | <p>The JWE to inspect</p> |

<a name="Authentication+getPublicKey"></a>

### authentication.getPublicKey(request) ⇒
<p>Retrieves the PublicKey used to sign a JWS</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>The PublicKey the JWS used for signing</p>  

| Param | Description |
| --- | --- |
| request | <p>the JWE string</p> |

<a name="Authentication+getRequesterNonce"></a>

### authentication.getRequesterNonce(jwsToken) ⇒
<p>Retrieves the nonce from the JWS</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>The nonce</p>  

| Param | Description |
| --- | --- |
| jwsToken | <p>The JWS containing the nonce</p> |

<a name="Authentication+signThenEncryptInternal"></a>

### authentication.signThenEncryptInternal(nonce, requesterkey, content) ⇒
<p>Forms a JWS using the local private key and content, then wraps in JWE using the requesterKey and nonce.</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>An encrypted and signed form of the content</p>  

| Param | Description |
| --- | --- |
| nonce | <p>Nonce to be included in the response</p> |
| requesterkey | <p>PublicKey in which to encrypt the response</p> |
| content | <p>The content to be signed and encrypted</p> |

<a name="Authentication+issueNewAccessToken"></a>

### authentication.issueNewAccessToken(subjectDid, nonce, issuerKeyReference, requesterKey) ⇒
<p>Creates a new access token and wrap it in a JWE/JWS pair.</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>A new access token</p>  

| Param | Description |
| --- | --- |
| subjectDid | <p>the DID this access token is issue to</p> |
| nonce | <p>the nonce used in the original request</p> |
| issuerKeyReference | <p>A reference to the key used in the original request</p> |
| requesterKey | <p>the requesters key to encrypt the response with</p> |

<a name="Authentication+createAccessToken"></a>

### authentication.createAccessToken(subjectDid, privateKeyReference, validDurationInMinutes) ⇒
<p>Creates an access token for the subjectDid using the privateKey for the validDurationInMinutes</p>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>Signed JWT in compact serialized format.</p>  

| Param | Description |
| --- | --- |
| subjectDid | <p>The did this access token is issued to</p> |
| privateKeyReference | <p>The private key used to generate this access token</p> |
| validDurationInMinutes | <p>The duration this token is valid for, in minutes</p> |

<a name="Authentication+verifyJwt"></a>

### authentication.verifyJwt(publicKey, signedJwtString, expectedRequesterDid) ⇒
<p>Verifies:</p>
<ol>
<li>JWT signature.</li>
<li>Token's subject matches the given requeter DID.</li>
<li>Token is not expired.</li>
</ol>

**Kind**: instance method of [<code>Authentication</code>](#Authentication)  
**Returns**: <p>true if token passes all validation, false otherwise.</p>  

| Param | Description |
| --- | --- |
| publicKey | <p>Public key used to verify the given JWT in JWK JSON object format.</p> |
| signedJwtString | <p>The signed-JWT string.</p> |
| expectedRequesterDid | <p>Expected requester ID in the 'sub' field of the JWT payload.</p> |

<a name="Constants"></a>

## Constants
<p>Class containing constants used in Authentication.</p>

**Kind**: global class  
<a name="AesCryptoSuite"></a>

## AesCryptoSuite
<p>Encrypter plugin for Advanced Encryption Standard symmetric keys</p>

**Kind**: global class  

* [AesCryptoSuite](#AesCryptoSuite)
    * [.getEncrypters()](#AesCryptoSuite+getEncrypters)
    * [.getSigners()](#AesCryptoSuite+getSigners)
    * [.encryptAesCbcHmacSha2(keySize, hashSize)](#AesCryptoSuite+encryptAesCbcHmacSha2) ⇒
    * [.decryptAesCbcHmacSha2(keySize, hashSize)](#AesCryptoSuite+decryptAesCbcHmacSha2) ⇒
    * [.encryptAesGcm(keySize)](#AesCryptoSuite+encryptAesGcm) ⇒
    * [.decryptAesGcm(keySize)](#AesCryptoSuite+decryptAesGcm) ⇒
    * [.generateHmacTag(hashSize, keySize, mackey, additionalAuthenticatedData, initializationVector, ciphertext)](#AesCryptoSuite+generateHmacTag) ⇒
    * [.generateHmac(hashSize, mackey, additionalAuthenticatedData, initializationVector, ciphertext)](#AesCryptoSuite+generateHmac) ⇒
    * [.getAdditionalAuthenticatedDataLength(additionalAuthenticatedData)](#AesCryptoSuite+getAdditionalAuthenticatedDataLength) ⇒
    * [.generateSymmetricKey(bits)](#AesCryptoSuite+generateSymmetricKey)
    * [.generateInitializationVector(bits)](#AesCryptoSuite+generateInitializationVector)

<a name="AesCryptoSuite+getEncrypters"></a>

### aesCryptoSuite.getEncrypters()
<p>Encryption algorithms</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
<a name="AesCryptoSuite+getSigners"></a>

### aesCryptoSuite.getSigners()
<p>Signing algorithms</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
<a name="AesCryptoSuite+encryptAesCbcHmacSha2"></a>

### aesCryptoSuite.encryptAesCbcHmacSha2(keySize, hashSize) ⇒
<p>Given the encryption parameters, returns the AES CBC HMAC SHA2 encryption function</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
**Returns**: <p>a SymmetricEncrypter encrypt function</p>  

| Param | Description |
| --- | --- |
| keySize | <p>Size of the keys</p> |
| hashSize | <p>Size of the SHA2 hash</p> |

<a name="AesCryptoSuite+decryptAesCbcHmacSha2"></a>

### aesCryptoSuite.decryptAesCbcHmacSha2(keySize, hashSize) ⇒
<p>Given the decryption parameters, returns an AES CBC HMAC SHA2 decryption function</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
**Returns**: <p>a SymmetricEncrypter decrypt function</p>  

| Param | Description |
| --- | --- |
| keySize | <p>Size of the keys</p> |
| hashSize | <p>Size of the SHA2 hash</p> |

<a name="AesCryptoSuite+encryptAesGcm"></a>

### aesCryptoSuite.encryptAesGcm(keySize) ⇒
<p>Given the encryption parameters, returns the AES GCM encryption function</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
**Returns**: <p>a SymmetricEncrypter encrypt function</p>  

| Param | Description |
| --- | --- |
| keySize | <p>Size of the keys</p> |

<a name="AesCryptoSuite+decryptAesGcm"></a>

### aesCryptoSuite.decryptAesGcm(keySize) ⇒
<p>Given the decryption parameters, returns an AES GCM decryption function</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
**Returns**: <p>a SymmetricEncrypter decrypt function</p>  

| Param | Description |
| --- | --- |
| keySize | <p>Size of the keys</p> |

<a name="AesCryptoSuite+generateHmacTag"></a>

### aesCryptoSuite.generateHmacTag(hashSize, keySize, mackey, additionalAuthenticatedData, initializationVector, ciphertext) ⇒
<p>Generates the HMAC Tag</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
**Returns**: <p>HMAC Tag</p>  

| Param | Description |
| --- | --- |
| hashSize | <p>HMAC hash size</p> |
| keySize | <p>HMAC tag size</p> |
| mackey | <p>MAC key</p> |
| additionalAuthenticatedData | <p>Additional authenticated data</p> |
| initializationVector | <p>initialization vector</p> |
| ciphertext | <p>encrypted data</p> |

<a name="AesCryptoSuite+generateHmac"></a>

### aesCryptoSuite.generateHmac(hashSize, mackey, additionalAuthenticatedData, initializationVector, ciphertext) ⇒
<p>Generates the full HMac</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
**Returns**: <p>HMAC in full</p>  

| Param | Description |
| --- | --- |
| hashSize | <p>HMAC hash size</p> |
| mackey | <p>MAC key</p> |
| additionalAuthenticatedData | <p>Additional authenticated data</p> |
| initializationVector | <p>initialization vector</p> |
| ciphertext | <p>encrypted data</p> |

<a name="AesCryptoSuite+getAdditionalAuthenticatedDataLength"></a>

### aesCryptoSuite.getAdditionalAuthenticatedDataLength(additionalAuthenticatedData) ⇒
<p>Gets the Additional Authenticated Data length in Big Endian notation</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  
**Returns**: <p>Additional Authenticated Data returned as a base64 big endian unsigned integer</p>  

| Param | Description |
| --- | --- |
| additionalAuthenticatedData | <p>Additional authenticated data</p> |

<a name="AesCryptoSuite+generateSymmetricKey"></a>

### aesCryptoSuite.generateSymmetricKey(bits)
<p>Generates a symmetric key</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  

| Param | Description |
| --- | --- |
| bits | <p>Size in bits of the key</p> |

<a name="AesCryptoSuite+generateInitializationVector"></a>

### aesCryptoSuite.generateInitializationVector(bits)
<p>Generates an initialization vector</p>

**Kind**: instance method of [<code>AesCryptoSuite</code>](#AesCryptoSuite)  

| Param | Description |
| --- | --- |
| bits | <p>Size in bits of the initialization vector</p> |

<a name="EcPrivateKey"></a>

## EcPrivateKey ⇐ [<code>PrivateKey</code>](#PrivateKey)
<p>Represents an Elliptic Curve private key</p>

**Kind**: global class  
**Extends**: [<code>PrivateKey</code>](#PrivateKey)  

* [EcPrivateKey](#EcPrivateKey) ⇐ [<code>PrivateKey</code>](#PrivateKey)
    * [new EcPrivateKey(key)](#new_EcPrivateKey_new)
    * [.wrapJwk(kid, jwk)](#EcPrivateKey.wrapJwk)
    * [.generatePrivateKey(kid)](#EcPrivateKey.generatePrivateKey)

<a name="new_EcPrivateKey_new"></a>

### new EcPrivateKey(key)
<p>Constructs a private key given a DID Document public key descriptor containing additional private key
information.</p>
<p>TODO: This feels odd, should define a separate type.</p>


| Param | Description |
| --- | --- |
| key | <p>public key object with additional private key information</p> |

<a name="EcPrivateKey.wrapJwk"></a>

### EcPrivateKey.wrapJwk(kid, jwk)
<p>Wraps a EC private key in jwk format into a Did Document public key object with additonal information</p>

**Kind**: static method of [<code>EcPrivateKey</code>](#EcPrivateKey)  

| Param | Description |
| --- | --- |
| kid | <p>Key ID</p> |
| jwk | <p>JWK of the private key</p> |

<a name="EcPrivateKey.generatePrivateKey"></a>

### EcPrivateKey.generatePrivateKey(kid)
<p>Generates a new private key</p>

**Kind**: static method of [<code>EcPrivateKey</code>](#EcPrivateKey)  

| Param | Description |
| --- | --- |
| kid | <p>Key ID</p> |

<a name="EcPublicKey"></a>

## EcPublicKey ⇐ <code>PublicKey</code>
<p>Represents an Elliptic Curve public key</p>

**Kind**: global class  
**Extends**: <code>PublicKey</code>  
<a name="new_EcPublicKey_new"></a>

### new EcPublicKey(keyData)
<p>An Elliptic Curve JWK</p>


| Param | Description |
| --- | --- |
| keyData | <p>The IDidDocumentPublicKey containing the elliptic curve public key parameters.</p> |

<a name="Secp256k1CryptoSuite"></a>

## Secp256k1CryptoSuite
<p>Encrypter plugin for Elliptic Curve P-256K1</p>

**Kind**: global class  

* [Secp256k1CryptoSuite](#Secp256k1CryptoSuite)
    * _instance_
        * [.getEncrypters()](#Secp256k1CryptoSuite+getEncrypters)
        * [.getSigners()](#Secp256k1CryptoSuite+getSigners)
        * [.getKeyConstructors()](#Secp256k1CryptoSuite+getKeyConstructors)
    * _static_
        * [.verify()](#Secp256k1CryptoSuite.verify) ⇒
        * [.sign(jwsHeaderParameters)](#Secp256k1CryptoSuite.sign) ⇒

<a name="Secp256k1CryptoSuite+getEncrypters"></a>

### secp256k1CryptoSuite.getEncrypters()
<p>Encryption with Secp256k1 keys not supported</p>

**Kind**: instance method of [<code>Secp256k1CryptoSuite</code>](#Secp256k1CryptoSuite)  
<a name="Secp256k1CryptoSuite+getSigners"></a>

### secp256k1CryptoSuite.getSigners()
<p>Signing algorithms</p>

**Kind**: instance method of [<code>Secp256k1CryptoSuite</code>](#Secp256k1CryptoSuite)  
<a name="Secp256k1CryptoSuite+getKeyConstructors"></a>

### secp256k1CryptoSuite.getKeyConstructors()
<p>Defines constructors for the identifiers proposed in Linked Data Cryptographic Suite Registry
https://w3c-ccg.github.io/ld-cryptosuite-registry/#eddsasasignaturesecp256k1 plus the additional
ones spotted in the wild.</p>

**Kind**: instance method of [<code>Secp256k1CryptoSuite</code>](#Secp256k1CryptoSuite)  
<a name="Secp256k1CryptoSuite.verify"></a>

### Secp256k1CryptoSuite.verify() ⇒
<p>Verifies the given signed content using SHA256 algorithm.</p>

**Kind**: static method of [<code>Secp256k1CryptoSuite</code>](#Secp256k1CryptoSuite)  
**Returns**: <p>true if passed signature verification, false otherwise.</p>  
<a name="Secp256k1CryptoSuite.sign"></a>

### Secp256k1CryptoSuite.sign(jwsHeaderParameters) ⇒
<p>Sign the given content using the given private key in JWK format using algorithm SHA256.</p>

**Kind**: static method of [<code>Secp256k1CryptoSuite</code>](#Secp256k1CryptoSuite)  
**Returns**: <p>Signed payload in compact JWS format.</p>  

| Param | Description |
| --- | --- |
| jwsHeaderParameters | <p>Header parameters in addition to 'alg' and 'kid' to be included in the JWS.</p> |

<a name="RsaCryptoSuite"></a>

## RsaCryptoSuite
<p>Encrypter plugin for RsaSignature2018</p>

**Kind**: global class  

* [RsaCryptoSuite](#RsaCryptoSuite)
    * _instance_
        * [.getEncrypters()](#RsaCryptoSuite+getEncrypters)
        * [.getSigners()](#RsaCryptoSuite+getSigners)
    * _static_
        * [.verifySignatureRs256()](#RsaCryptoSuite.verifySignatureRs256) ⇒
        * [.signRs256(jwsHeaderParameters)](#RsaCryptoSuite.signRs256) ⇒
        * [.verifySignatureRs512()](#RsaCryptoSuite.verifySignatureRs512) ⇒
        * [.signRs512(jwsHeaderParameters)](#RsaCryptoSuite.signRs512) ⇒
        * [.encryptRsaOaep()](#RsaCryptoSuite.encryptRsaOaep)
        * [.decryptRsaOaep()](#RsaCryptoSuite.decryptRsaOaep)

<a name="RsaCryptoSuite+getEncrypters"></a>

### rsaCryptoSuite.getEncrypters()
<p>Encryption algorithms</p>

**Kind**: instance method of [<code>RsaCryptoSuite</code>](#RsaCryptoSuite)  
<a name="RsaCryptoSuite+getSigners"></a>

### rsaCryptoSuite.getSigners()
<p>Signing algorithms</p>

**Kind**: instance method of [<code>RsaCryptoSuite</code>](#RsaCryptoSuite)  
<a name="RsaCryptoSuite.verifySignatureRs256"></a>

### RsaCryptoSuite.verifySignatureRs256() ⇒
<p>Verifies the given signed content using RS256 algorithm.</p>

**Kind**: static method of [<code>RsaCryptoSuite</code>](#RsaCryptoSuite)  
**Returns**: <p>true if passed signature verification, false otherwise.</p>  
<a name="RsaCryptoSuite.signRs256"></a>

### RsaCryptoSuite.signRs256(jwsHeaderParameters) ⇒
<p>Sign the given content using the given private key in JWK format using algorithm RS256.
TODO: rewrite to get rid of node-jose dependency.</p>

**Kind**: static method of [<code>RsaCryptoSuite</code>](#RsaCryptoSuite)  
**Returns**: <p>Signed payload in compact JWS format.</p>  

| Param | Description |
| --- | --- |
| jwsHeaderParameters | <p>Header parameters in addition to 'alg' and 'kid' to be included in the JWS.</p> |

<a name="RsaCryptoSuite.verifySignatureRs512"></a>

### RsaCryptoSuite.verifySignatureRs512() ⇒
<p>Verifies the given signed content using RS512 algorithm.</p>

**Kind**: static method of [<code>RsaCryptoSuite</code>](#RsaCryptoSuite)  
**Returns**: <p>true if passed signature verification, false otherwise.</p>  
<a name="RsaCryptoSuite.signRs512"></a>

### RsaCryptoSuite.signRs512(jwsHeaderParameters) ⇒
<p>Sign the given content using the given private key in JWK format using algorithm RS512.
TODO: rewrite to get rid of node-jose dependency.</p>

**Kind**: static method of [<code>RsaCryptoSuite</code>](#RsaCryptoSuite)  
**Returns**: <p>Signed payload in compact JWS format.</p>  

| Param | Description |
| --- | --- |
| jwsHeaderParameters | <p>Header parameters in addition to 'alg' and 'kid' to be included in the JWS.</p> |

<a name="RsaCryptoSuite.encryptRsaOaep"></a>

### RsaCryptoSuite.encryptRsaOaep()
<p>Rsa-OAEP encrypts the given data using the given public key in JWK format.</p>

**Kind**: static method of [<code>RsaCryptoSuite</code>](#RsaCryptoSuite)  
<a name="RsaCryptoSuite.decryptRsaOaep"></a>

### RsaCryptoSuite.decryptRsaOaep()
<p>Rsa-OAEP decrypts the given data using the given private key in JWK format.
TODO: correctly implement this after getting rid of node-jose dependency.</p>

**Kind**: static method of [<code>RsaCryptoSuite</code>](#RsaCryptoSuite)  
<a name="RsaPrivateKey"></a>

## RsaPrivateKey ⇐ [<code>PrivateKey</code>](#PrivateKey)
<p>Represents an Rsa private key</p>

**Kind**: global class  
**Extends**: [<code>PrivateKey</code>](#PrivateKey)  

* [RsaPrivateKey](#RsaPrivateKey) ⇐ [<code>PrivateKey</code>](#PrivateKey)
    * [new RsaPrivateKey(key)](#new_RsaPrivateKey_new)
    * [.wrapJwk(kid, jwk)](#RsaPrivateKey.wrapJwk)
    * [.generatePrivateKey(kid)](#RsaPrivateKey.generatePrivateKey)

<a name="new_RsaPrivateKey_new"></a>

### new RsaPrivateKey(key)
<p>Constructs a private key given a Did Document public key object containing additional private key
information</p>


| Param | Description |
| --- | --- |
| key | <p>public key object with additional private key information</p> |

<a name="RsaPrivateKey.wrapJwk"></a>

### RsaPrivateKey.wrapJwk(kid, jwk)
<p>Wraps a rsa private key in jwk format into a Did Document public key object with additonal information</p>

**Kind**: static method of [<code>RsaPrivateKey</code>](#RsaPrivateKey)  

| Param | Description |
| --- | --- |
| kid | <p>Key ID</p> |
| jwk | <p>JWK of the private key</p> |

<a name="RsaPrivateKey.generatePrivateKey"></a>

### RsaPrivateKey.generatePrivateKey(kid)
<p>Generates a new private key</p>

**Kind**: static method of [<code>RsaPrivateKey</code>](#RsaPrivateKey)  

| Param | Description |
| --- | --- |
| kid | <p>Key ID</p> |

<a name="RsaPublicKey"></a>

## RsaPublicKey ⇐ <code>PublicKey</code>
<p>Represents an Rsa public key</p>

**Kind**: global class  
**Extends**: <code>PublicKey</code>  
<a name="new_RsaPublicKey_new"></a>

### new RsaPublicKey(n, e)
<p>A Rsa JWK</p>


| Param | Description |
| --- | --- |
| n | <p>The Rsa modulus in Base64urlUInt encoding as specified by RFC7518 6.3.1.1</p> |
| e | <p>The Rsa public exponent in Base64urlUInt encoding as specified by RFC7518 6.3.1.2</p> |

<a name="CryptoFactory"></a>

## CryptoFactory
<p>Utility class to handle all CryptoSuite dependency injection</p>

**Kind**: global class  

* [CryptoFactory](#CryptoFactory)
    * [new CryptoFactory(suites)](#new_CryptoFactory_new)
    * [.constructJwe(content)](#CryptoFactory+constructJwe)
    * [.constructJws(content)](#CryptoFactory+constructJws)
    * [.constructPublicKey(key)](#CryptoFactory+constructPublicKey) ⇒
    * [.getEncrypter(name)](#CryptoFactory+getEncrypter) ⇒
    * [.getSigner(name)](#CryptoFactory+getSigner) ⇒
    * [.getSymmetricEncrypter(name)](#CryptoFactory+getSymmetricEncrypter) ⇒
    * [.getDefaultSymmetricEncryptionAlgorithm()](#CryptoFactory+getDefaultSymmetricEncryptionAlgorithm)

<a name="new_CryptoFactory_new"></a>

### new CryptoFactory(suites)
<p>Constructs a new CryptoRegistry</p>


| Param | Description |
| --- | --- |
| suites | <p>The suites to use for dependency injeciton</p> |

<a name="CryptoFactory+constructJwe"></a>

### cryptoFactory.constructJwe(content)
<p>constructs the jwe to be encrypted or decrypted</p>

**Kind**: instance method of [<code>CryptoFactory</code>](#CryptoFactory)  

| Param | Description |
| --- | --- |
| content | <p>content for the JWE</p> |

<a name="CryptoFactory+constructJws"></a>

### cryptoFactory.constructJws(content)
<p>constructs the jws to be signed or verified</p>

**Kind**: instance method of [<code>CryptoFactory</code>](#CryptoFactory)  

| Param | Description |
| --- | --- |
| content | <p>content for the JWS</p> |

<a name="CryptoFactory+constructPublicKey"></a>

### cryptoFactory.constructPublicKey(key) ⇒
<p>Given a public key definition from a DID Document, constructs a JWK public key. Throws an error
if the key definition cannot be converted.</p>

**Kind**: instance method of [<code>CryptoFactory</code>](#CryptoFactory)  
**Returns**: <p>The same key as a [PublicKey](PublicKey)</p>  

| Param | Description |
| --- | --- |
| key | <p>publicKey object from a [DidDocument](DidDocument)</p> |

<a name="CryptoFactory+getEncrypter"></a>

### cryptoFactory.getEncrypter(name) ⇒
<p>Gets the Encrypter object given the encryption algorithm's name</p>

**Kind**: instance method of [<code>CryptoFactory</code>](#CryptoFactory)  
**Returns**: <p>The corresponding Encrypter, if any</p>  

| Param | Description |
| --- | --- |
| name | <p>The name of the algorithm</p> |

<a name="CryptoFactory+getSigner"></a>

### cryptoFactory.getSigner(name) ⇒
<p>Gets the Signer object given the signing algorithm's name</p>

**Kind**: instance method of [<code>CryptoFactory</code>](#CryptoFactory)  
**Returns**: <p>The corresponding Signer, if any</p>  

| Param | Description |
| --- | --- |
| name | <p>The name of the algorithm</p> |

<a name="CryptoFactory+getSymmetricEncrypter"></a>

### cryptoFactory.getSymmetricEncrypter(name) ⇒
<p>Gets the SymmetricEncrypter object given the symmetric encryption algorithm's name</p>

**Kind**: instance method of [<code>CryptoFactory</code>](#CryptoFactory)  
**Returns**: <p>The corresponding SymmetricEncrypter, if any</p>  

| Param | Description |
| --- | --- |
| name | <p>The name of the algorithm</p> |

<a name="CryptoFactory+getDefaultSymmetricEncryptionAlgorithm"></a>

### cryptoFactory.getDefaultSymmetricEncryptionAlgorithm()
<p>Gets the default symmetric encryption algorithm to use</p>

**Kind**: instance method of [<code>CryptoFactory</code>](#CryptoFactory)  
<a name="KeyStoreMem"></a>

## KeyStoreMem
<p>Class defining methods and properties for a light KeyStore</p>

**Kind**: global class  

* [KeyStoreMem](#KeyStoreMem)
    * [.get(keyReference, publicKeyOnly)](#KeyStoreMem+get)
    * [.list()](#KeyStoreMem+list)
    * [.save(keyIdentifier, key)](#KeyStoreMem+save)
    * [.sign(keyReference, payload, format, cryptoFactory, tokenHeaderParameters)](#KeyStoreMem+sign) ⇒
    * [.decrypt(keyReference, cipher, format, cryptoFactory)](#KeyStoreMem+decrypt) ⇒

<a name="KeyStoreMem+get"></a>

### keyStoreMem.get(keyReference, publicKeyOnly)
<p>Returns the key associated with the specified
key identifier.</p>

**Kind**: instance method of [<code>KeyStoreMem</code>](#KeyStoreMem)  

| Param | Description |
| --- | --- |
| keyReference | <p>for which to return the key.</p> |
| publicKeyOnly | <p>True if only the public key is needed.</p> |

<a name="KeyStoreMem+list"></a>

### keyStoreMem.list()
<p>Lists all keys with their corresponding key ids</p>

**Kind**: instance method of [<code>KeyStoreMem</code>](#KeyStoreMem)  
<a name="KeyStoreMem+save"></a>

### keyStoreMem.save(keyIdentifier, key)
<p>Saves the specified key to the key store using
the key identifier.</p>

**Kind**: instance method of [<code>KeyStoreMem</code>](#KeyStoreMem)  

| Param | Description |
| --- | --- |
| keyIdentifier | <p>for the key being saved.</p> |
| key | <p>being saved to the key store.</p> |

<a name="KeyStoreMem+sign"></a>

### keyStoreMem.sign(keyReference, payload, format, cryptoFactory, tokenHeaderParameters) ⇒
<p>Sign the data with the key referenced by keyIdentifier.</p>

**Kind**: instance method of [<code>KeyStoreMem</code>](#KeyStoreMem)  
**Returns**: <p>The protected message</p>  

| Param | Description |
| --- | --- |
| keyReference | <p>for the key used for signature.</p> |
| payload | <p>Data to sign</p> |
| format | <p>used to protect the content</p> |
| cryptoFactory | <p>used to specify the algorithms to use</p> |
| tokenHeaderParameters | <p>Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.</p> |

<a name="KeyStoreMem+decrypt"></a>

### keyStoreMem.decrypt(keyReference, cipher, format, cryptoFactory) ⇒
<p>Decrypt the data with the key referenced by keyReference.</p>

**Kind**: instance method of [<code>KeyStoreMem</code>](#KeyStoreMem)  
**Returns**: <p>The plain text message</p>  

| Param | Description |
| --- | --- |
| keyReference | <p>Reference to the key used for signature.</p> |
| cipher | <p>Data to decrypt</p> |
| format | <p>Protection format used to decrypt the data</p> |
| cryptoFactory | <p>used to specify the algorithms to use</p> |

<a name="Protect"></a>

## Protect
<p>Class to model protection mechanisms</p>

**Kind**: global class  

* [Protect](#Protect)
    * [.sign(keyStorageReference, payload, format, keyStore, cryptoFactory, tokenHeaderParameters)](#Protect.sign)
    * [.decrypt(keyStorageReference, cipher, format, keyStore, cryptoFactory)](#Protect.decrypt) ⇒

<a name="Protect.sign"></a>

### Protect.sign(keyStorageReference, payload, format, keyStore, cryptoFactory, tokenHeaderParameters)
<p>Sign the payload</p>

**Kind**: static method of [<code>Protect</code>](#Protect)  

| Param | Description |
| --- | --- |
| keyStorageReference | <p>used to reference the signing key</p> |
| payload | <p>to sign</p> |
| format | <p>Signature format</p> |
| keyStore | <p>where to retrieve the signing key</p> |
| cryptoFactory | <p>used to specify the algorithms to use</p> |
| tokenHeaderParameters | <p>Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.</p> |

<a name="Protect.decrypt"></a>

### Protect.decrypt(keyStorageReference, cipher, format, keyStore, cryptoFactory) ⇒
<p>Decrypt the data with the key referenced by keyReference.</p>

**Kind**: static method of [<code>Protect</code>](#Protect)  
**Returns**: <p>The plain text message</p>  

| Param | Description |
| --- | --- |
| keyStorageReference | <p>Reference to the key used for signature.</p> |
| cipher | <p>Data to decrypt</p> |
| format | <p>Protection format used to decrypt the data</p> |
| keyStore | <p>where to retrieve the signing key</p> |
| cryptoFactory | <p>used to specify the algorithms to use</p> |

<a name="JoseToken"></a>

## JoseToken
<p>Base class for containing common operations for JWE and JWS tokens.
Not intended for creating instances of this class directly.</p>

**Kind**: global class  

* [JoseToken](#JoseToken)
    * [new JoseToken()](#new_JoseToken_new)
    * [.getHeader()](#JoseToken+getHeader)
    * [.getProtectedHeader()](#JoseToken+getProtectedHeader)
    * [.isContentWellFormedToken()](#JoseToken+isContentWellFormedToken)

<a name="new_JoseToken_new"></a>

### new JoseToken()
<p>Constructor for JoseToken that takes in a compact-serialized token string.</p>

<a name="JoseToken+getHeader"></a>

### joseToken.getHeader()
<p>Gets the header as a JS object.</p>

**Kind**: instance method of [<code>JoseToken</code>](#JoseToken)  
<a name="JoseToken+getProtectedHeader"></a>

### joseToken.getProtectedHeader()
<p>Gets the protected headers as a JS object.</p>

**Kind**: instance method of [<code>JoseToken</code>](#JoseToken)  
<a name="JoseToken+isContentWellFormedToken"></a>

### joseToken.isContentWellFormedToken()
<p>Returns true if and only if the content was parsed as a token</p>

**Kind**: instance method of [<code>JoseToken</code>](#JoseToken)  
<a name="JweToken"></a>

## JweToken
<p>Class for performing JWE encryption operations.
This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.</p>

**Kind**: global class  

* [JweToken](#JweToken)
    * [.encrypt()](#JweToken+encrypt) ⇒
    * [.encryptAsFlattenedJson()](#JweToken+encryptAsFlattenedJson) ⇒
    * [.encryptContentEncryptionKey(keyEncryptionAlgorithm, keyBuffer, jwk)](#JweToken+encryptContentEncryptionKey)
    * [.decrypt()](#JweToken+decrypt) ⇒
    * [.toCompactJwe()](#JweToken+toCompactJwe)
    * [.toFlattenedJsonJwe(headers)](#JweToken+toFlattenedJsonJwe)

<a name="JweToken+encrypt"></a>

### jweToken.encrypt() ⇒
<p>Encrypts the original content from construction into a JWE compact serialized format
using the given key in JWK JSON object format.Content encryption algorithm is hardcoded to 'A128GCM'.</p>

**Kind**: instance method of [<code>JweToken</code>](#JweToken)  
**Returns**: <p>Buffer of the original content encrypted in JWE compact serialized format.</p>  
<a name="JweToken+encryptAsFlattenedJson"></a>

### jweToken.encryptAsFlattenedJson() ⇒
<p>Encrypts the original content from construction into a JWE JSON serialized format using
the given key in JWK JSON object format. Content encryption algorithm is hardcoded to 'A128GCM'.</p>

**Kind**: instance method of [<code>JweToken</code>](#JweToken)  
**Returns**: <p>Buffer of the original content encrytped in JWE flattened JSON serialized format.</p>  
<a name="JweToken+encryptContentEncryptionKey"></a>

### jweToken.encryptContentEncryptionKey(keyEncryptionAlgorithm, keyBuffer, jwk)
<p>Encrypts the given content encryption key using the specified algorithm and asymmetric public key.</p>

**Kind**: instance method of [<code>JweToken</code>](#JweToken)  

| Param | Description |
| --- | --- |
| keyEncryptionAlgorithm | <p>Asymmetric encryption algorithm to be used.</p> |
| keyBuffer | <p>The content encryption key to be encrypted.</p> |
| jwk | <p>The asymmetric public key used to encrypt the content encryption key.</p> |

<a name="JweToken+decrypt"></a>

### jweToken.decrypt() ⇒
<p>Decrypts the original JWE using the given key in JWK JSON object format.</p>

**Kind**: instance method of [<code>JweToken</code>](#JweToken)  
**Returns**: <p>Decrypted plaintext of the JWE</p>  
<a name="JweToken+toCompactJwe"></a>

### jweToken.toCompactJwe()
<p>Converts the JWE from the constructed type into a Compact JWE</p>

**Kind**: instance method of [<code>JweToken</code>](#JweToken)  
<a name="JweToken+toFlattenedJsonJwe"></a>

### jweToken.toFlattenedJsonJwe(headers)
<p>Converts the JWE from the constructed type into a Flat JSON JWE</p>

**Kind**: instance method of [<code>JweToken</code>](#JweToken)  

| Param | Description |
| --- | --- |
| headers | <p>unprotected headers to use</p> |

<a name="JwsToken"></a>

## JwsToken
<p>Class for containing JWS token operations.
This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.</p>

**Kind**: global class  

* [JwsToken](#JwsToken)
    * [.sign(jwsHeaderParameters)](#JwsToken+sign) ⇒
    * [.signAsFlattenedJson(jwk, options)](#JwsToken+signAsFlattenedJson)
    * [.verifySignature()](#JwsToken+verifySignature) ⇒
    * [.getPayload()](#JwsToken+getPayload)
    * [.toCompactJws()](#JwsToken+toCompactJws)
    * [.toFlattenedJsonJws(headers)](#JwsToken+toFlattenedJsonJws)

<a name="JwsToken+sign"></a>

### jwsToken.sign(jwsHeaderParameters) ⇒
<p>Signs contents given at construction using the given private key in JWK format.</p>

**Kind**: instance method of [<code>JwsToken</code>](#JwsToken)  
**Returns**: <p>Signed payload in compact JWS format.</p>  

| Param | Description |
| --- | --- |
| jwsHeaderParameters | <p>Header parameters in addition to 'alg' and 'kid' to be included in the JWS.</p> |

<a name="JwsToken+signAsFlattenedJson"></a>

### jwsToken.signAsFlattenedJson(jwk, options)
<p>Signs contents given at construction using the given private key in JWK format with additional optional header fields</p>

**Kind**: instance method of [<code>JwsToken</code>](#JwsToken)  

| Param | Description |
| --- | --- |
| jwk | <p>Private key used in the signature</p> |
| options | <p>Additional protected and header fields to include in the JWS</p> |

<a name="JwsToken+verifySignature"></a>

### jwsToken.verifySignature() ⇒
<p>Verifies the JWS using the given key in JWK object format.</p>

**Kind**: instance method of [<code>JwsToken</code>](#JwsToken)  
**Returns**: <p>The payload if signature is verified. Throws exception otherwise.</p>  
<a name="JwsToken+getPayload"></a>

### jwsToken.getPayload()
<p>Gets the base64 URL decrypted payload.</p>

**Kind**: instance method of [<code>JwsToken</code>](#JwsToken)  
<a name="JwsToken+toCompactJws"></a>

### jwsToken.toCompactJws()
<p>Converts the JWS from the constructed type into a Compact JWS</p>

**Kind**: instance method of [<code>JwsToken</code>](#JwsToken)  
<a name="JwsToken+toFlattenedJsonJws"></a>

### jwsToken.toFlattenedJsonJws(headers)
<p>Converts the JWS from the constructed type into a Flat JSON JWS</p>

**Kind**: instance method of [<code>JwsToken</code>](#JwsToken)  

| Param | Description |
| --- | --- |
| headers | <p>unprotected headers to use</p> |

<a name="PrivateKey"></a>

## *PrivateKey*
<p>Represents a Private Key in JWK format.</p>

**Kind**: global abstract class  
<a name="KeyOperation"></a>

## *KeyOperation*
**Kind**: global abstract class  
<a name="new_KeyOperation_new"></a>

### *new exports.KeyOperation()*
<p>Represents a Public Key in JWK format.</p>

<a name="Base64Url"></a>

## Base64Url
<p>Class for performing various Base64 URL operations.</p>

**Kind**: global class  

* [Base64Url](#Base64Url)
    * [.encode()](#Base64Url.encode)
    * [.decode()](#Base64Url.decode)
    * [.decodeToBuffer()](#Base64Url.decodeToBuffer)
    * [.toBase64()](#Base64Url.toBase64)
    * [.fromBase64()](#Base64Url.fromBase64)

<a name="Base64Url.encode"></a>

### Base64Url.encode()
<p>Encodes the input string or Buffer into a Base64URL string.</p>

**Kind**: static method of [<code>Base64Url</code>](#Base64Url)  
<a name="Base64Url.decode"></a>

### Base64Url.decode()
<p>Decodes a Base64URL string.</p>

**Kind**: static method of [<code>Base64Url</code>](#Base64Url)  
<a name="Base64Url.decodeToBuffer"></a>

### Base64Url.decodeToBuffer()
<p>Decodes a Base64URL string</p>

**Kind**: static method of [<code>Base64Url</code>](#Base64Url)  
<a name="Base64Url.toBase64"></a>

### Base64Url.toBase64()
<p>Converts a Base64URL string to a Base64 string.
TODO: Improve implementation perf.</p>

**Kind**: static method of [<code>Base64Url</code>](#Base64Url)  
<a name="Base64Url.fromBase64"></a>

### Base64Url.fromBase64()
<p>Converts a Base64 string to a Base64URL string.
TODO: Improve implementation perf.</p>

**Kind**: static method of [<code>Base64Url</code>](#Base64Url)  
<a name="ProtectionFormat"></a>

## ProtectionFormat
<p>Enum to define different protection formats</p>

**Kind**: global variable  
<a name="RecommendedKeyType"></a>

## RecommendedKeyType
<p>JWA recommended KeyTypes to be implemented</p>

**Kind**: global variable  
<a name="RecommendedKeyType"></a>

## RecommendedKeyType
<p>JWK key operations</p>

**Kind**: global variable  
<a name="iss"></a>

## iss
<p>DID of the issuer of the request. This should match the signature</p>

**Kind**: global variable  
<a name="response_type"></a>

## response\_type
<p>MUST be set as 'id_token' in order to match OIDC self-issued protocol</p>

**Kind**: global variable  
<a name="client_id"></a>

## client\_id
<p>The redirect url as specified in the OIDC self-issued protocol</p>

**Kind**: global variable  
<a name="scope"></a>

## scope
<p>MUST be set to 'openid'</p>

**Kind**: global variable  
<a name="state"></a>

## state
<p>Opaque value used by issuer for state</p>

**Kind**: global variable  
<a name="nonce"></a>

## nonce
<p>Request Nonce</p>

**Kind**: global variable  
<a name="claims"></a>

## claims
<p>Claims that are requested</p>

**Kind**: global variable  
