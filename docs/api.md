## Classes

<dl>
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
</dl>

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
