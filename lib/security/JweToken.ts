import Base64Url from '../utilities/Base64Url';
import JoseToken from './JoseToken';
import PublicKey from '../security/PublicKey';
import PrivateKey from '../security/PrivateKey';
import CryptoFactory from '../CryptoFactory';

/**
 * Definition for a delegate that can encrypt data.
 */
type EncryptDelegate = (data: Buffer, jwk: PublicKey) => Promise<Buffer>;

/**
 * JWE in flattened json format
 */
export type FlatJsonJwe = {
  /** The protected (integrity) header. */
  protected?: string,
  /** The unprotected (unverified) header. */
  unprotected?: {[key: string]: string},
  /** Contain the value BASE64URL(JWE Encrypted Key) */
  encrypted_key: string,
  /** Contains the initial vector used for encryption */
  iv: string,
  /** The encrypted data */
  ciphertext: string,
  /** Contain the value BASE64URL(JWE Authentication Tag) */
  tag: string,
  /**  Contains the additional value */
  aad?: string
};

/**
 * Class for performing JWE encryption operations.
 * This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.
 */
export default class JweToken extends JoseToken {

  // used for verification if a JSON Serialized JWS was given
  private readonly encryptedKey: Buffer | undefined;
  private readonly iv: Buffer | undefined;
  private readonly tag: Buffer | undefined;
  private readonly aad: Buffer | undefined;

  public constructor (content: string | object, protected cryptoFactory: CryptoFactory) {
    super(content, cryptoFactory);
    let jsonContent: any = content;
    // check for compact JWE
    if (typeof content === 'string') {
      // 1. Parse JWE for components: BASE64URL(UTF8(JWE Header)) || '.' || BASE64URL(JWE Encrypted Key) || '.' ||
      //    BASE64URL(JWE Initialization Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' ||
      //    BASE64URL(JWE Authentication Tag)
      const base64EncodedValues = content.split('.');
      if (base64EncodedValues.length === 5) {
        // 2. Base64url decode the encoded header, encryption key, iv, ciphertext, and auth tag
        this.protectedHeaders = base64EncodedValues[0];
        this.encryptedKey = Base64Url.decodeToBuffer(base64EncodedValues[1]);
        this.iv = Base64Url.decodeToBuffer(base64EncodedValues[2]);
        this.payload = base64EncodedValues[3];
        this.tag = Base64Url.decodeToBuffer(base64EncodedValues[4]);
        // 15. Let the Additional Authentication Data (AAD) be ASCII(encodedprotectedHeader)
        this.aad = Buffer.from(base64EncodedValues[0]);
        return;
      }
      // attempt to parse the string into a JSON object in the event it is a JSON serialized token
      try {
        jsonContent = JSON.parse(content);
      } catch (error) {
        // it was not.
      }
    }

    if (typeof jsonContent === 'object' &&
    'ciphertext' in jsonContent && typeof jsonContent.ciphertext === 'string' &&
    'iv' in jsonContent && typeof jsonContent.iv === 'string' &&
    'tag' in jsonContent && typeof jsonContent.tag === 'string' &&
    ('protected' in jsonContent || 'unprotected' in jsonContent || 'header' in jsonContent)) {
      if (
        ('protected' in jsonContent && jsonContent.protected !== undefined && typeof jsonContent.protected !== 'string') ||
        ('unprotected' in jsonContent && jsonContent.unprotected !== undefined && typeof jsonContent.unprotected !== 'object') ||
        ('header' in jsonContent && jsonContent.header !== undefined && typeof jsonContent.header !== 'object')
        ) {
        // One of the properties is of the wrong type
        return;
      }
      if ('recipients' in jsonContent) {
        // TODO: General JWE JSON Serialization (Issue #22)
        return;
      } else if ('encrypted_key' in jsonContent && typeof jsonContent.encrypted_key === 'string') {
        // Flattened JWE JSON Serialization
        if ('header' in jsonContent) {
          this.unprotectedHeaders = jsonContent.header;
        }
        this.encryptedKey = Base64Url.decodeToBuffer(jsonContent.encrypted_key);
      } else {
        // This isn't a JWE
        return;
      }
      if ('protected' in jsonContent) {
        this.protectedHeaders = jsonContent.protected;
      }
      if ('unprotected' in jsonContent) {
        if (this.unprotectedHeaders) {
          this.unprotectedHeaders = Object.assign(this.unprotectedHeaders, jsonContent.unprotected);
        } else {
          this.unprotectedHeaders = jsonContent.unprotected;
        }
      }
      this.iv = Base64Url.decodeToBuffer(jsonContent.iv);
      this.tag = Base64Url.decodeToBuffer(jsonContent.tag);
      this.payload = jsonContent.ciphertext;
      if (jsonContent.aad) {
        this.aad = Buffer.from(this.protectedHeaders + '.' + jsonContent.aad);
      } else {
        this.aad = Buffer.from(this.protectedHeaders || '');
      }
    }
  }

  /**
   * Encrypts the original content from construction into a JWE compact serialized format
   * using the given key in JWK JSON object format.Content encryption algorithm is hardcoded to 'A128GCM'.
   *
   * @returns Buffer of the original content encrypted in JWE compact serialized format.
   */
  public async encrypt (jwk: PublicKey,
                        additionalHeaders?: {[header: string]: string}): Promise<Buffer> {

    // Decide key encryption algorithm based on given JWK.
    const keyEncryptionAlgorithm = jwk.defaultEncryptionAlgorithm;

    // Construct header.
    const enc = this.cryptoFactory.getDefaultSymmetricEncryptionAlgorithm();
    let header: {[header: string]: string} = Object.assign({}, {
      kid: jwk.kid,
      alg: keyEncryptionAlgorithm,
      enc
    }, additionalHeaders);

    // Base64url encode header.
    const protectedHeaderBase64Url = Base64Url.encode(JSON.stringify(header));

    // Get the symmetric encrypter and encrypt
    const symEncrypter = this.cryptoFactory.getSymmetricEncrypter(header.enc);
    const symEnc = await symEncrypter.encrypt(Buffer.from(this.content), Buffer.from(protectedHeaderBase64Url));

    // Encrypt content encryption key then base64-url encode it.
    const encryptedKeyBuffer = await this.encryptContentEncryptionKey(header.alg, symEnc.key, jwk);
    const encryptedKeyBase64Url = Base64Url.encode(encryptedKeyBuffer);

    // Get the base64s of the symmetric encryptions
    const initializationVectorBase64Url = Base64Url.encode(symEnc.initializationVector);
    const ciphertextBase64Url = Base64Url.encode(symEnc.ciphertext);
    const authenticationTagBase64Url = Base64Url.encode(symEnc.tag);

    // Form final compact serialized JWE string.
    const jweString = [
      protectedHeaderBase64Url,
      encryptedKeyBase64Url,
      initializationVectorBase64Url,
      ciphertextBase64Url,
      authenticationTagBase64Url
    ].join('.');

    return Buffer.from(jweString);
  }

  /**
   * Encrypts the original content from construction into a JWE JSON serialized format using
   * the given key in JWK JSON object format. Content encryption algorithm is hardcoded to 'A128GCM'.
   *
   * @returns Buffer of the original content encrytped in JWE flattened JSON serialized format.
   */
  public async encryptAsFlattenedJson (jwk: PublicKey,
    options?: {
  /** The unprotected (unverified) header. */
      unprotected?: {[key: string]: any},
  /** The protected (integrity) header. */
      protected?: {[key: string]: any},
  /**  Contains the additional value */
      aad?: string | Buffer
    }): Promise<FlatJsonJwe> {

    // Decide key encryption algorithm based on given JWK.
    const keyEncryptionAlgorithm = jwk.defaultEncryptionAlgorithm;

    // Construct header.
    let header: {[header: string]: string} = Object.assign({}, {
      kid: jwk.kid,
      alg: keyEncryptionAlgorithm,
      enc: this.cryptoFactory.getDefaultSymmetricEncryptionAlgorithm()
    }, (options || {}).protected || {});

    // Base64url encode header.
    const protectedHeaderBase64Url = Base64Url.encode(JSON.stringify(header));

    const aad = Buffer.from(options && options.aad ? `${protectedHeaderBase64Url}.${Base64Url.encode(options.aad)}` : protectedHeaderBase64Url);

    // Symmetrically encrypt the content
    const symEncrypter = this.cryptoFactory.getSymmetricEncrypter(header.enc);
    const symEncParams = await symEncrypter.encrypt(Buffer.from(this.content), aad);

    // Encrypt content encryption key and base64 all the parameters
    const encryptedKeyBuffer = await this.encryptContentEncryptionKey(keyEncryptionAlgorithm, symEncParams.key, jwk);
    const encryptedKeyBase64Url = Base64Url.encode(encryptedKeyBuffer);
    const initializationVectorBase64Url = Base64Url.encode(symEncParams.initializationVector);
    const ciphertextBase64Url = Base64Url.encode(symEncParams.ciphertext);
    const authenticationTagBase64Url = Base64Url.encode(symEncParams.tag);

    // Form final compact serialized JWE string.
    let returnJwe: FlatJsonJwe = {
      protected: protectedHeaderBase64Url,
      unprotected: (options || {}).unprotected,
      encrypted_key: encryptedKeyBase64Url,
      iv: initializationVectorBase64Url,
      ciphertext: ciphertextBase64Url,
      tag: authenticationTagBase64Url
    };
    if (options && options.aad) {
      returnJwe.aad = Base64Url.encode(options.aad);
    }
    return returnJwe;
  }

  /**
   * Encrypts the given content encryption key using the specified algorithm and asymmetric public key.
   *
   * @param keyEncryptionAlgorithm Asymmetric encryption algorithm to be used.
   * @param keyBuffer The content encryption key to be encrypted.
   * @param jwk The asymmetric public key used to encrypt the content encryption key.
   */
  private async encryptContentEncryptionKey (keyEncryptionAlgorithm: string, keyBuffer: Buffer,
                                             jwk: PublicKey): Promise<Buffer> {

    let encrypt: EncryptDelegate;
    let encrypter = this.cryptoFactory.getEncrypter(keyEncryptionAlgorithm);

    // Find the correct encryption algorithm from all cryptoAlgorithm plugins.
    if (encrypter) {
      encrypt = encrypter.encrypt;
    } else {
      const err = new Error(`Unsupported encryption algorithm: ${keyEncryptionAlgorithm}`);
      throw err;
    }
    return encrypt(keyBuffer, jwk);
  }

  /**
   * Decrypts the original JWE using the given key in JWK JSON object format.
   *
   * @returns Decrypted plaintext of the JWE
   */
  public async decrypt (jwk: PrivateKey): Promise<string> {
    // following steps for JWE Decryption in RFC7516 section 5.2
    if (this.encryptedKey === undefined || this.payload === undefined || this.iv === undefined || this.aad === undefined || this.tag === undefined) {
      throw new Error('Could not parse contents into a JWE');
    }
    const ciphertext = Base64Url.decodeToBuffer(this.payload);

    const headers = this.getHeader();
    // 4. only applies to JWE JSON Serializaiton
    // 5. verify header fields
    ['alg', 'enc'].forEach((header: string) => {
      if (!(header in headers)) {
        throw new Error(`Missing required header: ${header}`);
      }
    });

    if ('crit' in headers) { // RFC7516 4.1.13/RFC7515 4.1.11
      const extensions = headers.crit as string[];
      if (extensions.filter) {
        // TODO: determine which additional header fields are supported
        const supported: string[] = [];
        const unsupported = extensions.filter((extension) => { return !(extension in supported); });
        if (unsupported.length > 0) {
          throw new Error(`Unsupported "crit" headers: ${unsupported.join(', ')}`);
        }
      } else {
        throw new Error('Malformed "crit" header field');
      }
    }
    // 6. Determine the Key management mode by the "alg" header
    // TODO: Support other methods beyond key wrapping
    // 7. Verify that the JWE key is known
    if (headers.kid && jwk.kid && headers.kid !== jwk.kid) {
      throw new Error('JWEToken key does not match provided jwk key');
    }
    // 8. With keywrapping or direct key, let the jwk.kid be used to decrypt the encryptedkey
    // 9. Unwrap the encryptedkey to produce the content encryption key (CEK)
    const cek = await (this.cryptoFactory.getEncrypter(headers.alg)).decrypt(this.encryptedKey, jwk);
    // TODO: Verify CEK length meets "enc" algorithm's requirement
    // 10. TODO: Support direct key, then ensure encryptedKey === ""
    // 11. TODO: Support direct encryption, let CEK be the shared symmetric key
    // 12. record successful CEK for this recipient or not
    // 13. Skip due to JWE JSON Serialization format specific
    // 14. Compute the protected header: BASE64URL(UTF8(JWE Header))
    // this would be base64Encodedvalues[0]
    // 16. Decrypt JWE Ciphertext using CEK, IV, AAD, and authTag, using "enc" algorithm.

    const symDecrypter = this.cryptoFactory.getSymmetricEncrypter(headers.enc);
    const plaintext = await symDecrypter.decrypt(ciphertext, this.aad, this.iv, cek, this.tag);

    // 17. if a "zip" parameter was included, uncompress the plaintext using the specified algorithm
    if ('zip' in headers) {
      throw new Error('"zip" is not currently supported');
    }
    // 18. If there was no recipient, the JWE is invalid. Otherwise output the plaintext.
    return plaintext.toString('utf8');
  }

  /**
   * Converts the JWE from the constructed type into a Compact JWE
   */
  public toCompactJwe (): string {
    if (this.encryptedKey === undefined || this.payload === undefined || this.iv === undefined || this.aad === undefined || this.tag === undefined) {
      throw new Error('Could not parse contents into a JWE');
    }
    const protectedHeaders = this.getProtectedHeader();
    if (!('alg' in protectedHeaders) || !('enc' in protectedHeaders)) {
      throw new Error("'alg' and 'enc' are required to be in the protected header");
    }
    // Compact JWEs must have the default AAD value of the protected header (RFC 7516 5.1.14)
    if (this.aad.compare(Buffer.from(this.protectedHeaders || '')) !== 0) {
      throw new Error("'aad' must not be set in original JWE");
    }
    const encryptedKeyBase64Url = Base64Url.encode(this.encryptedKey);
    const initializationVectorBase64Url = Base64Url.encode(this.iv);
    const authenticationTagBase64Url = Base64Url.encode(this.tag);
    return `${this.protectedHeaders}.${encryptedKeyBase64Url}.${initializationVectorBase64Url}.${this.payload}.${authenticationTagBase64Url}`;
  }

  /**
   * Converts the JWE from the constructed type into a Flat JSON JWE
   * @param headers unprotected headers to use
   */
  public toFlattenedJsonJwe (headers?: {[member: string]: any}): FlatJsonJwe {
    if (this.encryptedKey === undefined || this.payload === undefined || this.iv === undefined || this.aad === undefined || this.tag === undefined) {
      throw new Error('Could not parse contents into a JWE');
    }
    const unprotectedHeaders = headers || this.unprotectedHeaders || undefined;
    const protectedHeaders = this.getProtectedHeader();
    // TODO: verify no header parameters in unprotected headers conflict with protected headers
    if ((!('alg' in protectedHeaders) &&
         !(unprotectedHeaders && ('alg' in unprotectedHeaders))
        ) || (
         !('enc' in protectedHeaders) &&
         !(unprotectedHeaders && ('enc' in unprotectedHeaders))
        )) {
      throw new Error("'alg' and 'enc' are required to be in the header or protected header");
    }
    const encryptedKeyBase64Url = Base64Url.encode(this.encryptedKey);
    const initializationVectorBase64Url = Base64Url.encode(this.iv);
    const authenticationTagBase64Url = Base64Url.encode(this.tag);
    let jwe = {
      encrypted_key: encryptedKeyBase64Url,
      iv: initializationVectorBase64Url,
      ciphertext: this.payload,
      tag: authenticationTagBase64Url
    };
    // add AAD if its unique
    if (this.aad.compare(Buffer.from(this.protectedHeaders || '')) !== 0) {
      // decrypt the aad and remove the protected headers.
      const aadParts = this.aad.toString().split('.');
      // Only the unique part of the aad is required
      jwe = Object.assign(jwe, { aad: aadParts[1] });
    }
    if (this.protectedHeaders) {
      jwe = Object.assign(jwe, { protected: this.protectedHeaders });
    }
    if (unprotectedHeaders) {
      jwe = Object.assign(jwe, { unprotected: unprotectedHeaders });
    }
    return jwe;
  }
}
