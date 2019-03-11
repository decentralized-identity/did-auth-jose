import * as crypto from 'crypto';
import Base64Url from '../utilities/Base64Url';
import JoseToken from './JoseToken';
import PublicKey from '../security/PublicKey';
import PrivateKey from '../security/PrivateKey';
import { CryptoFactory } from '..';

/**
 * Definition for a delegate that can encrypt data.
 */
type EncryptDelegate = (data: Buffer, jwk: PublicKey) => Promise<Buffer>;

/**
 * Class for performing JWE encryption operations.
 * This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.
 */
export default class JweToken extends JoseToken {

  // used for verification if a JSON Serialized JWS was given
  private readonly protected: string | undefined;
  private unprotected: {[key: string]: any} | undefined;
  private readonly encrypted_key: string | undefined;
  private readonly iv: string | undefined;
  private readonly tag: string | undefined;
  private readonly aad: string | undefined;
  private readonly isFlattenedJSONSerialized: boolean;

  public constructor (content: string | object, protected cryptoFactory: CryptoFactory) {
    super(content, cryptoFactory);
    const jsonContent: any = content;
    this.isFlattenedJSONSerialized = false;
    if (typeof jsonContent === 'object' &&
    'ciphertext' in jsonContent && typeof jsonContent.ciphertext === 'string' &&
    'aad' in jsonContent && typeof jsonContent.aad === 'string' &&
    'iv' in jsonContent && typeof jsonContent.iv === 'string' &&
    'tag' in jsonContent && typeof jsonContent.tag === 'string' &&
    (('protected' in jsonContent && typeof jsonContent.protected === 'string') ||
    ('unprotected' in jsonContent && typeof jsonContent.unprotected === 'object'))) {
      if ('protected' in jsonContent) {
        this.protected = jsonContent.protected;
      }
      if ('unprotected' in jsonContent) {
        this.unprotected = jsonContent.unprotected;
      }
      this.iv = jsonContent.iv;
      this.tag = jsonContent.tag;
      this.aad = jsonContent.aad;
      if ('recipients' in jsonContent) {
        // TODO: General JWE JSON Serialization
      } else if ('encrypted_key' in jsonContent && typeof jsonContent.encrypted_key === 'string') {
        // Flattened JWE JSON Serialization
        this.encrypted_key = jsonContent.encrypted_key;
        if ('header' in jsonContent && typeof jsonContent.header === 'object') {
          this.unprotected = Object.assign(this.unprotected, jsonContent.header);
        }
        this.isFlattenedJSONSerialized = true;
      }
      this.content = jsonContent.ciphertext;
    }
  }

  /**
   * Encrypts the given string in JWE compact serialized format using the given key in JWK JSON object format.
   * Content encryption algorithm is hardcoded to 'A128GCM'.
   *
   * @returns Encrypted Buffer in JWE compact serialized format.
   */
  public async encrypt (jwk: PublicKey,
                        additionalHeaders?: {[header: string]: string}
                        /* encryptionType?: string */): Promise<Buffer> {
    /// TODO: extend to include encryptionType to determine symmetric key encryption using register

    // Decide key encryption algorithm based on given JWK.
    const keyEncryptionAlgorithm = jwk.defaultEncryptionAlgorithm;

    // Construct header.
    let header: {[header: string]: string} = Object.assign({}, {
      kid: jwk.kid,
      alg: keyEncryptionAlgorithm,
      enc: 'A128GCM'
    }, additionalHeaders);

    // Base 64 encode header.
    const protectedHeaderBase64Url = Base64Url.encode(JSON.stringify(header));

    // Generate content encryption key.
    const keyBuffer = crypto.randomBytes(16);

    // Encrypt content encryption key then base64-url encode it.
    const encryptedKeyBuffer = await this.encryptContentEncryptionKey(keyEncryptionAlgorithm, keyBuffer, jwk);
    const encryptedKeyBase64Url = Base64Url.encode(encryptedKeyBuffer);

    // Generate initialization vector then base64-url encode it.
    const initializationVectorBuffer = crypto.randomBytes(12);
    const initializationVectorBase64Url = Base64Url.encode(initializationVectorBuffer);

    // Encrypt content.
    const cipher = crypto.createCipheriv('aes-128-gcm', keyBuffer, initializationVectorBuffer);
    cipher.setAAD(Buffer.from(protectedHeaderBase64Url));
    const ciphertextBuffer = Buffer.concat([
      cipher.update(Buffer.from(this.content)),
      cipher.final()
    ]);
    const ciphertextBase64Url = Base64Url.encode(ciphertextBuffer);

    // Get the authentication tag.
    const authenticationTagBuffer = cipher.getAuthTag();
    const authenticationTagBase64Url = Base64Url.encode(authenticationTagBuffer);

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
   * Decrypts the given JWE compact serialized string using the given key in JWK JSON object format.
   * TODO: implement decryption without node-jose dependency so we can use decryption algorithms from plugins.
   *
   * @returns Decrypted plaintext.
   */
  public async decrypt (jwk: PrivateKey): Promise<string> {
    let base64EncodedValues: string[];
    // following steps for JWE Decryption in RFC7516 section 5.2
    if (this.isFlattenedJSONSerialized) {
      // use the pre-parsed contents.
      base64EncodedValues = [this.protected!,
        this.encrypted_key!,
        this.iv!,
        this.content!,
        this.tag!];
    } else {
      // 1. Parse JWE for components: BASE64URL(UTF8(JWE Header)) || '.' || BASE64URL(JWE Encrypted Key) || '.' ||
      //    BASE64URL(JWE Initialization Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' ||
      //    BASE64URL(JWE Authentication Tag)
      base64EncodedValues = this.content.split('.');
    }

    // 2. Base64url decode the encoded header, encryption key, iv, ciphertext, and auth tag
    const headerString = Base64Url.decode(base64EncodedValues[0]);
    const encryptedKey = Buffer.from(Base64Url.toBase64(base64EncodedValues[1]), 'base64');
    const iv = Buffer.from(Base64Url.toBase64(base64EncodedValues[2]), 'base64');
    const ciphertext = Buffer.from(Base64Url.toBase64(base64EncodedValues[3]), 'base64');
    const authTag = Buffer.from(Base64Url.toBase64(base64EncodedValues[4]), 'base64');
    // 3. let the JWE Header be a JSON object
    const headers = JSON.parse(headerString);
    // 4. only applies to JWE JSON Serializaiton
    // 5. verify header fields
    ['alg', 'enc', 'kid'].forEach((header: string) => {
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
    if (headers.kid !== jwk.kid) {
      throw new Error('JWEToken key does not match provided jwk key');
    }
    // 8. With keywrapping or direct key, let the jwk.kid be used to decrypt the encryptedkey
    // 9. Unwrap the encryptedkey to produce the content encryption key (CEK)
    const cek = await (this.cryptoFactory.getEncrypter(headers.alg)).decrypt(encryptedKey, jwk);
    // TODO: Verify CEK length meets "enc" algorithm's requirement
    // 10. TODO: Support direct key, then ensure encryptedKey === ""
    // 11. TODO: Support direct encryption, let CEK be the shared symmetric key
    // 12. record successful CEK for this recipient or not
    // 13. Skip due to JWE JSON Serialization format specific
    // 14. Compute the protected header: BASE64URL(UTF8(JWE Header))
    // this would be base64Encodedvalues[0]
    // 15. Let the Additional Authentication Data (AAD) be ASCII(encodedprotectedHeader)
    let aad: string;
    if (this.isFlattenedJSONSerialized) {
      aad = this.aad!;
    } else {
      aad = base64EncodedValues[0];
    }
    // 16. Decrypt JWE Ciphertext using CEK, IV, AAD, and authTag, using "enc" algorithm.

    // TODO: complex work involving symmetric key encryption here
    const cryptoMap: {[enc: string]: string} = {
      A128GCM: 'aes-128-gcm',
      A192GCM: 'aes-192-gcm',
      A256GCM: 'aes-256-gcm'
    };
    const enc = cryptoMap[headers.enc];

    const decipher = crypto.createDecipheriv(enc, cek, iv) as crypto.DecipherGCM;
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(authTag);
    const plaintext = decipher.update(ciphertext, 'base64', 'utf8');
    if (decipher.final().length !== 0) {
      throw new Error('crypto cipher final returned additional data');
    }

    // 17. if a "zip" parameter was included, uncompress the plaintext using the specified algorithm
    if ('zip' in headers) {
      throw new Error('"zip" is not currently supported');
    }
    // 18. If there was no recipient, the JWE is invalid. Otherwise output the plaintext.
    return plaintext;
  }
}
