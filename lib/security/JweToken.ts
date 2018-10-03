import * as crypto from 'crypto';
import Base64Url from '../utilities/Base64Url';
import JoseToken from './JoseToken';
import PublicKey from '../security/PublicKey';
import { PrivateKey } from '..';

// TODO: Rewrite decrypt() to allow additional cryptographic algorithms to be added easily then remove dependency on 'node-jose'.
const jose = require('node-jose');

/**
 * Definition for a delegate that can encrypt data.
 */
type EncryptDelegate = (data: Buffer, jwk: PublicKey) => Buffer;

/**
 * Class for performing JWE encryption operations.
 * This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.
 */
export default class JweToken extends JoseToken {
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
    const encryptedKeyBuffer = this.encryptContentEncryptionKey(keyEncryptionAlgorithm, keyBuffer, jwk);
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
  private encryptContentEncryptionKey (keyEncryptionAlgorithm: string, keyBuffer: Buffer,
                                             jwk: PublicKey): Buffer {

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
    const key = await jose.JWK.asKey(jwk); // NOTE: Must use library object for decryption.
    const decryptedData = await jose.JWE.createDecrypt(key).decrypt(this.content);
    const decryptedPlaintext = decryptedData.plaintext.toString();

    return decryptedPlaintext;
  }
}
