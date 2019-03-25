import CryptoSuite, { Encrypter, Signer, SymmetricEncrypter, PublicKeyConstructors } from '../../interfaces/CryptoSuite';
import crypto from 'crypto';

/**
 * Encrypter plugin for Advanced Encryption Standard symmetric keys
 */
export default class AesCryptoSuite implements CryptoSuite {

  getEncrypters (): { [algorithm: string]: Encrypter } {
    return {};
  }

  getSigners (): { [algorithm: string]: Signer; } {
    return {};
  }

  getKeyConstructors (): PublicKeyConstructors {
    return {};
  }

  getSymmetricEncrypters (): { [algorithm: string]: SymmetricEncrypter } {
    return {
      'A128GCM': {
        encrypt: this.encryptAesGcm(128),
        decrypt: this.decryptAesGcm(128)
      },
      'A192GCM': {
        encrypt: this.encryptAesGcm(192),
        decrypt: this.decryptAesGcm(192)
      },
      'A256GCM': {
        encrypt: this.encryptAesGcm(256),
        decrypt: this.decryptAesGcm(256)
      },
      'A128CBC-HS256': {
        encrypt: this.encryptAesCbcHmacSha2(128, 256),
        decrypt: this.decryptAesCbcHmacSha2(128, 256)
      },
      'A192CBC-HS384': {
        encrypt: this.encryptAesCbcHmacSha2(192, 384),
        decrypt: this.decryptAesCbcHmacSha2(192, 384)
      },
      'A256CBC-HS512': {
        encrypt: this.encryptAesCbcHmacSha2(256, 512),
        decrypt: this.decryptAesCbcHmacSha2(256, 512)
      }
    };
  }

  /**
   * Given the encryption parameters, returns the AES CBC HMAC SHA2 encryption function
   * @param keySize Size of the keys
   * @param hashSize Size of the SHA2 hash
   * @returns a SymmetricEncrypter encrypt function
   */
  private encryptAesCbcHmacSha2 (keySize: number, hashSize: number): (plaintext: Buffer, additionalAuthenticatedData: Buffer) =>
  Promise<{ciphertext: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer}> {
    return async (plaintext: Buffer, additionalAuthenticatedData: Buffer) => {
      const mackey = this.generateSymmetricKey(keySize);
      const enckey = this.generateSymmetricKey(keySize);
      const initializationVector = this.generateInitializationVector(128);
      const algorithm = `aes-${keySize}-cbc`;
      const cipher = crypto.createCipheriv(algorithm, enckey, initializationVector);
      const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
      ]);
      const tag = this.generateHmacTag(hashSize, keySize, mackey, additionalAuthenticatedData, initializationVector, ciphertext);
      return {
        ciphertext,
        initializationVector,
        key: Buffer.concat([mackey, enckey]),
        tag
      };
    };
  }

  /**
   * Given the decryption parameters, returns an AES CBC HMAC SHA2 decryption function
   * @param keySize Size of the keys
   * @param hashSize Size of the SHA2 hash
   * @returns a SymmetricEncrypter decrypt function
   */
  private decryptAesCbcHmacSha2 (keySize: number, hashSize: number):
  (ciphertext: Buffer, additionalAuthenticatedData: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer) =>
  Promise<Buffer> {
    return async (ciphertext: Buffer, additionalAuthenticatedData: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer) => {
      const splitLength = key.length / 2;
      const mackey = key.slice(0, splitLength);
      const enckey = key.slice(splitLength, key.length);
      const computedTag = this.generateHmacTag(hashSize, keySize, mackey, additionalAuthenticatedData, initializationVector, ciphertext);
      if (computedTag.compare(tag) !== 0) {
        throw new Error('Invalid tag');
      }
      const algorithm = `aes-${keySize}-cbc`;
      const decipher = crypto.createDecipheriv(algorithm, enckey, initializationVector);
      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);
      return plaintext;
    };
  }

  /**
   * Given the encryption parameters, returns the AES GCM encryption function
   * @param keySize Size of the keys
   * @returns a SymmetricEncrypter encrypt function
   */
  private encryptAesGcm (keySize: number): (plaintext: Buffer, additionalAuthenticatedData: Buffer) =>
  Promise<{ciphertext: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer}> {
    return async (plaintext: Buffer, additionalAuthenticatedData: Buffer) => {
      const key = this.generateSymmetricKey(keySize);
      const initializationVector = this.generateInitializationVector(96);
      const algorithm = `aes-${keySize}-gcm`;
      const cipher = crypto.createCipheriv(algorithm, key, initializationVector) as crypto.CipherGCM;
      cipher.setAAD(additionalAuthenticatedData);
      const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
      ]);
      return {
        ciphertext,
        initializationVector,
        key,
        tag: cipher.getAuthTag()
      };
    };
  }

  /**
   * Given the decryption parameters, returns an AES GCM decryption function
   * @param keySize Size of the keys
   * @returns a SymmetricEncrypter decrypt function
   */
  private decryptAesGcm (keySize: number):
  (ciphertext: Buffer, additionalAuthenticatedData: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer) =>
  Promise<Buffer> {
    return async (ciphertext: Buffer, additionalAuthenticatedData: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer) => {
      const algorithm = `aes-${keySize}-gcm`;
      const decipher = crypto.createDecipheriv(algorithm, key, initializationVector) as crypto.DecipherGCM;
      decipher.setAAD(additionalAuthenticatedData);
      decipher.setAuthTag(tag);
      return Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
      ]);
    };
  }

  /**
   * Generates the HMAC Tag
   * @param hashSize HMAC hash size
   * @param keySize HMAC tag size
   * @param mackey MAC key
   * @param additionalAuthenticatedData Additional authenticated data
   * @param initializationVector initialization vector
   * @param ciphertext encrypted data
   * @returns HMAC Tag
   */
  private generateHmacTag (hashSize: number, keySize: number, mackey: Buffer,
    additionalAuthenticatedData: Buffer, initializationVector: Buffer, ciphertext: Buffer): Buffer {
    const mac = this.generateHmac(hashSize, mackey, additionalAuthenticatedData, initializationVector, ciphertext);
    return mac.slice(0, Math.ceil(keySize / 8));
  }

  /**
   * Generates the full HMac
   * @param hashSize HMAC hash size
   * @param mackey MAC key
   * @param additionalAuthenticatedData Additional authenticated data
   * @param initializationVector initialization vector
   * @param ciphertext encrypted data
   * @returns HMAC in full
   */
  private generateHmac (hashSize: number, mackey: Buffer,
    additionalAuthenticatedData: Buffer, initializationVector: Buffer, ciphertext: Buffer): Buffer {
    const al = this.getAdditionalAuthenticatedDataLength(additionalAuthenticatedData);
    const hmac = crypto.createHmac(`sha${hashSize}`, mackey);
    hmac.update(additionalAuthenticatedData);
    hmac.update(initializationVector);
    hmac.update(ciphertext);
    hmac.update(al);
    const mac = hmac.digest();
    return mac;
  }

  /**
   * Gets the Additional Authenticated Data length in Big Endian notation
   * @param additionalAuthenticatedData Additional authenticated data
   * @return Additional Authenticated Data returned as a base64 big endian unsigned integer
   */
  private getAdditionalAuthenticatedDataLength (additionalAuthenticatedData: Buffer): Buffer {
    const aadLength = additionalAuthenticatedData.length * 8;
    const alMsb = aadLength & 0xFFFFFFFF00000000;
    const alLsb = (aadLength >> 32) & 0x00000000FFFFFFFF;
    const al = Buffer.alloc(8);
    al.writeUInt32BE(alMsb, 0);
    al.writeUInt32BE(alLsb, 4);
    return al;
  }

  // these are two different functions to allow validation against RFC specs

  /**
   * Generates a symmetric key
   * @param bits Size in bits of the key
   */
  private generateSymmetricKey (bits: number): Buffer {
    return crypto.randomBytes(Math.ceil(bits / 8));
  }

  /**
   * Generates an initialization vector
   * @param bits Size in bits of the initialization vector
   */
  private generateInitializationVector (bits: number): Buffer {
    return crypto.randomBytes(Math.ceil(bits / 8));
  }
}
