import CryptoSuite, {Encrypter, Signer, SymmetricEncrypter, PublicKeyConstructors} from "../../interfaces/CryptoSuite";
import crypto from 'crypto';

export default class AesCryptoSuite implements CryptoSuite {
  getEncrypters(): { [algorithm: string]: Encrypter } {
    return {};
  }
  getSigners(): { [algorithm: string]: Signer; } {
    return {};
  }
  getKeyConstructors(): PublicKeyConstructors {
    return {};
  }
  getSymmetricEncrypters(): { [algorithm: string]: SymmetricEncrypter } {
    return {
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
    }
  }

  /**
   * Given the encryption parameters, returns the AES CBC HMAC SHA2 encryption function
   * @param keySize Size of the keys
   * @param hashSize Size of the SHA2 hash
   * @returns a SymmetricEncrypter encrypt function
   */
  private encryptAesCbcHmacSha2(keySize: number, hashSize: number): (plaintext: Buffer, additionalAuthenticatedData: Buffer) =>
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
  private decryptAesCbcHmacSha2(keySize: number, hashSize: number):
  (ciphertext: Buffer, additionalAuthenticatedData: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer) =>
  Promise<Buffer> {
    return async (ciphertext: Buffer, additionalAuthenticatedData: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer) {
      const mackey = key.slice(0, 4);
      const enckey = key.slice(4, 8);
      const computedTag = this.generateHmacTag(hashSize, keySize, mackey, additionalAuthenticatedData, initializationVector, ciphertext);
      if (computedTag !== tag) {
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

  private generateHmacTag (hashSize: number, keySize: number, mackey: Buffer,
    additionalAuthenticatedData: Buffer, initializationVector: Buffer, ciphertext: Buffer): Buffer {
    const aadLength = additionalAuthenticatedData.length * 8;
    const alMsb = (aadLength >> 32) & 0xFFFFFFFF;
    const alLsb = aadLength & 0xFFFFFFFF;
    const al = Buffer.alloc(8);
    al.writeUInt32BE(alMsb, 0);
    al.writeUInt32BE(alLsb, 4);
    const hmac = crypto.createHmac(`sha${hashSize}`, mackey);
    hmac.update(additionalAuthenticatedData);
    hmac.update(initializationVector);
    hmac.update(ciphertext);
    hmac.update(al);
    const mac = hmac.digest();
    return mac.slice(0, Math.ceil(keySize / 8));
  }

  private generateSymmetricKey(bits: number): Buffer {
    return crypto.randomBytes(Math.ceil(bits / 8));
  }

  private generateInitializationVector(bits: number): Buffer {
    return crypto.randomBytes(Math.ceil(bits / 8));
  }
}