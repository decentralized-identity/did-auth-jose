import CryptoSuite from '../../lib/interfaces/CryptoSuite';
import { TestPublicKey } from './TestPublicKey';

/**
 * A {@link CryptoSuite} used for unit testing
 */
export default class TestCryptoSuite implements CryptoSuite {
  private readonly id: number;
  private static called: {[id: number]: number} = {};
  private static readonly ENCRYPT = 0x1;
  private static readonly DECRYPT = 0x2;
  private static readonly SIGN = 0x4;
  private static readonly VERIFY = 0x8;
  private static readonly SYMENCRYPT = 0xF;
  private static readonly SYMDECRYPT = 0x10;

  getKeyConstructors () {
    return {
      test: () => { return new TestPublicKey(); }
    };
  }

  constructor () {
    this.id = Math.round(Math.random() * Number.MAX_SAFE_INTEGER);
  }

  private encrypt (id: number): (data: Buffer, key: object) => Promise<Buffer> {
    return (data, _) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.ENCRYPT;
      return Promise.resolve(data);
    };
  }

  private decrypt (id: number): (data: Buffer, key: object) => Promise<Buffer> {
    return (data, _) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.DECRYPT;
      return Promise.resolve(data);
    };
  }

  private sign (id: number): ({}, {}) => Promise<string> {
    return (_, __) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.SIGN;
      return Promise.resolve('');
    };
  }

  private verify (id: number): ({}, {}, {}) => Promise<boolean> {
    return (_, __, ___) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.VERIFY;
      return Promise.resolve(true);
    };
  }

  private symEncrypt (id: number): (plaintext: Buffer, _: Buffer) =>
  Promise<{ciphertext: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer}> {
    return (plaintext: Buffer, _) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.SYMENCRYPT;
      return Promise.resolve({
        ciphertext: plaintext,
        initializationVector: Buffer.alloc(0),
        key: Buffer.alloc(0),
        tag: Buffer.alloc(0)
      });
    };
  }

  private symDecrypt (id: number): (ciphertext: Buffer, additionalAuthenticatedData: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer) =>
  Promise<Buffer> {
    return (ciphertext: Buffer, _, __, ___, ____) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.SYMDECRYPT;
      return Promise.resolve(ciphertext);
    };
  }

  /** Encryption algorithms */
  getEncrypters () {
    return {
      test: {
        encrypt: this.encrypt(this.id),
        decrypt: this.decrypt(this.id)
      }
    };
  }

  /** Signing algorithms */
  getSigners () {
    return {
      test: {
        sign: this.sign(this.id),
        verify: this.verify(this.id)
      }
    };
  }

  getSymmetricEncrypters () {
    return {
      test: {
        encrypt: this.symEncrypt(this.id),
        decrypt: this.symDecrypt(this.id)
      }
    };
  }

  /**
   * Returns true when encrypt() was called since last reset()
   */
  wasEncryptCalled (): boolean {
    return (TestCryptoSuite.called[this.id] & TestCryptoSuite.ENCRYPT) > 0;
  }

  /**
   * Returns true when decrypt() was called since last reset()
   */
  wasDecryptCalled (): boolean {
    return (TestCryptoSuite.called[this.id] & TestCryptoSuite.DECRYPT) > 0;
  }

  /**
   * Returns true when sign() was called since last reset()
   */
  wasSignCalled (): boolean {
    return (TestCryptoSuite.called[this.id] & TestCryptoSuite.SIGN) > 0;
  }

  /**
   * Returns true when verify() was called since last reset()
   */
  wasVerifyCalled (): boolean {
    return (TestCryptoSuite.called[this.id] & TestCryptoSuite.VERIFY) > 0;
  }

  /**
   * Returns true when Symmetric Encrypt was called since last reset()
   */
  wasSymEncryptCalled (): boolean {
    return (TestCryptoSuite.called[this.id] & TestCryptoSuite.SYMENCRYPT) > 0;
  }

  /**
   * Returns true when Symmetric Decrypt was called since last reset()
   */
  wasSymDecryptCalled (): boolean {
    return (TestCryptoSuite.called[this.id] & TestCryptoSuite.SYMDECRYPT) > 0;
  }

  /**
   * Resets visited flags for encrypt, decrypt, sign, and verify
   */
  reset () {
    TestCryptoSuite.called[this.id] = 0;
  }
}
