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

  getKeyConstructors () {
    return {
      test: () => { return new TestPublicKey(); }
    };
  }

  constructor () {
    this.id = Math.round(Math.random() * Number.MAX_SAFE_INTEGER);
  }

  private encrypt (id: number): (data: Buffer, key: object) => Buffer {
    return (data, _) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.ENCRYPT;
      return data;
    };
  }

  private decrypt (id: number): (data: Buffer, key: object) => Buffer {
    return (data, _) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.DECRYPT;
      return data;
    };
  }

  private sign (id: number): ({}, {}) => Promise<string> {
    return (_, __) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.SIGN;
      return Promise.resolve('');
    };
  }

  private verify (id: number): ({}, {}, {}) => boolean {
    return (_, __, ___) => {
      TestCryptoSuite.called[id] |= TestCryptoSuite.VERIFY;
      return false;
    };
  }

  getEncrypters () {
    return {
      test: {
        encrypt: this.encrypt(this.id),
        decrypt: this.decrypt(this.id)
      }
    };
  }

  getSigners () {
    return {
      test: {
        sign: this.sign(this.id),
        verify: this.verify(this.id)
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
   * Resets visited flags for encrypt, decrypt, sign, and verify
   */
  reset () {
    TestCryptoSuite.called[this.id] = 0;
  }
}
