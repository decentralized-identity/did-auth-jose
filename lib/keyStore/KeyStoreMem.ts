import { ProtectionFormat } from './ProtectionFormat';
import Protect from './Protect';
import PrivateKey from '../security/PrivateKey';
import PublicKey from '../security/PublicKey';
import IKeyStore from './IKeyStore';
import CryptoFactory from '../CryptoFactory';

/**
 * Class defining methods and properties for a light KeyStore
 */
export default class KeyStoreMem implements IKeyStore {
  private store: Map<string, Buffer | PrivateKey | PublicKey> = new Map<string, Buffer | PrivateKey | PublicKey>();

  /**
   * Returns the key associated with the specified
   * key identifier.
   * @param keyReference for which to return the key.
   * @param publicKeyOnly True if only the public key is needed.
   */
  get (keyReference: string, _publicKeyOnly: boolean): Promise<Buffer | PrivateKey | PublicKey> {
    return new Promise((resolve, reject) => {
      if (this.store.has(keyReference)) {
        resolve(this.store.get(keyReference));
      } else {
        reject(`${keyReference} not found`);
      }
    });
  }

  /**
   * Saves the specified key to the key store using
   * the key identifier.
   * @param keyIdentifier for the key being saved.
   * @param key being saved to the key store.
   */
  save (keyIdentifier: string, key: Buffer | PrivateKey | PublicKey): Promise<void> {
    console.log(this.store.toString() + keyIdentifier + key.toString());
    this.store.set(keyIdentifier, key);
    return new Promise((resolve) => {
      resolve();
    });
  }

  /**
   * Sign the data with the key referenced by keyIdentifier.
   * @param keyIdentifier for the key used for signature.
   * @param payload Data to sign
   * @param format used to protect the content
   * @param cryptoFactory used to specify the algorithms to use
   * @param tokenHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.
   * @returns The protected message
   */
  public async protect (keyIdentifier: string,
    payload: string,
    format: ProtectionFormat,
    cryptoFactory: CryptoFactory,
    tokenHeaderParameters?: { [name: string]: string }): Promise<string> {
      // TODO add encryption formats
    return Protect.sign(payload, keyIdentifier, format, this, cryptoFactory, tokenHeaderParameters);
  }
}
