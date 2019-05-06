
import { ProtectionFormat } from './ProtectionFormat';
import PrivateKey from '../security/PrivateKey';
import PublicKey from '../security/PublicKey';
import CryptoFactory from '../CryptoFactory';

/**
 * Interface defining methods and properties to
 * be implemented by specific key stores.
 */
export default interface IKeyStore {
  /**
   * Returns the key associated with the specified
   * key reference.
   * @param keyIdentifier for which to return the key.
   * @param publicKeyOnly True if only the public key is needed.
   */
  get (keyReference: string, publicKeyOnly: boolean): Promise<Buffer | PrivateKey | PublicKey>;

  /**
   * Saves the specified key to the key store using
   * the key reference.
   * @param keyReference Reference for the key being saved.
   * @param key being saved to the key store.
   */
  save (keyReference: string, key: Buffer | PrivateKey): Promise<void>;

  /**
   * Lists all key references with their corresponding key ids
   */
  list (): Promise<{ [name: string]: string }>;

  /**
   * Sign the data with the key referenced by keyReference.
   * @param keyReference Reference to the key used for signature.
   * @param data Data to sign
   * @param format Protection format used to sign data
   * @param cryptoFactory used to specify the algorithms to use
   * @param tokenHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.
   * @returns The protected message
   */
  sign (keyReference: string,
    data: string, format: ProtectionFormat, cryptoFactory: CryptoFactory, tokenHeaderParameters?: { [name: string]: string }): Promise<string>;

  /**
   * Decrypt the data with the key referenced by keyReference.
   * @param keyReference Reference to the key used for signature.
   * @param cipher Data to decrypt
   * @param format Protection format used to decrypt the data
   * @param cryptoFactory used to specify the algorithms to use
   * @returns The plain text message
   */
  decrypt (keyReference: string, cipher: string, format: ProtectionFormat, cryptoFactory: CryptoFactory): Promise<string>;
}
