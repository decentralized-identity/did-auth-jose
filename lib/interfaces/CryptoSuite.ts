import PublicKey from '../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
import { PrivateKey } from '..';

/** A dictionary with the did document key type mapping to the public key constructor */
export type PublicKeyConstructors = {[didDocumentKeyType: string]: (keyData: IDidDocumentPublicKey) => PublicKey};

/**
 * Interface for the Crypto Algorithms Plugins
 */
export default interface CryptoSuite {
 /**
  * Gets all of the Encrypter Algorithms from the plugin
  * @returns a dictionary with the name of the algorithm for encryption/decryption as the key
  */
  getEncrypters (): { [algorithm: string]: Encrypter };

 /**
  * Gets all of the Signer Algorithms from the plugin
  * @returns a dictionary with the name of the algorithm for sign and verify as the key
  */
  getSigners (): {[algorithm: string]: Signer };

  /**
   * Gets all of the {@link PublicKey} constructors
   * @returns a dictionary with the did document key type mapping to the public key constructor
   */
  getKeyConstructors (): PublicKeyConstructors;
}

/**
 * Interface for Encryption/Decryption
 */
export interface Encrypter {
  /** Given the data to encrypt and a JWK public key, encrypts the data */
  encrypt (data: Buffer, jwk: PublicKey): Promise<Buffer>;

  /** Given the encrypted data and a jwk private key, decrypts the data */
  decrypt (data: Buffer, jwk: PrivateKey): Promise<Buffer>;
}

/**
 *  Interface for Signing/Signature Verification
 */
export interface Signer {
  /** Given signature input content and a JWK private key, creates and returns a signature as a base64 string */
  sign (content: string, jwk: PrivateKey): Promise<string>;

  /**
   * Given the content used in the original signature input, the signature, and a JWK public key,
   * returns true if the signature is valid, else false
   */
  verify (signedContent: string, signature: string, jwk: PublicKey): Promise<boolean>;
}
