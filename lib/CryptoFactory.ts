import CryptoSuite, { Encrypter, Signer, PublicKeyConstructors } from './interfaces/CryptoSuite';
import { DidPublicKey } from 'did-common-typescript';
import JweToken from './security/JweToken';
import JwsToken from './security/JwsToken';

/** A dictionary of JWA encryption algorithm names to Encrypter objects */
type EncrypterMap = {[name: string]: Encrypter};
/** A dictionary of JWA signing algorithm names to Signer objects */
type SignerMap = { [name: string]: Signer };

/**
 * Utility class to handle all CryptoSuite dependency injection
 */
export default class CryptoFactory {

  private encrypters: EncrypterMap;
  private signers: SignerMap;

  // the constructors should be factored out as they don't really relate to the pure crypto
  private keyConstructors: PublicKeyConstructors;

  /**
   * Constructs a new CryptoRegistry
   * @param suites The suites to use for dependency injeciton
   */
  constructor (suites: CryptoSuite[]) {
    this.encrypters = {};
    this.signers = {};
    this.keyConstructors = {};

    // takes each suite (CryptoSuite objects) and maps to name of the algorithm.
    suites.forEach((suite) => {
      const encAlgorithms = suite.getEncrypters();
      for (const encrypterKey in encAlgorithms) {
        this.encrypters[encrypterKey] = encAlgorithms[encrypterKey];
      }

      const signerAlgorithms = suite.getSigners();
      for (const signerKey in signerAlgorithms) {
        this.signers[signerKey] = signerAlgorithms[signerKey];
      }

      const pluginKeyConstructors = suite.getKeyConstructors();
      for (const keyType in pluginKeyConstructors) {
        this.keyConstructors[keyType] = pluginKeyConstructors[keyType];
      }
    });
  }

  /**
   * constructs the jwe to be encrypted or decrypted
   * @param content content for the JWE
   */
  constructJwe (content: string | object): JweToken {
    return new JweToken(content, this);
  }

  /**
   * constructs the jws to be signed or verified
   * @param content content for the JWS
   */
  constructJws (content: string | object): JwsToken {
    return new JwsToken(content, this);
  }

  /**
   * given a public key object found on a Did Document, constructs a JWK public key
   * Converts Did Document public keys to {@link PublicKey} implementations, or throws
   * @param key publicKey object from a {@link DidDocument}
   * @returns The same key as a {@link PublicKey}
   */
  constructPublicKey (publicKey: DidPublicKey) {
    return this.keyConstructors[publicKey.type](publicKey);
  }

  /**
   * Gets the Encrypter object given the encryption algorithm's name
   * @param name The name of the algorithm
   * @returns The corresponding Encrypter, if any
   */
  getEncrypter (name: string): Encrypter {
    return this.encrypters[name];
  }

  /**
   * Gets the Signer object given the signing algorithm's name
   * @param name The name of the algorithm
   * @returns The corresponding Signer, if any
   */
  getSigner (name: string): Signer {
    return this.signers[name];
  }
}
