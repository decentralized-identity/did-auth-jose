import PublicKey from './PublicKey';

/**
 * Represents a Private Key in JWK format.
 * @class
 * @abstract
 * @hideconstructor
 */
export default abstract class PrivateKey extends PublicKey {

  /** Default Sign Algorithm for JWS 'alg' field */
  readonly defaultSignAlgorithm: string = 'none';

  /**
   * Gets the corresponding public key
   * @returns The corresponding {@link PublicKey}
   */
  abstract getPublicKey (): PublicKey;
}
