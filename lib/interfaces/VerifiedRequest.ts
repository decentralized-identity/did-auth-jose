import PublicKey from '../security/PublicKey';

/**
 * Verified and decrypted JOSE request
 * @interface
 */
export default interface VerifiedRequest {
  /** Fully qualified key id of the local key */
  readonly localKeyId: string;
  /** Requesters PublicKey used for signature */
  readonly requesterPublicKey: PublicKey;
  /** Requesters PublicKeys */
  readonly requesterPublicKeys: PublicKey[];
  /** Request Nonce */
  readonly nonce: string;
  /** Plaintext of the request */
  request: string;
}
