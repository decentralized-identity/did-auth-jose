import PublicKey from '../../lib/security/PublicKey';

/**
 * A public key object used for testing
 */
export class TestPublicKey extends PublicKey {
  /** Its unique identifier */
  uid: number;
  defaultEncryptionAlgorithm = 'test';

  constructor (kid?: string) {
    super();
    this.kty = 'test';
    this.uid = Math.round(Math.random() * Number.MAX_SAFE_INTEGER);
    this.kid = kid !== undefined ? kid : this.uid.toString();
  }
}
