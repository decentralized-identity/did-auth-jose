import PublicKey, { RecommendedKeyType } from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';

/**
 * Represents an Rsa public key
 * @class
 * @extends PublicKey
 */
export default class RsaPublicKey extends PublicKey {
  kty = RecommendedKeyType.Rsa;

  readonly defaultEncryptionAlgorithm: string = 'RSA-OAEP'; // should be -256

  /** Modulus */
  n: string;
  /** Exponent */
  e: string;

  /**
   * A Rsa JWK
   * @param n The Rsa modulus in Base64urlUInt encoding as specified by RFC7518 6.3.1.1
   * @param e The Rsa public exponent in Base64urlUInt encoding as specified by RFC7518 6.3.1.2
   */
  constructor (keyData: IDidDocumentPublicKey) {
    super();
    this.kid = keyData.id;

    const data = keyData as any;

    if ('publicKeyJwk' in data) {
      const jwk = data.publicKeyJwk;
      if (!keyData.id.endsWith(jwk.kid)) {
        throw new Error(`JWK kid '${jwk.kid}' does not match DID public key id '${keyData.id}'.`);
      }
      Object.keys(jwk).forEach((field) => {
        if (field === 'kid') {
          return;
        }
        (this as any)[field] = jwk[field];
      });
      if (!jwk.n || !jwk.e) {
        throw new Error('JWK missing required parameters');
      }

    } else {
      throw new Error('Cannot parse RsaVerificationKey2018');
    }
  }
}
