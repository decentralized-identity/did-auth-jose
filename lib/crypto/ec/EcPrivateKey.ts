import EcPublicKey from './EcPublicKey';
import PrivateKey from '../../security/PrivateKey';
import PublicKey, { KeyOperation } from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';

const ecKey = require('ec-key');

/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
export default class EcPrivateKey extends EcPublicKey implements PrivateKey {
  /** ECDSA w/ secp256k1 Curve */
  readonly defaultSignAlgorithm: string = 'ES256K';

  /** Private exponent */
  public d: string;

  /**
   * Constructs a private key given a DID Document public key descriptor containing additional private key
   * information.
   *
   * TODO: This feels odd, should define a separate type.
   *
   * @param key public key object with additional private key information
   */
  constructor (key: IDidDocumentPublicKey) {
    super(key);
    let data = (key as any).publicKeyJwk;
    if (!('d' in data)) {
      throw new Error('d required for private elliptic curve key.');
    }
    this.kid = data.kid;
    this.d = data.d;
    this.use = data.use;
  }

  /**
   * Wraps a EC private key in jwk format into a Did Document public key object with additonal information
   * @param kid Key ID
   * @param jwk JWK of the private key
   */
  static wrapJwk (kid: string, jwk: any): EcPrivateKey {
    return new EcPrivateKey({
      id: kid,
      type: 'EdDsaSAPublicKeySecp256k1',
      publicKeyJwk: jwk
    } as IDidDocumentPublicKey);
  }

  /**
   * Generates a new private key
   * @param kid Key ID
   */
  static async generatePrivateKey (kid: string): Promise<EcPrivateKey> {
    const key = ecKey.createECKey('P-256K');

    // Add the additional JWK parameters
    const jwk = Object.assign(key.toJSON(), {
      kid: kid,
      alg: 'ES256K',
      key_ops: [KeyOperation.Sign, KeyOperation.Verify]
    });

    return EcPrivateKey.wrapJwk(kid, jwk);
  }

  /** Gets the corresponding public key */
  getPublicKey (): PublicKey {
    return {
      kty: this.kty,
      kid: this.kid,
      crv: this.crv,
      x: this.x,
      y: this.y,
      use: this.use,
      defaultEncryptionAlgorithm: 'ECIES'
    } as EcPublicKey;
  }
}
