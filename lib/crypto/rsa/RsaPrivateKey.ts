import RsaPublicKey from './RsaPublicKey';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';

const jose = require('node-jose');
const keystore = jose.JWK.createKeyStore();

/* tslint:disable:completed-docs */
/**
 * Represents Other primes info (RFC7518 6.3.2.7)
 */
type OtherPrime = {
  r: string,
  d: string,
  t: string
};
/* tslint:enable:completed-docs */

/**
 * Represents an Rsa private key
 * @class
 * @extends PrivateKey
 */
export default class RsaPrivateKey extends RsaPublicKey implements PrivateKey {

  /** the 'alg' parameter */
  readonly defaultSignAlgorithm: string = 'RS256';

  /** Private exponent as specified by RFC7518 6.3.2.1 */
  public d: string;

  /** First prime factor as specified by RFC7518 6.3.2.2 */
  public p?: string;

  /** Second prime factor as specified by RFC7518 6.3.2.3 */
  public q?: string;

  /** First factor CRT exponent as specified by RFC7518 6.3.2.4 */
  public dp?: string;

  /** Second factor CRT exponent as specified by RFC7518 6.3.2.5 */
  public dq?: string;

  /** First CRT coefficent as specified by RFC7518 6.3.2.6 */
  public qi?: string;

  /** Other primes info as specified by RFC7518 6.3.2.7 */
  public oth?: OtherPrime[];

  /**
   * Constructs a private key given a Did Document public key object containing additional private key
   * information
   * @param key public key object with additional private key information
   */
  constructor (key: IDidDocumentPublicKey) {
    super(key);
    if (!('publicKeyJwk' in key)) {
      throw new Error('publicKeyJwk must exist on IDidDocumentPublicKey');
    }
    let data = (key as any).publicKeyJwk;
    if (!('d' in data)) {
      throw new Error('d required for private rsa key');
    }
    this.d = data.d;
    this.p = data.p;
    this.q = data.q;
    this.dp = data.dp;
    this.dq = data.dq;
    this.qi = data.qi;
    this.oth = data.oth;
  }

  /**
   * Wraps a rsa private key in jwk format into a Did Document public key object with additonal information
   * @param kid Key ID
   * @param jwk JWK of the private key
   */
  static wrapJwk (kid: string, jwk: any): RsaPrivateKey {
    return new RsaPrivateKey({
      id: kid,
      type: 'RsaVerificationKey2018',
      publicKeyJwk: jwk
    } as IDidDocumentPublicKey);
  }

  /**
   * Generates a new private key
   * @param kid Key ID
   */
  static async generatePrivateKey (kid: string): Promise<RsaPrivateKey> {
    const additionalProperties = {
      defaultEncryptionAlgorithm: 'RSA-OAEP',
      defaultSignAlgorithm: 'RS256',
      kid: kid
    };
    const keygen = await keystore.generate('RSA', 2048, additionalProperties);
    return RsaPrivateKey.wrapJwk(kid, keygen.toJSON(true));
  }

  /** Gets the public key */
  getPublicKey (): PublicKey {
    return {
      kty: this.kty,
      kid: this.kid,
      e: this.e,
      n: this.n,
      use: this.use,
      defaultEncryptionAlgorithm: this.defaultEncryptionAlgorithm
    } as RsaPublicKey;
  }
}
