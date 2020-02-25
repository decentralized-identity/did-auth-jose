import EcPublicKey from './EcPublicKey';
import CryptoSuite, { SymmetricEncrypter } from '../../interfaces/CryptoSuite';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
import { EcPrivateKey } from '../..';
import * as crypto from 'crypto';

const secp256k1 = require('secp256k1');
const keyto = require('@trust/keyto');

/**
 * Encrypter plugin for Elliptic Curve P-256K1
 */
export class Secp256k1CryptoSuite implements CryptoSuite {

  /** Symmetric key encrypters */
  getSymmetricEncrypters (): { [algorithm: string]: SymmetricEncrypter } {
    return {};
  }

  /** Encryption with Secp256k1 keys not supported */
  getEncrypters () {
    return {};
  }

  /** Signing algorithms */
  getSigners () {
    return {
      ES256K: {
        sign: Secp256k1CryptoSuite.sign,
        verify: Secp256k1CryptoSuite.verify
      }
    };
  }

  /**
   * Defines constructors for the identifiers proposed in Linked Data Cryptographic Suite Registry
   * https://w3c-ccg.github.io/ld-cryptosuite-registry/#eddsasasignaturesecp256k1 plus the additional
   * ones spotted in the wild.
   */
  getKeyConstructors () {
    return {
      Secp256k1VerificationKey2018: (keyData: IDidDocumentPublicKey) => { return new EcPublicKey(keyData); },
      EdDsaSAPublicKeySecp256k1: (keyData: IDidDocumentPublicKey) => { return new EcPublicKey(keyData); },
      EdDsaSASignatureSecp256k1: (keyData: IDidDocumentPublicKey) => { return new EcPublicKey(keyData); },
      EcdsaPublicKeySecp256k1: (keyData: IDidDocumentPublicKey) => { return new EcPublicKey(keyData); }
    };
  }

  /**
   * Verifies the given signed content using SHA256 algorithm.
   *
   * @returns true if passed signature verification, false otherwise.
   */
  public static async verify (
    signedContent: string,
    signature: string,
    jwk: PublicKey
  ): Promise<boolean> {
    let rawJwk: EcPublicKey = jwk as EcPublicKey;
    rawJwk.crv = 'K-256';
    let pubJwk = keyto.from(rawJwk, 'jwk').toString('blk', 'public');

    const sha256 = crypto.createHash('sha256');
    sha256.update(signedContent);
    const dataHash = sha256.digest('hex');
    try {
      const passedVerification: boolean = secp256k1.verify(
          Buffer.from(dataHash, 'hex'), Buffer.from(signature, 'hex'),
          Buffer.from(pubJwk, 'hex'));

      return passedVerification;
    } catch (e) {
      return false;
    }
  }

  /**
   * Sign the given content using the given private key in JWK format using algorithm SHA256.
   *
   * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
   * @returns Signed payload in compact JWS format.
   */
  public static async sign (content: string, jwk: PrivateKey): Promise<string> {
    let rawJwk: EcPrivateKey = jwk as EcPrivateKey;
    rawJwk.crv = 'K-256';
    let priJwk = keyto.from(rawJwk, 'jwk').toString('blk', 'private');
    let priKey = Buffer.from(priJwk, 'hex');

    const sha256 = crypto.createHash('sha256');
    sha256.update(content);
    const dataHash = sha256.digest('hex');

    let sigObj = secp256k1.sign(Buffer.from(dataHash, 'hex'), priKey);
    return sigObj.signature.toString('hex');
  }
}
