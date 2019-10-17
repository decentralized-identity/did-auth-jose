import EcPublicKey from './EcPublicKey';
import CryptoSuite, { SymmetricEncrypter } from '../../interfaces/CryptoSuite';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
import { EcPrivateKey } from '../..';

const ecKey = require('ec-key');
const keyto = require('@trust/keyto')
const ecies = require("ecies-parity");
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
    const ecies = {
        encrypt: Secp256k1CryptoSuite.encryptSecp256k1,
        decrypt: Secp256k1CryptoSuite.decryptSecp256k1
      };
    return {
        'ECIES': ecies
    };  
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
    let rawJwk: EcPublicKey = <EcPublicKey>jwk;
    if (rawJwk.crv === 'K-256') {
      rawJwk.crv = 'P-256K';
    }
    const publicKey = new ecKey(jwk);
    const passedVerification: boolean = publicKey.createVerify('SHA256')
                                         .update(signedContent)
                                         .verify(signature, 'base64');

    return passedVerification;
  }

  /**
   * Sign the given content using the given private key in JWK format using algorithm SHA256.
   *
   * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
   * @returns Signed payload in compact JWS format.
   */
  public static async sign (content: string, jwk: PrivateKey): Promise<string> {
    let rawJwk: EcPrivateKey = <EcPrivateKey>jwk;
    if (rawJwk.crv === 'K-256') {
      rawJwk.crv = 'P-256K';
    }
    const privateKey = new ecKey(jwk);
    return privateKey.createSign('SHA256')
                       .update(content)
                       .sign('base64');
  }


  public static encryptSecp256k1 (data: Buffer, jwk: PublicKey): Promise<Buffer> {
    return new Promise<Buffer>((resolve) => {
      let rawJwk: EcPublicKey = <EcPublicKey>jwk;
      rawJwk.crv = 'K-256';
      let pubJwk = keyto.from(rawJwk, 'jwk').toString('blk', 'public');
      let pubKey = Buffer.from(pubJwk, 'hex');

      ecies.encrypt(pubKey, data).then(function(encryptedDataBuffer) {
        resolve(encryptedDataBuffer);
      });
    });
  }

  public static decryptSecp256k1 (data: Buffer, jwk: PrivateKey): Promise<Buffer> {
    return new Promise<Buffer>((resolve) => {
      let rawJwk:EcPrivateKey = <EcPrivateKey>jwk;
      rawJwk.crv = 'K-256';
      let priJwk = keyto.from(rawJwk, 'jwk').toString('blk', 'private');
      let priKey = Buffer.from(priJwk, 'hex');

      ecies.decrypt(priKey, data).then(function(decryptedDataBuffer) {
        resolve(decryptedDataBuffer);
      });    
    });
  }
}
