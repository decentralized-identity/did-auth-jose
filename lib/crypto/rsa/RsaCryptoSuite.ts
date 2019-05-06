import RsaPublicKey from './RsaPublicKey';
import CryptoSuite, { SymmetricEncrypter } from '../../interfaces/CryptoSuite';
import { IDidDocumentPublicKey } from '@decentralized-identity/did-common-typescript';
// TODO: Create and reference TypeScript definition file for 'jwk-to-pem'
const jwkToPem = require('jwk-to-pem');
import * as crypto from 'crypto';
import * as constants from 'constants';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';

/**
 * Encrypter plugin for RsaSignature2018
 */
export class RsaCryptoSuite implements CryptoSuite {

  getSymmetricEncrypters (): { [algorithm: string]: SymmetricEncrypter } {
    return {};
  }

  /** Encryption algorithms */
  getEncrypters () {
    return {
      'RSA-OAEP': {
        encrypt: RsaCryptoSuite.encryptRsaOaep,
        decrypt: RsaCryptoSuite.decryptRsaOaep
      }
    };
  }

  /** Signing algorithms */
  getSigners () {
    return {
      RS256: {
        sign: RsaCryptoSuite.signRs256,
        verify: RsaCryptoSuite.verifySignatureRs256
      },
      RS512: {
        sign: RsaCryptoSuite.signRs512,
        verify: RsaCryptoSuite.verifySignatureRs512
      }
    };
  }

  getKeyConstructors () {
    return {
      RsaVerificationKey2018: (keyData: IDidDocumentPublicKey) => { return new RsaPublicKey(keyData); }
    };
  }

  /**
   * Verifies the given signed content using RS256 algorithm.
   *
   * @returns true if passed signature verification, false otherwise.
   */
  public static verifySignatureRs256 (signedContent: string, signature: string, jwk: PublicKey): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const publicKey = jwkToPem(jwk);
      const verifier = crypto.createVerify('RSA-SHA256');
      verifier.write(signedContent);

      const passedVerification = verifier.verify(publicKey, signature, 'base64');
      resolve(passedVerification);
    });
  }

  /**
   * Sign the given content using the given private key in JWK format using algorithm RS256.
   * TODO: rewrite to get rid of node-jose dependency.
   *
   * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
   * @returns Signed payload in compact JWS format.
   */
  public static async signRs256 (content: string, jwk: PrivateKey): Promise<string> {
    const privateKey = jwkToPem(jwk, { private: true });
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(content);
    return signer.sign(privateKey, 'base64');
  }

  /**
   * Verifies the given signed content using RS512 algorithm.
   *
   * @returns true if passed signature verification, false otherwise.
   */
  public static verifySignatureRs512 (signedContent: string, signature: string, jwk: PublicKey): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const publicKey = jwkToPem(jwk);
      const verifier = crypto.createVerify('RSA-SHA512');
      verifier.write(signedContent);

      const passedVerification = verifier.verify(publicKey, signature, 'base64');
      resolve(passedVerification);
    });
  }

  /**
   * Sign the given content using the given private key in JWK format using algorithm RS512.
   * TODO: rewrite to get rid of node-jose dependency.
   *
   * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
   * @returns Signed payload in compact JWS format.
   */
  public static async signRs512 (content: string, jwk: PrivateKey): Promise<string> {
    const privateKey = jwkToPem(jwk, { private: true });
    const signer = crypto.createSign('RSA-SHA512');
    signer.update(content);
    return signer.sign(privateKey, 'base64');
  }

  /**
   * Rsa-OAEP encrypts the given data using the given public key in JWK format.
   */
  public static encryptRsaOaep (data: Buffer, jwk: PublicKey): Promise<Buffer> {
    return new Promise<Buffer>((resolve) => {
      const publicKey = jwkToPem(jwk);
      const encryptedDataBuffer = crypto.publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING }, data);

      resolve(encryptedDataBuffer);
    });
  }

  /**
   * Rsa-OAEP decrypts the given data using the given private key in JWK format.
   * TODO: correctly implement this after getting rid of node-jose dependency.
   */
  public static decryptRsaOaep (data: Buffer, jwk: PrivateKey): Promise<Buffer> {
    return new Promise<Buffer>((resolve) => {
      const privateKey = jwkToPem(jwk, { private: true });
      const decryptedDataBuffer = crypto.privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING }, data);

      resolve(decryptedDataBuffer);
    });
  }
}
