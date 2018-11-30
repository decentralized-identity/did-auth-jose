import EcPublicKey from './EcPublicKey';
import CryptoSuite from '../../interfaces/CryptoSuite';
import PrivateKey from '../../security/PrivateKey';
import PublicKey from '../../security/PublicKey';
import { DidPublicKey } from '@decentralized-identity/did-common-typescript';

const ecKey = require('ec-key');

/**
 * Encrypter plugin for Elliptic Curve P-256K1
 */
export class Secp256k1CryptoSuite implements CryptoSuite {
  /** Encryption with Secp256k1 keys not supported */
  getEncrypters () {
    return {};
  }

  getSigners () {
    return {
      P256K: {
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
      Secp256k1VerificationKey2018: (keyData: DidPublicKey) => { return new EcPublicKey(keyData); },
      EdDsaSAPublicKeySecp256k1: (keyData: DidPublicKey) => { return new EcPublicKey(keyData); },
      EdDsaSASignatureSecp256k1: (keyData: DidPublicKey) => { return new EcPublicKey(keyData); },
      EcdsaPublicKeySecp256k1: (keyData: DidPublicKey) => { return new EcPublicKey(keyData); }
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
    const privateKey = new ecKey(jwk);
    return privateKey.createSign('SHA256')
                       .update(content)
                       .sign('base64');
  }
}
