
import JwsToken, { FlatJsonJws } from '../security/JwsToken';
import CryptoFactory from '../CryptoFactory';
import IKeyStore from './IKeyStore';
import { ProtectionFormat } from './ProtectionFormat';
import PrivateKey from '../security/PrivateKey';

 /**
  * Class to model protection mechanisms
  */
export default class Protect {
  /**
   * Sign the payload
   * @param keyStorageReference used to reference the signing key
   * @param payload to sign
   * @param format Signature format
   * @param keyStore where to retrieve the signing key
   * @param cryptoFactory used to specify the algorithms to use
   * @param tokenHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.
   */
  public static async sign (
    keyStorageReference: string,
    payload: string,
    format: ProtectionFormat,
    keyStore: IKeyStore,
    cryptoFactory: CryptoFactory,
    tokenHeaderParameters?: { [name: string]: string }
  ): Promise<string> {
    const token = new JwsToken(payload, cryptoFactory);
    // Get the key
    const jwk: any = await keyStore.get(keyStorageReference, false)
    .catch((err) => {
      throw new Error(`The key referenced by '${keyStorageReference}' is not available: '${err}'`);
    });

    switch (jwk.kty.toUpperCase()) {
      case 'RSA':
        jwk.defaultSignAlgorithm = 'RS256';
        break;

      case 'EC':
        jwk.defaultSignAlgorithm = 'ES256K';
        break;

      default:
        throw new Error(`The key type '${jwk.kty}' is not supported.`);
    }

    switch (format) {
      case ProtectionFormat.CompactJsonJws:
        return token.sign(jwk, tokenHeaderParameters);

      case ProtectionFormat.FlatJsonJws:
        const flatSignature: FlatJsonJws = await token.signAsFlattenedJson(jwk, tokenHeaderParameters);
        return JSON.stringify(flatSignature);
      default:
        throw new Error(`Non signature format passed: ${format.toString()}`);
    }
  }

  /**
   * Decrypt the data with the key referenced by keyReference.
   * @param keyStorageReference Reference to the key used for signature.
   * @param cipher Data to decrypt
   * @param format Protection format used to decrypt the data
   * @param keyStore where to retrieve the signing key
   * @param cryptoFactory used to specify the algorithms to use
   * @returns The plain text message
   */
  public static async decrypt (keyStorageReference: string, cipher: string,
    format: ProtectionFormat, keyStore: IKeyStore, cryptoFactory: CryptoFactory): Promise<string> {
    if (format !== ProtectionFormat.CompactJsonJwe && format !== ProtectionFormat.FlatJsonJwe) {
      throw new Error(`Only CompactJsonJwe, FlatJsonJwe is supported by decryption`);
    }
    // Get the key
    const jwk: PrivateKey = await (keyStore.get(keyStorageReference, false) as Promise<PrivateKey>)
    .catch((err) => {
      throw new Error(`The key referenced by '${keyStorageReference}' is not available: '${err}'`);
    });

    const jweToken = cryptoFactory.constructJwe(cipher);
    const payload = await jweToken.decrypt(jwk);
    return payload;
  }
}
