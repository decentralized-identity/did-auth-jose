import Base64Url from '../utilities/Base64Url';
import JoseToken from './JoseToken';
import PublicKey from '../security/PublicKey';
import { PrivateKey } from '..';

// TODO: Rewrite sign() to allow additional cryptographic algorithms to be added easily then remove dependency on 'node-jose'.
const jose = require('node-jose');

/**
 * Definition for a delegate that can verfiy signed data.
 */
type VerifySignatureDelegate = (signedContent: string, signature: string, jwk: PublicKey) => boolean;

/**
 * Class for containing JWS token operations.
 * This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.
 */
export default class JwsToken extends JoseToken {
  /**
   * Sign the given content using the given private key in JWK format.
   *
   * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
   * @returns Signed payload in compact JWS format.
   */
  public async sign (jwk: PrivateKey, jwsHeaderParameters?: { [name: string]: string }): Promise<string> {
    const contentBuffer = Buffer.from(this.content);
    const headers = jwsHeaderParameters || {};
    const contentJwsString = await jose.JWS.createSign({ format: 'compact', fields: headers }, jwk).update(contentBuffer).final();

    return contentJwsString;
  }

  /**
   * Verifies the given JWS compact serialized string using the given key in JWK object format.
   *
   * @returns The payload if signature is verified. Throws exception otherwise.
   */
  public verifySignature (jwk: PublicKey): string {
    const algorithm = this.getHeader().alg;
    const signer = this.cryptoFactory.getSigner(algorithm);

    // Get the correct signature verification function based on the given algorithm.
    let verifySignature: VerifySignatureDelegate;
    if (signer) {
      verifySignature = signer.verify;
    } else {
      const err = new Error(`Unsupported signing algorithm: ${algorithm}`);
      throw err;
    }

    const signedContent = this.getSignedContent();
    const signature = this.getSignature();
    const passedSignatureValidation = verifySignature(signedContent, signature, jwk);

    if (!passedSignatureValidation) {
      const err = new Error('Failed signature validation');
      throw err;
    }

    const verifiedData = this.getPayload();
    return verifiedData;
  }

  /**
   * Gets the signed content (i.e. '<header>.<payload>').
   */
  private getSignedContent (): string {
    const signedContentLength = this.content.lastIndexOf('.');
    const signedContent = this.content.substr(0, signedContentLength);

    return signedContent;
  }

  /**
   * Gets the base64 URL decrypted payload.
   */
  public getPayload (): any {
    const payloadStartIndex = this.content.indexOf('.') + 1;
    const payloadExclusiveEndIndex = this.content.lastIndexOf('.');
    const payload = this.content.substring(payloadStartIndex, payloadExclusiveEndIndex);

    return Base64Url.decode(payload);
  }

  /**
   * Gets the signature string.
   */
  private getSignature (): string {
    const signatureStartIndex = this.content.lastIndexOf('.') + 1;
    const signature = this.content.substr(signatureStartIndex);

    return signature;
  }

}
