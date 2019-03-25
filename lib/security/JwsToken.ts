import Base64Url from '../utilities/Base64Url';
import JoseToken from './JoseToken';
import PublicKey from '../security/PublicKey';
import { PrivateKey, CryptoFactory } from '..';

/**
 * Definition for a delegate that can verfiy signed data.
 */
type VerifySignatureDelegate = (signedContent: string, signature: string, jwk: PublicKey) => Promise<boolean>;

/**
 * Class for containing JWS token operations.
 * This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.
 */
export default class JwsToken extends JoseToken {

  // used for verification if a JSON Serialized JWS was given
  private readonly signature: string | undefined;

  constructor (content: string | object, protected cryptoFactory: CryptoFactory) {
    super(content, cryptoFactory);
    // check for compact JWS
    if (typeof content === 'string') {
      const parts = content.split('.');
      if (parts.length === 3) {
        this.protectedHeaders = parts[0];
        this.payload = parts[1];
        this.signature = parts[2];
        return;
      }
    }
    // Check for JSON Serialization and reparse content if appropriate
    if (typeof content === 'object') {
      const jsonObject: any = content;
      if ('payload' in jsonObject && typeof jsonObject.payload === 'string') {
        // TODO: General JWS JSON Serialization signatures and one of protected or header for each (Issue #22)
        if ('signature' in jsonObject && typeof jsonObject.signature === 'string') {
          // Flattened JWS JSON Serialization
          if (!('protected' in jsonObject && typeof jsonObject.protected === 'string') &&
            !('header' in jsonObject && typeof jsonObject.header === 'object')) {
            // invalid JWS JSON Serialization
            return;
          }
          // if we've gotten this far, we succeeded can can safely set parameters
          if ('protected' in jsonObject && typeof jsonObject.protected === 'string') {
            this.protectedHeaders = jsonObject.protected;
          }
          if ('header' in jsonObject && typeof jsonObject.header === 'object') {
            this.unprotectedHeaders = jsonObject.header;
          }
          this.payload = jsonObject.payload;
          this.signature = jsonObject.signature;
          return;
        }
      }
    }
  }

  /**
   * Signs contents given at construction using the given private key in JWK format.
   *
   * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
   * @returns Signed payload in compact JWS format.
   */
  public async sign (jwk: PrivateKey, jwsHeaderParameters?: { [name: string]: string }): Promise<string> {
    // Steps according to RTC7515 5.1
    // 2. Compute encoded payload vlaue base64URL(JWS Payload)
    const encodedContent = Base64Url.encode(this.content);
    // 3. Compute the headers
    const headers = jwsHeaderParameters || {};
    headers['alg'] = jwk.defaultSignAlgorithm;
    if (jwk.kid) {
      headers['kid'] = jwk.kid;
    }
    // 4. Compute BASE64URL(UTF8(JWS Header))
    const encodedHeaders = Base64Url.encode(JSON.stringify(headers));
    // 5. Compute the signature using data ASCII(BASE64URL(UTF8(JWS Header))) || . || . BASE64URL(JWS Payload)
    //    using the "alg" signature algorithm.
    const signatureInput = `${encodedHeaders}.${encodedContent}`;
    const signatureBase64 = await (this.cryptoFactory.getSigner(headers['alg'])).sign(signatureInput, jwk);
    // 6. Compute BASE64URL(JWS Signature)
    const encodedSignature = Base64Url.fromBase64(signatureBase64);
    // 7. Only applies to JWS JSON Serializaiton
    // 8. Create the desired output: BASE64URL(UTF8(JWS Header)) || . BASE64URL(JWS payload) || . || BASE64URL(JWS Signature)
    return `${signatureInput}.${encodedSignature}`;
  }

  /**
   * Signs contents given at construction using the given private key in JWK format with additional optional header fields
   * @param jwk Private key used in the signature
   * @param options Additional protected and header fields to include in the JWS
   */
  public async signFlatJson (jwk: PrivateKey,
    options?: {protected?: { [name: string]: string }, header?: { [name: string]: string }}):
    Promise<{protected?: string, header?: {[name: string]: string}, payload: string, signature: string}> {
    // Steps according to RTC7515 5.1
    // 2. Compute encoded payload vlaue base64URL(JWS Payload)
    const encodedContent = Base64Url.encode(this.content);
    // 3. Compute the headers
    const header = (options || {}).header;
    const protectedHeaders = (options || {}).protected || {};
    protectedHeaders['alg'] = jwk.defaultSignAlgorithm;
    protectedHeaders['kid'] = jwk.kid;
    // 4. Compute BASE64URL(UTF8(JWS Header))
    const encodedProtected = Base64Url.encode(JSON.stringify(protectedHeaders));
    // 5. Compute the signature using data ASCII(BASE64URL(UTF8(JWS Header))) || . || . BASE64URL(JWS Payload)
    //    using the "alg" signature algorithm.
    const signatureInput = `${encodedProtected}.${encodedContent}`;
    const signature = await (this.cryptoFactory.getSigner(protectedHeaders['alg'])).sign(signatureInput, jwk);
    // 6. Compute BASE64URL(JWS Signature)
    const encodedSignature = Base64Url.fromBase64(signature);
    // 8. Create the desired output: BASE64URL(UTF8(JWS Header)) || . BASE64URL(JWS payload) || . || BASE64URL(JWS Signature)
    return {
      protected: encodedProtected,
      header,
      payload: encodedContent,
      signature: encodedSignature
    };
  }

  /**
   * Verifies the JWS using the given key in JWK object format.
   *
   * @returns The payload if signature is verified. Throws exception otherwise.
   */
  public async verifySignature (jwk: PublicKey): Promise<string> {
    // ensure we have everything we need
    if (this.payload === undefined || this.signature === undefined) {
      throw new Error('Could not parse contents into a JWS');
    }
    const algorithm = this.getHeader().alg;
    const signer = this.cryptoFactory.getSigner(algorithm);

    // Get the correct signature verification function based on the given algorithm.
    let verify: VerifySignatureDelegate;
    if (signer) {
      verify = signer.verify;
    } else {
      const err = new Error(`Unsupported signing algorithm: ${algorithm}`);
      throw err;
    }

    const signedContent = `${this.protectedHeaders || ''}.${this.payload}`;
    const passedSignatureValidation = await verify(signedContent, this.signature, jwk);

    if (!passedSignatureValidation) {
      const err = new Error('Failed signature validation');
      throw err;
    }

    const verifiedData = Base64Url.decode(this.payload);
    return verifiedData;
  }

  /**
   * Gets the base64 URL decrypted payload.
   */
  public getPayload (): any {
    if (this.payload) {
      return Base64Url.decode(this.payload);
    }
    return this.content;
  }

  /**
   * Gets the header as a JS object.
   */
  public getHeader (): any {
    let headers = this.unprotectedHeaders;
    if (!headers) {
      headers = {};
    }
    if (this.protectedHeaders) {
      const jsonString = Base64Url.decode(this.protectedHeaders);
      const protect = JSON.parse(jsonString) as {[key: string]: any};
      headers = Object.assign(headers, protect);
    }
    return headers;
  }

}
