import Base64Url from '../utilities/Base64Url';
import JoseToken from './JoseToken';
import PublicKey from '../security/PublicKey';
import { PrivateKey, CryptoFactory } from '..';

/**
 * Definition for a delegate that can verfiy signed data.
 */
type VerifySignatureDelegate = (signedContent: string, signature: string, jwk: PublicKey) => Promise<boolean>;

/**
 * JWS in flattened json format
 */
export type FlatJsonJws = {
  /** The protected (signed) header. */
  protected?: string,
  /** The unprotected (unverified) header. */
  header?: {[name: string]: string},
  /** The application-specific payload. */
  payload: string,
  /** The JWS signature. */
  signature: string
};

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
    let jsonObject: any = content;
    if (typeof content === 'string') {
      const parts = content.split('.');
      if (parts.length === 3) {
        this.protectedHeaders = parts[0];
        this.payload = parts[1];
        this.signature = parts[2];
        return;
      }
      // attempt to parse the string into a JSON object in the event it is a JSON serialized token
      try {
        jsonObject = JSON.parse(content);
      } catch (error) {
        // it was not.
      }
    }
    // Check for JSON Serialization and reparse content if appropriate
    if (typeof jsonObject === 'object') {
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
    // add required fields if missing
    if (!('alg' in headers)) {
      headers['alg'] = jwk.defaultSignAlgorithm;
    }
    if (jwk.kid && !('kid' in headers)) {
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
  public async signAsFlattenedJson (jwk: PrivateKey,
    options?: {protected?: { [name: string]: string }, header?: { [name: string]: string }}):
    Promise<FlatJsonJws> {
    // Steps according to RTC7515 5.1
    // 2. Compute encoded payload vlaue base64URL(JWS Payload)
    const encodedContent = Base64Url.encode(this.content);
    // 3. Compute the headers
    const header = (options || {}).header;
    const protectedHeaders = (options || {}).protected || {};
    // add required fields if missing
    if (!(header && 'alg' in header) && !('alg' in protectedHeaders)) {
      protectedHeaders['alg'] = jwk.defaultSignAlgorithm;
    }
    if (jwk.kid && !(header && 'kid' in header) && !('kid' in protectedHeaders)) {
      protectedHeaders['kid'] = jwk.kid;
    }
    const alg = protectedHeaders.alg || header!.alg;
    let protectedUsed = Object.keys(protectedHeaders).length > 0;
    // 4. Compute BASE64URL(UTF8(JWS Header))
    const encodedProtected = !protectedUsed ? '' : Base64Url.encode(JSON.stringify(protectedHeaders));
    // 5. Compute the signature using data ASCII(BASE64URL(UTF8(JWS Header))) || . || . BASE64URL(JWS Payload)
    //    using the "alg" signature algorithm.
    const signatureInput = `${encodedProtected}.${encodedContent}`;
    const signature = await (this.cryptoFactory.getSigner(alg)).sign(signatureInput, jwk);
    // 6. Compute BASE64URL(JWS Signature)
    const encodedSignature = Base64Url.fromBase64(signature);
    // 8. Create the desired output: BASE64URL(UTF8(JWS Header)) || . BASE64URL(JWS payload) || . || BASE64URL(JWS Signature)
    const jws: FlatJsonJws = {
      header,
      payload: encodedContent,
      signature: encodedSignature
    };
    if (protectedUsed) {
      jws.protected = encodedProtected;
    }
    return jws;
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
   * Converts the JWS from the constructed type into a Compact JWS
   */
  public toCompactJws (): string {
    if (this.payload === undefined || this.signature === undefined) {
      throw new Error('Could not parse contents into a JWS');
    }
    if (!('alg' in this.getProtectedHeader())) {
      throw new Error("'alg' is required to be in the protected header");
    }
    return `${this.protectedHeaders}.${this.payload}.${this.signature}`;
  }

  /**
   * Converts the JWS from the constructed type into a Flat JSON JWS
   * @param headers unprotected headers to use
   */
  public toFlattenedJsonJws (headers?: {[member: string]: any}): FlatJsonJws {
    if (this.payload === undefined || this.signature === undefined) {
      throw new Error('Could not parse contents into a JWS');
    }
    const unprotectedHeaders = headers || this.unprotectedHeaders || undefined;
    const protectedHeaders = this.getProtectedHeader();
    // TODO: verify no header parameters in unprotected headers conflict with protected headers
    if (!('alg' in protectedHeaders) &&
        !(unprotectedHeaders && ('alg' in unprotectedHeaders))) {
      throw new Error("'alg' is required to be in the header or protected header");
    }
    let jws = {
      payload: this.payload,
      signature: this.signature
    };
    if (this.protectedHeaders) {
      jws = Object.assign(jws, { protected: this.protectedHeaders });
    }
    if (unprotectedHeaders) {
      jws = Object.assign(jws, { header: unprotectedHeaders });
    }
    return jws;
  }
}
