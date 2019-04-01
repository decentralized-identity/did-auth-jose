import CryptoFactory from '../CryptoFactory';
import Base64Url from '../utilities/Base64Url';

/**
 * Base class for containing common operations for JWE and JWS tokens.
 * Not intended for creating instances of this class directly.
 */
export default abstract class JoseToken {
  /**
   * Content of the token
   */
  protected content: string;

  /**
   * Protected headers (base64url encoded)
   */
  protected protectedHeaders: string | undefined;
  /**
   * Unprotected headers
   */
  protected unprotectedHeaders: {[member: string]: any} | undefined;
  /**
   * Payload (base64url encoded)
   */
  protected payload: string | undefined;
  /**
   * Constructor for JoseToken that takes in a compact-serialized token string.
   */
  public constructor (content: string | object, protected cryptoFactory: CryptoFactory) {
    if (typeof content === 'string') {
      this.content = content;
    } else {
      this.content = JSON.stringify(content);
    }
  }

  /**
   * Gets the header as a JS object.
   */
  public getHeader (): {[member: string]: any} {
    let headers = this.unprotectedHeaders;
    if (!headers) {
      headers = {};
    }
    if (this.protectedHeaders) {
      headers = Object.assign(headers, this.getProtectedHeader());
    }
    return headers;
  }

  /**
   * Gets the protected headers as a JS object.
   */
  public getProtectedHeader (): {[member: string]: any} {
    if (this.protectedHeaders) {
      const jsonString = Base64Url.decode(this.protectedHeaders);
      return JSON.parse(jsonString) as {[key: string]: any};
    }
    return {};
  }

  /**
   * Returns true if and only if the content was parsed as a token
   */
  public isContentWellFormedToken (): boolean {
    return this.payload !== undefined;
  }
}
