import Base64Url from '../utilities/Base64Url';
import CryptoFactory from '../CryptoFactory';

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
  public getHeader (): any {
    let [headerBase64Url] = this.content.split('.');
    if (!headerBase64Url) {
      return;
    }
    const jsonString = Base64Url.decode(headerBase64Url);

    return JSON.parse(jsonString);
  }
}
