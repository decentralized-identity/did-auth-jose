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
  public abstract getHeader (): any;
}
