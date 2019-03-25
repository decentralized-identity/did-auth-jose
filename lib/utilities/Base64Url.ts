/**
 * Class for performing various Base64 URL operations.
 */
export default class Base64Url {

  /**
   * Encodes the input string or Buffer into a Base64URL string.
   */
  public static encode (input: string | Buffer, encoding: string = 'utf8'): string {
    let inputBuffer;
    if (Buffer.isBuffer(input)) {
      inputBuffer = input;
    } else {
      inputBuffer = Buffer.from(input, encoding);
    }

    const base64String = inputBuffer.toString('base64');
    return Base64Url.fromBase64(base64String);
  }

  /**
   * Decodes a Base64URL string.
   */
  public static decode (base64urlString: string, encoding: string = 'utf8'): string {
    return Base64Url.decodeToBuffer(base64urlString).toString(encoding);
  }

  /**
   * Decodes a Base64URL string
   */
  public static decodeToBuffer (base64urlString: string): Buffer {
    const base64String = Base64Url.toBase64(base64urlString);
    return Buffer.from(base64String, 'base64');
  }

  /**
   * Converts a Base64URL string to a Base64 string.
   * TODO: Improve implementation perf.
   */
  static toBase64 (base64UrlString: string): string {
    return (base64UrlString + '==='.slice((base64UrlString.length + 3) % 4))
      .replace(/-/g, '+')
      .replace(/_/g, '/');
  }

  /**
   * Converts a Base64 string to a Base64URL string.
   * TODO: Improve implementation perf.
   */
  static fromBase64 (base64String: string): string {
    return base64String
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

}
