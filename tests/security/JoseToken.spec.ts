import JoseToken from "../../lib/security/JoseToken";
import { TestCryptoSuite, CryptoFactory } from "../../lib";
import Base64Url from "../../lib/utilities/Base64Url";

class TestToken extends JoseToken {
  private static registry = new CryptoFactory([new TestCryptoSuite()]);
  constructor (content: string | object) {
    super(content, TestToken.registry);
    if (content === 'token') {
      this.payload = content;
    }
  }
}

describe('JoseToken', () => {
  describe('constructor', () => {
    it('should accept strings', () => {
      const token = new TestToken('foo');
      expect(token['content']).toEqual('foo');
    });

    it('should convert objects to JSON', () => {
      const fooObject = {
        test: 'foo'
      };
      const fooJson = JSON.stringify(fooObject);
      const token = new TestToken(fooObject);
      expect(token['content']).toEqual(fooJson);
    });
  });

  describe('getHeader', () => {
    it('should return protected and unprotected headers', () => {
      const token = new TestToken('token');
      token['protectedHeaders'] = Base64Url.encode(JSON.stringify({
        protectedHeader: 'foo'
      }));
      token['unprotectedHeaders'] = {
        unprotectedHeader: 'bar'
      };
      const headers = token.getHeader();
      expect(headers['unprotectedHeader']).toEqual('bar');
      expect(headers['protectedHeader']).toEqual('foo');
    });

    it('should return protected headers', () => {
      const token = new TestToken('token');
      token['protectedHeaders'] = Base64Url.encode(JSON.stringify({
        protectedHeader: 'foo'
      }));
      const headers = token.getHeader();
      expect(headers['protectedHeader']).toEqual('foo');
    });

    it('should return unprotected headers', () => {
      const token = new TestToken('token');
      token['unprotectedHeaders'] = {
        unprotectedHeader: 'bar'
      };
      const headers = token.getHeader();
      expect(headers['unprotectedHeader']).toEqual('bar');
    });
  });

  describe('getProtectedHeader', () => {
    it('should return protected headers', () => {
      const token = new TestToken('token');
      token['protectedHeaders'] = Base64Url.encode(JSON.stringify({
        protectedHeader: 'foo'
      }));
      const headers = token.getProtectedHeader();
      expect(headers['protectedHeader']).toEqual('foo');
    });

    it('should return empty if no protected headers are defined', () => {
      const token = new TestToken('token');
      const headers = token.getProtectedHeader();
      expect(headers).toEqual({});
    });

    it('should ignore unprotected headers', () => {
      const token = new TestToken('token');
      token['unprotectedHeaders'] = {
        unprotectedHeader: 'bar'
      };
      const headers = token.getProtectedHeader();
      expect(headers).toEqual({});
    });
  });

  describe('parsedToken', () => {
    it('should return true if it was able to parse the token', () => {
      const token = new TestToken('token');
      expect(token.parsedToken()).toBeTruthy();
    });

    it('should return false if it was unable to parse the token', () => {
      const token = new TestToken('not a token');
      expect(token.parsedToken()).toBeFalsy();
    });
  })
});