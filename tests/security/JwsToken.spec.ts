import JwsToken from '../../lib/security/JwsToken';
import TestCryptoAlgorithms from '../mocks/TestCryptoProvider';
import Base64Url from '../../lib/utilities/Base64Url';
import { TestPublicKey } from '../mocks/TestPublicKey';
import CryptoFactory from '../../lib/CryptoFactory';
import TestPrivateKey from '../mocks/TestPrivateKey';

describe('JwsToken', () => {
  const crypto = new TestCryptoAlgorithms();
  let registry: CryptoFactory;
  beforeEach(() => {
    registry = new CryptoFactory([crypto]);
  });

  describe('constructor', () => {
    it('should construct from a flattened JSON object', () => {
      const correctJWS = {
        protected: 'foo',
        payload: 'foobar',
        signature: 'baz'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['isFlattenedJSONSerialized']).toBeTruthy();
      expect(jws['protected']).toEqual('foo');
      expect(jws['content']).toEqual('foobar');
      expect(jws['signature']).toEqual('baz');
      expect(jws['header']).toBeUndefined();
    });

    it('should construct from a flattened JSON object using header', () => {
      const correctJWS = {
        header: {
          alg: 'test',
          kid: 'test'
        },
        payload: 'foobar',
        signature: 'baz'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['isFlattenedJSONSerialized']).toBeTruthy();
      expect(jws['protected']).toBeUndefined();
      expect(jws['header']).toBeDefined();
      expect(jws['header']!['kid']).toEqual('test');
      expect(jws['content']).toEqual('foobar');
      expect(jws['signature']).toEqual('baz');
    });

    it('should include nonprotected headers', () => {
      const correctJWS = {
        protected: 'foo',
        header: {
          foo: 'bar'
        },
        payload: 'foobar',
        signature: 'baz'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['isFlattenedJSONSerialized']).toBeTruthy();
      expect(jws['protected']).toEqual('foo');
      expect(jws['content']).toEqual('foobar');
      expect(jws['signature']).toEqual('baz');
      expect(jws['header']).toBeDefined();
      expect(jws['header']!['foo']).toEqual('bar');
    });

    it('should ignore objects with invalid header formats', () => {
      const correctJWS = {
        header: 'wrong',
        payload: 'foobar',
        signature: 'baz'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['isFlattenedJSONSerialized']).toBeFalsy();
    });

    it('should ignore objects missing protected and header', () => {
      const correctJWS = {
        payload: 'foobar',
        signature: 'baz'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['isFlattenedJSONSerialized']).toBeFalsy();
    });

    it('should ignore objects missing signature', () => {
      const correctJWS = {
        protected: 'foo',
        payload: 'foobar'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['isFlattenedJSONSerialized']).toBeFalsy();
    });
  });

  describe('verifySignature', () => {

    const header = {
      alg: 'test',
      kid: 'did:example:123456789abcdefghi#keys-1'
    };

    const payload = {
      description: 'JWSToken test'
    };

    it('should throw an error because algorithm unsupported', async () => {
      const unsupportedHeader = {
        alg: 'RS256',
        kid: 'did:example:123456789abcdefghi#keys-1'
      };

      const data = Base64Url.encode(JSON.stringify(unsupportedHeader)) + '.' +
      Base64Url.encode(JSON.stringify(payload)) + '.';

      const jwsToken = new JwsToken(data, registry);
      try {
        await jwsToken.verifySignature(new TestPublicKey());
        fail('Expected verifySignature to throw');
      } catch (err) {
        expect(err.message).toContain('Unsupported signing algorithm');
      }
    });

    it('should throw an error because signature failed', async () => {
      const data = Base64Url.encode(JSON.stringify(header)) + '.' +
      Base64Url.encode(JSON.stringify(payload)) + '.';
      spyOn(crypto, 'getSigners').and.returnValue({
        test: {
          sign: () => { return Buffer.from(''); },
          verify: (_: any, __: any, ___: any) => { return Promise.resolve(false); }
        }
      });
      registry = new CryptoFactory([crypto]);
      const jwsToken = new JwsToken(data, registry);
      try {
        await jwsToken.verifySignature(new TestPublicKey());
        fail('Expected verifySignature to throw');
      } catch (err) {
        expect(err.message).toContain('Failed signature validation');
      }
    });

    it('should call the crypto Algorithms\'s verify', async () => {
      const data = Base64Url.encode(JSON.stringify(header)) + '.' +
      Base64Url.encode(JSON.stringify(payload)) + '.';
      const jwsToken = new JwsToken(data, registry);
      crypto.reset();
      try {
        await jwsToken.verifySignature(new TestPublicKey());
      } catch (err) {
        // This signature will fail.
      }
      expect(crypto.wasVerifyCalled()).toBeTruthy();
    });
  });

  describe('sign', () => {
    const data = {
      description: 'JWSToken test'
    };

    it('should throw an error because the algorithm is not supported', async () => {
      const privateKey = new TestPrivateKey();
      privateKey.defaultSignAlgorithm = 'unsupported';
      const jwsToken = new JwsToken(data, registry);
      try {
        await jwsToken.sign(privateKey);
      } catch (err) {
        expect(err).toBeDefined();
        return;
      }
      fail('Sign did not throw');
    });

    it('should call the crypto Algorithms\'s sign', async () => {
      const jwsToken = new JwsToken(data, registry);
      crypto.reset();
      await jwsToken.sign(new TestPrivateKey());
      expect(crypto.wasSignCalled()).toBeTruthy();
    });
  });
});
