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
      expect(jws['protectedHeaders']).toEqual('foo');
      expect(jws['payload']).toEqual('foobar');
      expect(jws['signature']).toEqual('baz');
      expect(jws['unprotectedHeaders']).toBeUndefined();
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
      expect(jws['protectedHeaders']).toBeUndefined();
      expect(jws['unprotectedHeaders']).toBeDefined();
      expect(jws['unprotectedHeaders']!['kid']).toEqual('test');
      expect(jws['payload']).toEqual('foobar');
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
      expect(jws['protectedHeaders']).toEqual('foo');
      expect(jws['payload']).toEqual('foobar');
      expect(jws['signature']).toEqual('baz');
      expect(jws['unprotectedHeaders']).toBeDefined();
      expect(jws['unprotectedHeaders']!['foo']).toEqual('bar');
    });

    it('should ignore objects with invalid header formats', () => {
      const correctJWS = {
        header: 'wrong',
        payload: 'foobar',
        signature: 'baz'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['protectedHeaders']).toBeUndefined();
    });

    it('should ignore objects missing protected and header', () => {
      const correctJWS = {
        payload: 'foobar',
        signature: 'baz'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['protectedHeaders']).toBeUndefined();
    });

    it('should ignore objects missing signature', () => {
      const correctJWS = {
        protected: 'foo',
        payload: 'foobar'
      };
      const jws = new JwsToken(correctJWS, registry);
      expect(jws['protectedHeaders']).toBeUndefined();
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

    it('should require the JWS to have been parsed correctly', async () => {
      const jws = new JwsToken('I am not decryptable', registry);
      try {
        await jws.verifySignature(new TestPublicKey());
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('Could not parse contents into a JWS');
      }
    });
  });

  describe('getHeader', () => {
    it('should return headers from Compact JWS', () => {
      const test = Math.random().toString(16);
      const protectedHeaders = Base64Url.encode(JSON.stringify({
        test
      }));
      const jws = new JwsToken(protectedHeaders + '..', registry);
      const headers = jws.getHeader();
      expect(headers).toBeDefined();
      expect(headers['test']).toEqual(test);
    });

    it('should return headers from Flattened JSON Serialization', () => {
      const test = Math.random().toString(16);
      const headertest = Math.random().toString(16);
      const protectedHeaders = Base64Url.encode(JSON.stringify({
        test
      }));
      const jws = new JwsToken({
        protected: protectedHeaders,
        header: {
          headertest
        },
        payload: '',
        signature: ''
      }, registry);
      const headers = jws.getHeader();
      expect(headers).toBeDefined();
      expect(headers['test']).toEqual(test);
      expect(headers['headertest']).toEqual(headertest);
    });

    it('should return headers from Flattened JSON Serialization with only header', () => {
      const headertest = Math.random().toString(16);
      const jws = new JwsToken({
        header: {
          headertest
        },
        payload: '',
        signature: ''
      }, registry);
      const headers = jws.getHeader();
      expect(headers).toBeDefined();
      expect(headers['headertest']).toEqual(headertest);
    });

    it('should return headers from Flattened JSON Serialization with only protected', () => {
      const test = Math.random().toString(16);
      const protectedHeaders = Base64Url.encode(JSON.stringify({
        test
      }));
      const jws = new JwsToken({
        protected: protectedHeaders,
        payload: '',
        signature: ''
      }, registry);
      const headers = jws.getHeader();
      expect(headers).toBeDefined();
      expect(headers['test']).toEqual(test);
    });
  });

  describe('getPayload', () => {
    let data: string;
    let payload: string;

    beforeEach(() => {
      data = JSON.stringify({
        test: Math.random()
      });
      payload = Base64Url.encode(data);
    });

    it('should return the payload from a compact JWS', () => {
      const jws = new JwsToken(`.${payload}.`, registry);
      expect(jws.getPayload()).toEqual(data);
    });

    it('should return the payload from a Flattened JSON JWS', () => {
      const jws = new JwsToken({
        header: {
          alg: 'none'
        },
        payload,
        signature: ''
      }, registry);
      expect(jws.getPayload()).toEqual(data);
    });

    it('should return the original content if it was unable to parse a JWS', () => {
      const jws = new JwsToken('some test value', registry);
      expect(jws.getPayload()).toEqual('some test value');
    })
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

  describe('signFlatJson', () => {

    let data: any;

    beforeEach(() => {
      data = {
        description: `test: ${Math.random()}`
      };
    });

    it('should throw an error because the algorithm is not supported', async () => {
      const privateKey = new TestPrivateKey();
      privateKey.defaultSignAlgorithm = 'unsupported';
      const jwsToken = new JwsToken(data, registry);
      try {
        await jwsToken.signFlatJson(privateKey);
      } catch (err) {
        expect(err).toBeDefined();
        return;
      }
      fail('Sign did not throw');
    });

    it('should call the crypto Algorithms\'s sign', async () => {
      const jwsToken = new JwsToken(data, registry);
      crypto.reset();
      await jwsToken.signFlatJson(new TestPrivateKey());
      expect(crypto.wasSignCalled()).toBeTruthy();
    });

    it('should return the expected JSON JWS', async () => {
      const jwsToken = new JwsToken(data, registry);
      const key = new TestPrivateKey();
      const jws = await jwsToken.signFlatJson(key);
      console.log(jws);
      expect(jws.signature).toBeDefined();
      expect(Base64Url.decode(jws.payload)).toEqual(JSON.stringify(data));
    });
  });
});
