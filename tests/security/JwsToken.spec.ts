import JwsToken from '../../lib/security/JwsToken';
import TestCryptoAlgorithms from '../mocks/TestCryptoProvider';
import Base64Url from '../../lib/utilities/Base64Url';
import { TestPublicKey } from '../mocks/TestPublicKey';
import CryptoFactory from '../../lib/CryptoFactory';
import TestPrivateKey from '../mocks/TestPrivateKey';
import { RsaCryptoSuite } from '../../lib';

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
      expect(jws.signature).toBeDefined();
      expect(Base64Url.decode(jws.payload)).toEqual(JSON.stringify(data));
    });
  });

  describe('validations', () => {

    beforeEach(() => {
      registry = new CryptoFactory([new RsaCryptoSuite()]);
    });

    describe('RSASSA-PKCS1-v1_5 SHA-256', () => {
      // rfc-7515 A.2.1
      const headers = { alg: 'RS256' };
      // rfc-7515 A.2.1
      const encodedHeaders = 'eyJhbGciOiJSUzI1NiJ9';
      // rfc-7515 A.2.1
      const payload = Buffer.from([123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
        32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
        48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
        109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
        111, 116, 34, 58, 116, 114, 117, 101, 125]);
      // rfc-7515 A.2.1
      const encodedPayload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt' +
        'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
      // rfc-7515 A.2.1
      const rsaKey = {
        kty: 'RSA',
        n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx' +
            'HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs' +
            'D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH' +
            'SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV' +
            'MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8' +
            'NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
        e: 'AQAB',
        d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I' +
            'jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0' +
            'BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn' +
            '439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT' +
            'CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh' +
            'BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
        p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi' +
            'YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG' +
            'BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
        q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa' +
            'ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA' +
            '-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
        dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q' +
            'CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb' +
            '34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
        dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa' +
            '7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky' +
            'NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
        qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o' +
            'y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU' +
            'W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U'
      };
      // rfc-7515 A.2.1
      const finalJws = 'eyJhbGciOiJSUzI1NiJ9' +
        '.' +
        'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt' +
        'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ' +
        '.' +
        'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7' +
        'AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4' +
        'BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K' +
        '0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv' +
        'hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB' +
        'p0igcN_IoypGlUPQGe77Rw';

      it('signs correctly', async () => {
        const jws = new JwsToken(payload.toString(), registry);
        const privateKey: any = rsaKey;
        privateKey['defaultSignAlgorithm'] = 'RS256';
        const signed = await jws.sign(privateKey);
        expect(signed).toEqual(finalJws);
      });

      it('should validate correctly', async () => {
        const jws = new JwsToken(finalJws, registry);
        expect(jws['protectedHeaders']).toEqual(encodedHeaders);
        expect(jws['payload']).toEqual(encodedPayload);
        expect(jws.getHeader()).toEqual(headers);
        const publicKey: any = {
          kty: 'RSA',
          n: rsaKey.n,
          e: rsaKey.e
        };
        const actualPayload = await jws.verifySignature(publicKey);
        expect(actualPayload).toEqual(payload.toString());
      });
    });
  });
});
