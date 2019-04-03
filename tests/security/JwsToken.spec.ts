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

    it('should parse a JSON JWS from a string', async () => {
      const testValue = Math.random().toString(16);
      const token = new JwsToken(testValue, registry);
      const privateKey = new TestPrivateKey();
      const encryptedToken = await token.signAsFlattenedJson(privateKey);
      const encryptedTokenAsString = JSON.stringify(encryptedToken);

      const actualToken = new JwsToken(encryptedTokenAsString, registry);
      expect(actualToken.isContentWellFormedToken()).toBeTruthy();
      const actualValue = await actualToken.verifySignature(privateKey.getPublicKey());
      expect(actualValue).toEqual(testValue);
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

    it('should not add its own alg and kid headers if ones are provided', async () => {
      const privateKey = new TestPrivateKey();
      const jwsToken = new JwsToken(data, registry);
      try {
        await jwsToken.sign(privateKey, {
          alg: 'unknown',
          kid: 'also unknown'
        });
        fail('expected to throw');
      } catch (err) {
        expect(err).toBeDefined();
        return;
      }
    });
  });

  describe('signAsFlattenedJson', () => {

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
        await jwsToken.signAsFlattenedJson(privateKey);
      } catch (err) {
        expect(err).toBeDefined();
        return;
      }
      fail('Sign did not throw');
    });

    it('should call the crypto Algorithms\'s sign', async () => {
      const jwsToken = new JwsToken(data, registry);
      crypto.reset();
      await jwsToken.signAsFlattenedJson(new TestPrivateKey());
      expect(crypto.wasSignCalled()).toBeTruthy();
    });

    it('should return the expected JSON JWS', async () => {
      const jwsToken = new JwsToken(data, registry);
      const key = new TestPrivateKey();
      const jws = await jwsToken.signAsFlattenedJson(key);
      expect(jws.signature).toBeDefined();
      expect(Base64Url.decode(jws.payload)).toEqual(JSON.stringify(data));
    });

    it('should not add alg or kid if they are provided in the header', async () => {
      const privateKey = new TestPrivateKey();
      const jwsToken = new JwsToken(data, registry);
      const jws = await jwsToken.signAsFlattenedJson(privateKey, {
        header: {
          alg: privateKey.defaultSignAlgorithm,
          kid: privateKey.kid
        }
      });
      expect(jws.signature).toBeDefined();
      expect(jws.protected).toBeUndefined();
    });
  });

  describe('toCompactJws', () => {
    it('should fail if the token is not a JWS', () => {
      const token = new JwsToken('definately not a jws', registry);
      try {
        token.toCompactJws();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('parse');
      }
    });

    it('should fail if alg is not a protected header', () => {
      const token = new JwsToken({
        protected: '',
        payload: '',
        signature: ''
      }, registry);
      try {
        token.toCompactJws();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('alg');
      }
    });

    it('should form a compact JWS', () => {
      const expectedProtected = Base64Url.encode(JSON.stringify({
        alg: 'RSA-OAEP'
      }));
      const token = new JwsToken({
        protected: expectedProtected,
        header: {
          test: 'should be ignored'
        },
        payload: 'signedContent',
        signature: 'signature'
      }, registry);
      expect(token.toCompactJws()).toEqual(
        `${expectedProtected}.signedContent.signature`
      );
    });
  });

  describe('toFlattenedJsonJws', () => {
    const expectedProtected = Base64Url.encode(JSON.stringify({
      alg: 'RSA-OAEP'
    }));
    const signature = 'signature';
    const payload = 'signedContent';
    let jws: string;

    beforeEach(() => {
      jws = `${expectedProtected}.${payload}.${signature}`;
    });

    it('should fail if the token is not a JWS', () => {
      const token = new JwsToken('not a jws', registry);
      try {
        token.toFlattenedJsonJws();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('parse');
      }
    });

    it('should fail if alg is not a header', () => {
      jws = `.${payload}.${signature}`;
      const token = new JwsToken(jws, registry);
      try {
        token.toFlattenedJsonJws();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('alg');
      }
    });

    it('should form a JSON JWS from a compact JWS', () => {
      const token = new JwsToken(jws, registry);
      expect(token.toFlattenedJsonJws()).toEqual({
        protected: expectedProtected,
        payload,
        signature
      });
    });

    it('should override unprotected headers with those passed to it', () => {
      const headers = {
        test: 'foo'
      };
      const token = new JwsToken({
        protected: expectedProtected,
        header: {
          test: 'bar'
        },
        payload,
        signature
      }, registry);
      expect(token.toFlattenedJsonJws(headers)).toEqual({
        protected: expectedProtected,
        header: headers,
        payload,
        signature
      });
    });

    it('should accept JWSs with no protected header', () => {
      const headers = {
        alg: 'RSA-OAEP'
      };
      const token = new JwsToken({
        header: {
          test: 'bar'
        },
        payload,
        signature
      }, registry);
      expect(token.toFlattenedJsonJws(headers)).toEqual({
        header: headers,
        payload,
        signature
      });
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
