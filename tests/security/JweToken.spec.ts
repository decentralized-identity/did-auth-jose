import TestCryptoAlgorithms from '../mocks/TestCryptoProvider';
import { PublicKey, JweToken, PrivateKey, RsaCryptoSuite, AesCryptoSuite } from '../../lib';
import CryptoRegistry from '../../lib/CryptoFactory';
import TestPrivateKey from '../mocks/TestPrivateKey';
import Base64Url from '../../lib/utilities/Base64Url';

describe('JweToken', () => {
  const crypto = new TestCryptoAlgorithms();
  let registry: CryptoRegistry;

  beforeEach(() => {
    registry = new CryptoRegistry([crypto]);
  });

  describe('constructor', () => {
    it('should construct from a flattened JSON object with a protected', () => {
      const jweObject = {
        ciphertext: 'secrets',
        iv: 'vector',
        tag: 'tag',
        encrypted_key: 'a key',
        protected: 'secret properties'
      };
      const jwe = new JweToken(jweObject, registry);
      expect(jwe['protectedHeaders']).toEqual('secret properties');
      expect(jwe['payload']).toEqual('secrets');
      expect(jwe['unprotectedHeaders']).toBeUndefined();
      expect(jwe['iv']).toEqual(Base64Url.decodeToBuffer('vector'));
      expect(jwe['tag']).toEqual(Base64Url.decodeToBuffer('tag'));
      expect(jwe['encryptedKey']).toEqual(Base64Url.decodeToBuffer('a key'));
    });
    it('should construct from a flattened JSON object with an unprotected', () => {
      const jweObject = {
        ciphertext: 'secrets',
        iv: 'vector',
        tag: 'tag',
        encrypted_key: 'a key',
        unprotected: {
          test: 'secret property'
        }
      };
      const jwe = new JweToken(jweObject, registry);
      expect(jwe['unprotectedHeaders']).toBeDefined();
      expect(jwe['unprotectedHeaders']!['test']).toEqual('secret property');
      expect(jwe['payload']).toEqual('secrets');
      expect(jwe['iv']).toEqual(Base64Url.decodeToBuffer('vector'));
      expect(jwe['tag']).toEqual(Base64Url.decodeToBuffer('tag'));
      expect(jwe['encryptedKey']).toEqual(Base64Url.decodeToBuffer('a key'));
    });
    it('should combine flattened JSON object headers unprotected and header', () => {
      const jweObject = {
        ciphertext: 'secrets',
        iv: 'vector',
        tag: 'tag',
        encrypted_key: 'a key',
        unprotected: {
          test: 'secret property'
        },
        header: {
          test2: 'secret boogaloo'
        }
      };
      const jwe = new JweToken(jweObject, registry);
      expect(jwe['unprotectedHeaders']).toBeDefined();
      expect(jwe['unprotectedHeaders']!['test']).toEqual('secret property');
      expect(jwe['unprotectedHeaders']!['test2']).toEqual('secret boogaloo');
    });
    it('should accept flattened JSON object with only header', () => {
      const jweObject = {
        ciphertext: 'secrets',
        iv: 'vector',
        tag: 'tag',
        encrypted_key: 'a key',
        header: {
          test: 'secret boogaloo'
        }
      };
      const jwe = new JweToken(jweObject, registry);
      expect(jwe['unprotectedHeaders']).toBeDefined();
      expect(jwe['unprotectedHeaders']!['test']).toEqual('secret boogaloo');
    });
    it('should require encrypted_key as a flattened JSON object', () => {
      const jweObject = {
        ciphertext: 'secrets',
        iv: 'vector',
        tag: 'tag',
        protected: 'secret properties'
      };
      const jwe = new JweToken(jweObject, registry);
      expect(jwe['protectedHeaders']).toBeUndefined();
    });
    it('should handle ignore general JSON serialization for now', () => {
      const jweObject = {
        ciphertext: 'secrets',
        iv: 'vector',
        tag: 'tag',
        protected: 'secret properties',
        recipients: []
      };
      const jwe = new JweToken(jweObject, registry);
      expect(jwe['protectedHeaders']).toBeUndefined();
    });

    // test that it throws for incorrect types
    ['protected', 'unprotected', 'header', 'encrypted_key', 'iv', 'tag', 'ciphertext'].forEach(
      (property) => {
        it(`should throw if ${property} is not the right type`, () => {
          const jwe: any = {
            ciphertext: 'secrets',
            iv: 'vector',
            tag: 'tag',
            protected: 'secret properties',
            unprotected: {
              secrets: 'are everywhere'
            },
            header: {
              aliens: 'do you believe?'
            }
          };
          jwe[property] = true;
          const token = new JweToken(jwe, registry);
          expect(token['aad']).toBeUndefined();
          expect(token['encryptedKey']).toBeUndefined();
          expect(token['iv']).toBeUndefined();
          expect(token['payload']).toBeUndefined();
          expect(token['protectedHeaders']).toBeUndefined();
          expect(token['tag']).toBeUndefined();
          expect(token['unprotectedHeaders']).toBeUndefined();
        });
      });

    it('should parse a JSON JWE from a string', async () => {
      const testValue = Math.random().toString(16);
      const token = new JweToken(testValue, registry);
      const privateKey = new TestPrivateKey();
      const encryptedToken = await token.encryptAsFlattenedJson(privateKey.getPublicKey());
      const encryptedTokenAsString = JSON.stringify(encryptedToken);

      const actualToken = new JweToken(encryptedTokenAsString, registry);
      expect(actualToken.isContentWellFormedToken()).toBeTruthy();
      const actualValue = await actualToken.decrypt(privateKey);
      expect(actualValue).toEqual(testValue);
    });
  });

  describe('encrypt', () => {

    it('should fail for an unsupported encryption algorithm', () => {
      const testJwk = {
        kty: 'RSA',
        kid: 'did:example:123456789abcdefghi#keys-1',
        defaultEncryptionAlgorithm: 'unknown',
        defaultSignAlgorithm: 'test'
      };
      const jwe = new JweToken('', registry);
      jwe.encrypt(testJwk).then(() => {
        fail('Error was not thrown.');
      }).catch(
        (error) => {
          expect(error).toMatch(/Unsupported encryption algorithm/i);
        });
    });

    it('should call the crypto Algorithms\'s encrypt', async () => {
      crypto.reset();
      const jwk = {
        kty: 'RSA',
        kid: 'test',
        defaultEncryptionAlgorithm: 'test',
        defaultSignAlgorithm: 'test'
      } as PublicKey;
      const jwe = new JweToken('', registry);
      await jwe.encrypt(jwk);
      expect(crypto.wasEncryptCalled()).toBeTruthy();
    });

    it('should accept additional headers', async () => {
      const jwk = {
        kty: 'RSA',
        kid: 'test',
        defaultEncryptionAlgorithm: 'test',
        defaultSignAlgorithm: 'test'
      } as PublicKey;
      const magicvalue = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();
      const headers = {
        test: magicvalue
      };
      const jwe = new JweToken('', registry);
      const encrypted = await jwe.encrypt(jwk, headers);
      const text = encrypted.toString();
      const index = text.indexOf('.');
      const base64Headers = text.substr(0, index);
      const headersString = Buffer.from(base64Headers, 'base64').toString();
      const resultheaders = JSON.parse(headersString);
      expect(resultheaders['test']).toEqual(magicvalue);
    });
  });

  describe('encryptAsFlattenedJson', () => {
    it('should fail for an unsupported encryption algorithm', () => {
      const testJwk = {
        kty: 'RSA',
        kid: 'did:example:123456789abcdefghi#keys-1',
        defaultEncryptionAlgorithm: 'unknown',
        defaultSignAlgorithm: 'test'
      };
      const jwe = new JweToken('', registry);
      jwe.encryptAsFlattenedJson(testJwk).then(() => {
        fail('Error was not thrown.');
      }).catch(
        (error) => {
          expect(error).toMatch(/Unsupported encryption algorithm/i);
        });
    });

    it('should call the crypto Algorithms\'s encrypt', async () => {
      crypto.reset();
      const jwk = {
        kty: 'RSA',
        kid: 'test',
        defaultEncryptionAlgorithm: 'test',
        defaultSignAlgorithm: 'test'
      } as PublicKey;
      const jwe = new JweToken('', registry);
      await jwe.encryptAsFlattenedJson(jwk);
      expect(crypto.wasEncryptCalled()).toBeTruthy();
    });

    it('should accept additional options', async () => {
      const jwk = {
        kty: 'RSA',
        kid: 'test',
        defaultEncryptionAlgorithm: 'test',
        defaultSignAlgorithm: 'test'
      } as PublicKey;
      const protectedValue = Math.round(Math.random()).toString(16);
      const unprotectedValue = Math.round(Math.random()).toString(16);
      const aad = Math.round(Math.random()).toString(16);
      const plaintext = Math.round(Math.random()).toString(16);
      const jwe = new JweToken(plaintext, registry);
      crypto.reset();
      const encrypted = await jwe.encryptAsFlattenedJson(jwk, {
        aad,
        protected: {
          test: protectedValue
        },
        unprotected: {
          test: unprotectedValue
        }
      });
      expect(crypto.wasEncryptCalled()).toBeTruthy();
      expect(encrypted).toBeDefined();
      expect(encrypted.aad).toEqual(Base64Url.encode(aad));
      expect(encrypted.unprotected!['test']).toEqual(unprotectedValue);
      expect(JSON.parse(Base64Url.decode(encrypted.protected!))['test']).toEqual(protectedValue);
      expect(encrypted.ciphertext).not.toEqual(plaintext);
    });
  });

  describe('decrypt', () => {
    let privateKey: PrivateKey;
    let plaintext: string;
    let encryptedMessage: string;

    beforeEach(async () => {
      privateKey = new TestPrivateKey();
      const pub = privateKey.getPublicKey();
      plaintext = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString(16);
      const jwe = new JweToken(plaintext, registry);
      encryptedMessage = (await jwe.encrypt(pub)).toString();
    });

    function usingheaders (headers: any): string {
      const base64urlheaders = Base64Url.encode(JSON.stringify(headers));
      const messageParts = encryptedMessage.split('.');
      return `${base64urlheaders}.${messageParts[1]}.${messageParts[2]}.${messageParts[3]}.${messageParts[4]}`;
    }

    async function expectToThrow (jwe: JweToken, message: string, match?: string): Promise<void> {
      try {
        await jwe.decrypt(privateKey);
        fail(message);
      } catch (err) {
        expect(err).toBeDefined();
        if (match) {
          expect(err.message.toLowerCase()).toContain(match.toLowerCase());
        }
      }
    }

    it('should fail for an unsupported encryption algorithm', async () => {
      const newMessage = usingheaders({
        kty: 'test',
        kid: privateKey.kid,
        alg: 'unknown',
        enc: 'test'
      });
      const jwe = new JweToken(newMessage, registry);
      await expectToThrow(jwe, 'decrypt suceeded with unknown encryption algorithm used');
    });

    it('should call the crypto Algorithms\'s encrypt', async () => {
      const jwe = new JweToken(encryptedMessage.toString(), registry);
      crypto.reset();
      await jwe.decrypt(privateKey);
      expect(crypto.wasDecryptCalled()).toBeTruthy();
    });

    it('should require headers', async () => {
      const newMessage = usingheaders({
        kty: 'test',
        kid: privateKey.kid,
        enc: 'test'
      });
      const jwe = new JweToken(newMessage, registry);
      await expectToThrow(jwe, 'decrypt succeeded when a necessary header was omitted');
    });

    it('should check "crit" per RFC 7516 5.2.5 and RFC 7515 4.1.11', async () => {
      let message = usingheaders({
        kty: 'test',
        kid: privateKey.kid,
        enc: 'test',
        alg: 'test',
        test: 'A "required" field',
        crit: [
          'test'
        ]
      });
      let jwe = new JweToken(message, registry);
      await expectToThrow(jwe, 'decrypt succeeded when a "crit" header was included with unknown extensions', 'support');

      message = usingheaders({
        kty: 'test',
        kid: privateKey.kid,
        enc: 'test',
        alg: 'test',
        test: 'A "required" field',
        crit: 1
      });
      jwe = new JweToken(message, registry);
      await expectToThrow(jwe, 'decrypt succeeded when a "crit" header was malformed', 'malformed');
    });

    it('should require the key ids to match', async () => {
      const newMessage = usingheaders({
        kty: 'test',
        kid: privateKey.kid + '1',
        enc: 'test',
        alg: 'test'
      });
      const jwe = new JweToken(newMessage, registry);
      await expectToThrow(jwe, 'decrypt succeeded when the private key does not match the headers key');
    });

    it('should decrypt compact JWEs', async () => {
      const jwe = new JweToken(encryptedMessage, registry);
      const payload = await jwe.decrypt(privateKey);
      expect(payload).toEqual(plaintext);
    });

    it('should decrypt flattened JSON JWEs', async () => {
      const compactComponents = encryptedMessage.split('.');
      const jwe = new JweToken({
        protected: compactComponents[0],
        encrypted_key: compactComponents[1],
        iv: compactComponents[2],
        ciphertext: compactComponents[3],
        tag: compactComponents[4]
      }, registry);
      const payload = await jwe.decrypt(privateKey);
      expect(payload).toEqual(plaintext);
    });

    it('should decrypt flattened JSON JWEs using aad', async () => {
      const pub = privateKey.getPublicKey();
      const aad = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString(16);
      const jweToEncrypt = new JweToken(plaintext, registry);
      const encrypted = await jweToEncrypt.encryptAsFlattenedJson(pub, {
        aad
      });
      expect(encrypted.aad).toEqual(Base64Url.encode(aad));
      const jwe = new JweToken(encrypted, registry);
      const payload = await jwe.decrypt(privateKey);
      expect(payload).toEqual(plaintext);
    });

    it('should require the JWE to have been parsed correctly', async () => {
      const jwe = new JweToken('I am not decryptable', registry);
      try {
        await jwe.decrypt(privateKey);
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('Could not parse contents into a JWE');
      }
    });
  });

  describe('toCompactJwe', () => {
    it('should fail if the token is not a JWE', () => {
      const token = new JweToken('definately not a jwe', registry);
      try {
        token.toCompactJwe();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('parse');
      }
    });

    it('should fail if alg is not a protected header', () => {
      const token = new JweToken({
        protected: Base64Url.encode(JSON.stringify({
          enc: 'A128GCM'
        })),
        unprotected: {
          alg: 'RSA-OAEP'
        },
        ciphertext: '',
        iv: '',
        tag: '',
        encrypted_key: ''
      }, registry);
      try {
        token.toCompactJwe();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('alg');
      }
    });

    it('should fail if enc is not a protected header', () => {
      const token = new JweToken({
        protected: Base64Url.encode(JSON.stringify({
          alg: 'RSA-OAEP'
        })),
        unprotected: {
          enc: 'A128GCM'
        },
        ciphertext: '',
        iv: '',
        tag: '',
        encrypted_key: ''
      }, registry);
      try {
        token.toCompactJwe();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('enc');
      }
    });

    it('should fail if aad does not match compact aad', () => {
      const token = new JweToken({
        protected: Base64Url.encode(JSON.stringify({
          alg: 'RSA-OAEP',
          enc: 'A128GCM'
        })),
        ciphertext: '',
        iv: '',
        tag: '',
        encrypted_key: '',
        aad: 'cafecafe'
      }, registry);
      try {
        token.toCompactJwe();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('aad');
      }
    });

    it('should form a compact JWE from a JSON JWE', () => {
      const headers = Base64Url.encode(JSON.stringify({
        alg: 'RSA-OAEP',
        enc: 'A128GCM'
      }));
      const token = new JweToken({
        protected: headers,
        ciphertext: 'cccc',
        iv: 'bbbb',
        tag: 'dddd',
        encrypted_key: 'aaaa'
      }, registry);
      expect(token.toCompactJwe()).toEqual(`${headers}.aaaa.bbbb.cccc.dddd`);
    });
  });

  describe('toFlattenedJsonJwe', () => {
    let jwe: string;
    const expectedProtected = Base64Url.encode(JSON.stringify({
      enc: 'A128GCM',
      alg: 'RSA-OAEP'
    }));
    const iv = 'initializationVector';
    const key = 'encryptedKey';
    const cipher = 'cipher';
    const tag = 'authTag';

    beforeEach(() => {
      jwe = `${expectedProtected}.${key}.${iv}.${cipher}.${tag}`;
    });

    it('should fail if the token is not a JWE', () => {
      const token = new JweToken('definately not a jwe', registry);
      try {
        token.toFlattenedJsonJwe();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('parse');
      }
    });

    it('should fail if alg is not a header', () => {
      const headers = Base64Url.encode(JSON.stringify({
        enc: 'A128GCM'
      }));
      jwe = `${headers}.${key}.${iv}.${cipher}.${tag}`;
      const token = new JweToken(jwe, registry);
      try {
        token.toFlattenedJsonJwe();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('alg');
      }
    });

    it('should fail if enc is not a header', () => {
      const headers = Base64Url.encode(JSON.stringify({
        alg: 'RSA-OAEP'
      }));
      jwe = `${headers}.${key}.${iv}.${cipher}.${tag}`;
      const token = new JweToken(jwe, registry);
      try {
        token.toFlattenedJsonJwe();
        fail('expected to throw');
      } catch (err) {
        expect(err.message).toContain('enc');
      }
    });

    it('should form a JSON JWE from a compact JWE', () => {
      const token = new JweToken(jwe, registry);
      expect(token.toFlattenedJsonJwe()).toEqual({
        protected: expectedProtected,
        iv: iv,
        encrypted_key: key,
        ciphertext: cipher,
        tag
      });
    });

    it('should override unprotected headers with those passed to it', () => {
      const headers = {
        test: 'foo'
      };
      const token = new JweToken({
        protected: expectedProtected,
        unprotected: {
          test: 'bar'
        },
        iv: iv,
        encrypted_key: key,
        ciphertext: cipher,
        tag
      }, registry);
      expect(token.toFlattenedJsonJwe(headers)).toEqual({
        protected: expectedProtected,
        unprotected: headers,
        iv: iv,
        encrypted_key: key,
        ciphertext: cipher,
        tag
      });
    });

    it('should accept JWEs with no protected header', () => {
      const headers = {
        enc: 'A128GCM',
        alg: 'RSA-OAEP'
      };
      const token = new JweToken({
        unprotected: {
          test: 'bar'
        },
        iv: iv,
        encrypted_key: key,
        ciphertext: cipher,
        tag
      }, registry);
      expect(token.toFlattenedJsonJwe(headers)).toEqual({
        unprotected: headers,
        iv: iv,
        encrypted_key: key,
        ciphertext: cipher,
        tag
      });
    });

    it('should handle AAD data', () => {
      const aad = 'foobarbaz';
      const token = new JweToken({
        protected: expectedProtected,
        iv: iv,
        encrypted_key: key,
        ciphertext: cipher,
        tag,
        aad
      }, registry);
      expect(token.toFlattenedJsonJwe()).toEqual({
        protected: expectedProtected,
        iv: iv,
        encrypted_key: key,
        ciphertext: cipher,
        tag,
        aad
      });
    });
  });

  describe('validations', () => {
    describe('RSAES-OAEP with AES GCM', () => {
      let aes: AesCryptoSuite;
      // needs the actual RSA and AES implementations
      beforeEach(() => {
        aes = new AesCryptoSuite();
        registry = new CryptoRegistry([new RsaCryptoSuite(), aes]);
      });

      // rfc-7516 A.1
      const plaintext = Buffer.from([84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
        111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
        101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
        101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
        110, 97, 116, 105, 111, 110, 46]);
        // rfc-7516 A.1.1
      const expectedProtectedHeader = { alg: 'RSA-OAEP',enc: 'A256GCM' };
      // rfc-7516 A.1.1
      const encodedProtectedHeader = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ';
      // rfc-7516 A.1.2
      const cek = [177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
        212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
        234, 64, 252];
        // rfc-7516 A.1.3
      const rsaKey = {kty: 'RSA',
        n: 'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4D' +
        'FqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxzi' +
        'K72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsN' +
        'a7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
        e: 'AQAB',
        d: 'kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT' +
        '9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz' +
        '1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-' +
        'VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ',
        p: '1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAE' +
        'PTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0',
        q: 'wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28' +
        'cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc',
        dp: 'ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTj' +
        'Vw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE',
        dq: 'Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk' +
        '8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis',
        qi: 'VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOy' +
        'dB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY'
      };
      // rfc-7516 A.1.3
      const cekEncrypted = [56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
        22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
        82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
        145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
        74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
        13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
        173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
        89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
        243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
        41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
        215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
        63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
        193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
        206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
        104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
        89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
        172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
        117, 114, 135, 206];
      // rfc-7516 A.1.4
      const iv = [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219];
      // rfc-7516 A.1.5
      const aad = [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
        54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81];
      // rfc-7516 A.1.6
      const ciphertext = [229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
        233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
        104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
        123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
        160, 109, 64, 63, 192];
      // rfc-7516 A.1.6
      const tag = [92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
        210, 145];
      // rfc-7516 A.1.7
      const JWE = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.' +
      'OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe' +
      'ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb' +
      'Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV' +
      'mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8' +
      '1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi' +
      '6UklfCpIMfIjf7iGdXKHzg.' +
      '48V1_ALb6US04U3b.' +
      '5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji' +
      'SdiwkIr3ajwQzaBtQD_A.' +
      'XFBoMYUZodetZdvTiFvSkQ';
      it('should parse the compact JWE correctly', () => {
        const parsedJwe = new JweToken(JWE, registry);
        expect(parsedJwe['aad']).toEqual(Buffer.from(aad));
        expect(parsedJwe['encryptedKey']).toEqual(Buffer.from(cekEncrypted));
        expect(parsedJwe['iv']).toEqual(Buffer.from(iv));
        expect(parsedJwe['payload']).toEqual(Base64Url.encode(Buffer.from(ciphertext)));
        expect(parsedJwe['protectedHeaders']).toEqual(encodedProtectedHeader);
        expect(parsedJwe['tag']).toEqual(Buffer.from(tag));
        expect(parsedJwe['unprotectedHeaders']).toBeUndefined();
      });

      it('should decrypt correctly', async () => {
        const parsedJwe = new JweToken(JWE, registry);
        const actualPlaintext = await parsedJwe.decrypt(rsaKey as any);
        expect(actualPlaintext).toEqual(plaintext.toString());
      });

      it('should encrypt correctly', async (done) => {
        // set AES to return the expected IV and CEK
        spyOn(aes, 'generateInitializationVector' as any).and.returnValue(Buffer.from(iv));
        aes['generateSymmetricKey'] = (_: number) => { return Buffer.from(cek); };
        setTimeout(async () => {
          const plaintextString = plaintext.toString();
          const jwe = new JweToken(plaintextString, registry);

          const publicKey = {
            kty: 'RSA',
            n: rsaKey.n,
            e: rsaKey.e
          };
          const encrypted = await jwe.encrypt(publicKey as any, expectedProtectedHeader);
          // rfc-7516 A.1.8 CEK cannot be validated however other parameters should match.
          const actual = encrypted.toString().split('.');
          const expected = JWE.split('.');
          expect(actual[0]).toEqual(expected[0]);
          expect(actual[2]).toEqual(expected[2]);
          expect(actual[3]).toEqual(expected[3]);
          expect(actual[4]).toEqual(expected[4]);
          done();
        }, 100);
      });
    });
  });

});
