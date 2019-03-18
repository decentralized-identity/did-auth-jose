import TestCryptoAlgorithms from '../mocks/TestCryptoProvider';
import { PublicKey, JweToken, PrivateKey } from '../../lib';
import CryptoRegistry from '../../lib/CryptoFactory';
import TestPrivateKey from '../mocks/TestPrivateKey';
import Base64Url from '../../lib/utilities/Base64Url';

describe('JweToken', () => {
  const crypto = new TestCryptoAlgorithms();
  let registry = new CryptoRegistry([crypto]);

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
      expect(jwe['iv']).toEqual(Buffer.from(Base64Url.toBase64('vector'), 'base64'));
      expect(jwe['tag']).toEqual(Buffer.from(Base64Url.toBase64('tag'), 'base64'));
      expect(jwe['encryptedKey']).toEqual(Buffer.from(Base64Url.toBase64('a key'), 'base64'));
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
      expect(jwe['iv']).toEqual(Buffer.from(Base64Url.toBase64('vector'), 'base64'));
      expect(jwe['tag']).toEqual(Buffer.from(Base64Url.toBase64('tag'), 'base64'));
      expect(jwe['encryptedKey']).toEqual(Buffer.from(Base64Url.toBase64('a key'), 'base64'));
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

  describe('encryptFlatJson', () => {
    it('should fail for an unsupported encryption algorithm', () => {
      const testJwk = {
        kty: 'RSA',
        kid: 'did:example:123456789abcdefghi#keys-1',
        defaultEncryptionAlgorithm: 'unknown',
        defaultSignAlgorithm: 'test'
      };
      const jwe = new JweToken('', registry);
      jwe.encryptFlatJson(testJwk).then(() => {
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
      await jwe.encryptFlatJson(jwk);
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
      const encrypted = await jwe.encryptFlatJson(jwk, {
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
      const encrypted = await jweToEncrypt.encryptFlatJson(pub, {
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

  describe('getHeader', () => {
    it('should return headers from Compact JWE', () => {
      const test = Math.random().toString(16);
      const protectedHeaders = Base64Url.encode(JSON.stringify({
        test
      }));
      const jwe = new JweToken(protectedHeaders + '....', registry);
      const headers = jwe.getHeader();
      expect(headers).toBeDefined();
      expect(headers['test']).toEqual(test);
    });

    it('should return headers from Flattened JSON Serialization', () => {
      const test = Math.random().toString(16);
      const headertest = Math.random().toString(16);
      const unprotectedtest = Math.random().toString(16);
      const protectedHeaders = Base64Url.encode(JSON.stringify({
        test
      }));
      const jwe = new JweToken({
        protected: protectedHeaders,
        header: {
          headertest
        },
        unprotected: {
          unprotectedtest
        },
        ciphertext: '',
        iv: '',
        tag: '',
        encrypted_key: ''
      }, registry);
      const headers = jwe.getHeader();
      expect(headers).toBeDefined();
      expect(headers['test']).toEqual(test);
      expect(headers['headertest']).toEqual(headertest);
      expect(headers['unprotectedtest']).toEqual(unprotectedtest);
    });

    it('should return headers from Flattened JSON Serialization with only header', () => {
      const headertest = Math.random().toString(16);
      const unprotectedtest = Math.random().toString(16);
      const jwe = new JweToken({
        header: {
          headertest
        },
        unprotected: {
          unprotectedtest
        },
        ciphertext: '',
        iv: '',
        tag: '',
        encrypted_key: ''
      }, registry);
      const headers = jwe.getHeader();
      expect(headers).toBeDefined();
      expect(headers['headertest']).toEqual(headertest);
      expect(headers['unprotectedtest']).toEqual(unprotectedtest);
    });

    it('should return headers from Flattened JSON Serialization with only protected', () => {
      const test = Math.random().toString(16);
      const protectedHeaders = Base64Url.encode(JSON.stringify({
        test
      }));
      const jwe = new JweToken({
        protected: protectedHeaders,
        ciphertext: '',
        iv: '',
        tag: '',
        encrypted_key: ''
      }, registry);
      const headers = jwe.getHeader();
      expect(headers).toBeDefined();
      expect(headers['test']).toEqual(test);
    });
  });

});
