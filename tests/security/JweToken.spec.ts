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
      expect(jwe['isFlattenedJSONSerialized']).toBeTruthy();
      expect(jwe['protected']).toEqual('secret properties');
      expect(jwe['content']).toEqual('secrets');
      expect(jwe['unprotected']).toBeUndefined();
      expect(jwe['iv']).toEqual('vector');
      expect(jwe['tag']).toEqual('tag');
      expect(jwe['encrypted_key']).toEqual('a key');
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
      expect(jwe['isFlattenedJSONSerialized']).toBeTruthy();
      expect(jwe['unprotected']).toBeDefined();
      expect(jwe['unprotected']!['test']).toEqual('secret property');
      expect(jwe['content']).toEqual('secrets');
      expect(jwe['iv']).toEqual('vector');
      expect(jwe['tag']).toEqual('tag');
      expect(jwe['encrypted_key']).toEqual('a key');
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
      expect(jwe['isFlattenedJSONSerialized']).toBeTruthy();
      expect(jwe['unprotected']).toBeDefined();
      expect(jwe['unprotected']!['test']).toEqual('secret property');
      expect(jwe['unprotected']!['test2']).toEqual('secret boogaloo');
    });
    it('should require encrypted_key as a flattened JSON object', () => {
      const jweObject = {
        ciphertext: 'secrets',
        iv: 'vector',
        tag: 'tag',
        protected: 'secret properties'
      };
      const jwe = new JweToken(jweObject, registry);
      expect(jwe['isFlattenedJSONSerialized']).toBeFalsy();
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
      expect(jwe['isFlattenedJSONSerialized']).toBeFalsy();
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

  describe('decrypt', () => {
    const crypto = new TestCryptoAlgorithms();
    let registry = new CryptoRegistry([crypto]);
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
        enc: 'A128GCM'
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
        enc: 'A128GCM'
      });
      const jwe = new JweToken(newMessage, registry);
      await expectToThrow(jwe, 'decrypt succeeded when a necessary header was omitted');
    });

    it('should check "crit" per RFC 7516 5.2.5 and RFC 7515 4.1.11', async () => {
      let message = usingheaders({
        kty: 'test',
        kid: privateKey.kid,
        enc: 'A128GCM',
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
        enc: 'A128GCM',
        alg: 'test',
        test: 'A "required" field',
        crit: 1
      });
      jwe = new JweToken(message, registry);
      await expectToThrow(jwe, 'decrypt succeeded when a "crit" header was malformed', 'malformed');

      message = usingheaders({
        kty: 'test',
        kid: privateKey.kid,
        enc: 'A128GCM',
        alg: 'test',
        test: 'A "required" field',
        crit: []
      });
      jwe = new JweToken(message, registry);
      await expectToThrow(jwe, 'decrypt decrypted data with mis-matched headers', 'authenticat'); // e or ion
    });

    it('should require the key ids to match', async () => {
      const newMessage = usingheaders({
        kty: 'test',
        kid: privateKey.kid + '1',
        enc: 'A128GCM',
        alg: 'test'
      });
      const jwe = new JweToken(newMessage, registry);
      await expectToThrow(jwe, 'decrypt succeeded when the private key does not match the headers key');
    });

    it('should decrypt encrypted JWEs', async () => {
      const jwe = new JweToken(encryptedMessage, registry);
      const payload = await jwe.decrypt(privateKey);
      expect(payload).toEqual(plaintext);
    });
  });

});
