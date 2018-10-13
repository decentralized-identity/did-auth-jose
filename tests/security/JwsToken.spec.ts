import JwsToken from '../../lib/security/JwsToken';
import TestCryptoAlgorithms from '../mocks/TestCryptoProvider';
import Base64Url from '../../lib/utilities/Base64Url';
import { TestPublicKey } from '../mocks/TestPublicKey';
import CryptoFactory from '../../lib/CryptoFactory';
import TestPrivateKey from '../mocks/TestPrivateKey';

describe('JwsToken', () => {

  describe('verifySignature', () => {
    const crypto = new TestCryptoAlgorithms();
    let registry: CryptoFactory;
    beforeEach(() => {
      registry = new CryptoFactory([crypto]);
    });

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
    const crypto = new TestCryptoAlgorithms();
    let registry = new CryptoFactory([crypto]);

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
