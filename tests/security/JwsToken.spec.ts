import JwsToken from '../../lib/security/JwsToken';
import TestCryptoAlgorithms from '../mocks/TestCryptoProvider';
import Base64Url from '../../lib/utilities/Base64Url';
import { TestPublicKey } from '../mocks/TestPublicKey';
import CryptoRegistry from '../../lib/CryptoFactory';

describe('JwsToken', () => {

  describe('verifySignature', () => {
    const crypto = new TestCryptoAlgorithms();
    let registry = new CryptoRegistry([crypto]);

    const header = {
      alg: 'test',
      kid: 'did:example:123456789abcdefghi#keys-1'
    };

    const payload = {
      description: 'JWSToken test'
    };

    it('should throw an error because algorithm unsupported', () => {
      const unsupportedHeader = {
        alg: 'RS256',
        kid: 'did:example:123456789abcdefghi#keys-1'
      };

      const data = Base64Url.encode(JSON.stringify(unsupportedHeader)) + '.' +
      Base64Url.encode(JSON.stringify(payload)) + '.';
      expect(() => {
        const jwsToken = new JwsToken(data, registry);
        jwsToken.verifySignature(new TestPublicKey());
      }).toThrowError('Unsupported signing algorithm: RS256');

    });

    it('should throw an error because signature failed', () => {
      const data = Base64Url.encode(JSON.stringify(header)) + '.' +
      Base64Url.encode(JSON.stringify(payload)) + '.';
      expect(() => {
        const jwsToken = new JwsToken(data, registry);
        jwsToken.verifySignature(new TestPublicKey());
      }).toThrowError('Failed signature validation');

    });

    it('should call the crypto Algorithms\'s verify', () => {
      const data = Base64Url.encode(JSON.stringify(header)) + '.' +
      Base64Url.encode(JSON.stringify(payload)) + '.';
      const jwsToken = new JwsToken(data, registry);
      crypto.reset();
      try {
        jwsToken.verifySignature(new TestPublicKey());
      } catch (err) {
        // This signature will fail.
      }
      expect(crypto.wasVerifyCalled()).toBeTruthy();
    });
  });
});
