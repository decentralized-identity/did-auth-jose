import { DidDocument, unitTestExports } from '@decentralized-identity/did-common-typescript';
import { Authentication, CryptoFactory, PublicKey, PrivateKey, JweToken, JwsToken, PrivateKeyRsa, RsaCryptoSuite } from '../lib';
import VerifiedRequest from '../lib/interfaces/VerifiedRequest';

describe('Authentication', () => {
  let hubkey: PrivateKey;
  let examplekey: PrivateKey;
  let hubPublicKey: PublicKey;
  let hubResolvedDID: DidDocument;
  let hubKeys = {};
  let examplePublicKey: PublicKey;
  let exampleResolvedDID: DidDocument;
  let auth: Authentication;
  let registry = new CryptoFactory([new RsaCryptoSuite()]);
  let resolver = new unitTestExports.TestResolver();
  const hubDID = 'did:example:did';
  const exampleDID = 'did:example:123456789abcdefghi';

  beforeAll(async (done) => {
    hubkey = await PrivateKeyRsa.generatePrivateKey(`${hubDID}#key1`);
    examplekey = await PrivateKeyRsa.generatePrivateKey(`${exampleDID}#keys-1`);
    hubPublicKey = hubkey.getPublicKey();
    hubKeys = {
      'did:example:did#key1': hubkey
    };
    examplePublicKey = examplekey.getPublicKey();
    exampleResolvedDID = new DidDocument({
      '@context': 'https://w3id.org/did/v1',
      'id': exampleDID,
      'publicKey': [{
        id: `${exampleDID}#keys-1`,
        type: 'RsaVerificationKey2018',
        owner: exampleDID,
        publicKeyJwk: examplePublicKey
      }],
      'authentication': [{
        type: 'RsaSignatureAuthentication2018',
        publicKey: `${exampleDID}#keys-1`
      }],
      'service': [{
        type: 'ExampleService',
        serviceEndpoint: 'https://example.com/endpoint/8377464'
      }]
    });
    hubResolvedDID = new DidDocument({
      '@context': 'https://w3id.org/did/v1',
      'id': hubDID,
      'publicKey': [{
        id: `${hubDID}#key1`,
        type: 'RsaVerificationKey2018',
        owner: hubDID,
        publicKeyJwk: hubPublicKey
      }]
    });

    auth = new Authentication({
      resolver,
      keys: hubKeys
    });
    done();
  });

  // creates a new access token for 5 minutes using the key given
  async function newAccessToken (key: PrivateKey = hubkey): Promise<string> {
    return registry.constructJws({
      sub: exampleDID,
      iat: new Date(Date.now()),
      exp: new Date(Date.now() + 5 * 60 * 1000)
    }).sign(key);
  }

  // sets the resolver's resolution for a did, clearing all others
  function setResolve (forDid: string, resolution: DidDocument) {
    resolver.setHandle((did: string) => {
      return new Promise((resolve, reject) => {
        if (did === forDid) {
          resolve(resolution);
        } else {
          reject(`Attempted to resolve erroneous did ${did}`);
        }
      });
    });
  }

  let header = {
    'alg': 'RS256',
    'kid': `${exampleDID}#keys-1`,
    'did-access-token': ''};

  beforeEach(async () => {
    const token = await newAccessToken();

    header = {
      'alg': 'RS256',
      'kid': `${exampleDID}#keys-1`,
      'did-access-token': token
    };

    setResolve(exampleDID, exampleResolvedDID);
  });

  describe('getVerifiedRequest', () => {

    it('should reject for hub keys it does not contain', async () => {
      const payload = {
        description: 'Authenticaiton test'
      };
      const jwsToken = new JwsToken(payload, registry);
      const data = await jwsToken.sign(examplekey, header);

      const unknownKey = await PrivateKeyRsa.generatePrivateKey('did:example:totallyunknown#key');

      const jweToken = new JweToken(data, registry);
      const request = await jweToken.encrypt(unknownKey);

      try {
        const context = await auth.getVerifiedRequest(request);
        fail('Auth did not throw.');
        console.log(context);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it('should decrypt the request', async () => {
      const payload = {
        'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
      };

      const jws = new JwsToken(payload, registry);
      const data = await jws.sign(examplekey, header);

      const jwe = new JweToken(data, registry);
      const request = await jwe.encrypt(hubPublicKey);

      const context = await auth.getVerifiedRequest(request);
      expect((context as VerifiedRequest).request).toEqual(JSON.stringify(payload));
    });

    it('should throw if invalid signature', async () => {
      const payload = {
        'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
      };
      const jws = new JwsToken(payload, registry);
      let data = await jws.sign(examplekey, header);

      const index = data.lastIndexOf('.') + 1;
      const char = data[index] === 'a' ? 'b' : 'a';
      data = data.substr(0, index) + char + data.substr(index + 1);

      const jwe = new JweToken(data, registry);
      const request = await jwe.encrypt(hubPublicKey);

      try {
        await auth.getVerifiedRequest(request);
        fail('Expected function to throw an Error.');
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it('should throw if the requester key is not found', async () => {
      const payload = {
        'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
      };
      const jws = new JwsToken(payload, registry);

      const unknownKeyHeader = {
        alg: 'RS256',
        kid: 'did:example:123456789abcdefghi#unknown-key'
      };

      const data = await jws.sign(examplekey, unknownKeyHeader);

      const jwe = new JweToken(data, registry);
      const request = await jwe.encrypt(hubPublicKey);

      try {
        await auth.getVerifiedRequest(request);
        fail('Expected function to throw an Error.');
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it('should thorw if the key is not understood', async () => {
      const payload = {
        'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
      };

      const jws = new JwsToken(payload, registry);
      const data = await jws.sign(examplekey, header);

      const jwe = new JweToken(data, registry);
      const request = await jwe.encrypt(hubPublicKey);

      resolver.setHandle(() => {
        return new Promise((resolve) => {
          resolve(new DidDocument({
            '@context': 'https://w3id.org/did/v1',
            'id': hubDID,
            'publicKey': [{
              id: `${hubDID}#key1`,
              type: 'ExplicitlyUnknownKeyType2018',
              owner: hubDID,
              publicKeyJwk: hubkey
            }]
          }));
        });
      });

      try {
        await auth.getVerifiedRequest(request);
        fail('Expected function to throw an Error.');
      } catch (err) {
        expect(err).toBeDefined();
      }
    });
  });

  describe('getAuthenticatedRequest', () => {

    it('should encrypt with the DID\'s public key', async () => {
      const content = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();
      const request = await auth.getAuthenticatedRequest(content, hubkey, exampleDID, await newAccessToken(examplekey));
      const jwe = registry.constructJwe(request.toString());
      const jwsstring = await jwe.decrypt(examplekey);
      const jws = registry.constructJws(jwsstring);
      expect(jws.getPayload()).toEqual(content);
    });

  });

  describe('getAuthenticatedResponse', () => {
    it('should be understood by decrypt and validate', async () => {
      const requestString = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();

      setResolve(hubDID, hubResolvedDID);

      const request = await auth.getAuthenticatedRequest(requestString, examplekey, hubDID, header['did-access-token']);

      const testContent = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();

      setResolve(exampleDID, exampleResolvedDID);

      const verifiedRequest = await auth.getVerifiedRequest(request, true);

      if (verifiedRequest instanceof Buffer) {
        fail('Request should validate with the given access token');
        return;
      }

      const response = await auth.getAuthenticatedResponse(verifiedRequest, testContent);

      const clientAuth = new Authentication({
        resolver,
        keys: {
          'did:example:123456789abcdefghi#keys-1': examplekey
        }
      });

      setResolve(hubDID, hubResolvedDID);

      const context = await clientAuth.getVerifiedRequest(response, false);
      expect((context as VerifiedRequest).request).toEqual(testContent);
    });
  });
});
