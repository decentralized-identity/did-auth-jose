import { DidDocument, unitTestExports } from '@decentralized-identity/did-common-typescript';
import { Authentication, CryptoFactory, PublicKey, PrivateKey, JweToken, JwsToken, PrivateKeyRsa, RsaCryptoSuite, AesCryptoSuite } from '../lib';
import VerifiedRequest from '../lib/interfaces/VerifiedRequest';
import AuthenticationResponse from '../lib/interfaces/AuthenticationResponse';
import AuthenticationRequest from '../lib/interfaces/AuthenticationRequest';

describe('Authentication', () => {
  let hubkey: PrivateKey;
  let examplekey: PrivateKey;
  let hubPublicKey: PublicKey;
  let hubResolvedDID: DidDocument;
  let hubKeys = {};
  let examplePublicKey: PublicKey;
  let exampleResolvedDID: DidDocument;
  let auth: Authentication;
  let registry = new CryptoFactory([new RsaCryptoSuite(), new AesCryptoSuite()]);
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
        controller: exampleDID,
        publicKeyJwk: examplePublicKey
      }],
      'authentication': [{
        type: 'RsaSignatureAuthentication2018',
        publicKey: `${exampleDID}#keys-1`
      }],
      'service': [{
        id: 'example-service',
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
        controller: hubDID,
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

  let authenticationRequest: AuthenticationRequest = {
    iss: hubDID,
    response_type: 'id_token',
    client_id: '',
    scope: 'openid',
    state: '',
    nonce: '123456789',
    claims: { id_token: {} }
  };

  beforeEach(async () => {
    const token = await newAccessToken();

    header = {
      'alg': 'RS256',
      'kid': `${exampleDID}#keys-1`,
      'did-access-token': token
    };

    setResolve(exampleDID, exampleResolvedDID);

    authenticationRequest = {
      iss: hubDID,
      response_type: 'id_token',
      client_id: 'https://example.com/endpoint/8377464',
      scope: 'openid',
      state: '',
      nonce: '123456789',
      claims: { id_token: {} }
    };
  });

  describe('signAuthenticationRequest', () => {

    it('should throw error when cannot find key for DID', async () => {
      authenticationRequest.iss = 'did:test:wrongdid';
      try {
        const context = await auth.signAuthenticationRequest(authenticationRequest);
        fail('Auth did not throw.');
        console.log(context);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it('should sign the request', async () => {
      const request = await auth.signAuthenticationRequest(authenticationRequest);
      const jws = new JwsToken(request, registry);
      const payload = await jws.verifySignature(hubPublicKey);
      expect(payload).toEqual(JSON.stringify(authenticationRequest));
    });

  });

  describe('verifyAuthenticationRequest', () => {

    it('should throw error when public key cannot be found', async () => {
      setResolve(hubDID, exampleResolvedDID);
      const request = await auth.signAuthenticationRequest(authenticationRequest);
      try {
        const context = await auth.verifyAuthenticationRequest(request);
        fail('Auth did not throw');
        console.log(context);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it('should throw error when signing DID does not match issuer', async () => {
      setResolve(hubDID, hubResolvedDID);
      authenticationRequest.iss = 'did:test:wrongdid';
      const token = new JwsToken(authenticationRequest, registry);
      const request = await token.sign(hubkey);
      try {
        const context = await auth.verifyAuthenticationRequest(request);
        fail('Auth did not throw');
        console.log(context);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });

    it('should verify the signed authentication request with request as string', async () => {
      setResolve(hubDID, hubResolvedDID);
      const request = await auth.signAuthenticationRequest(authenticationRequest);
      const context = await auth.verifyAuthenticationRequest(request);
      expect(context).toEqual(authenticationRequest);
    });

    it('should verify the signed authentication request with request as buffer', async () => {
      setResolve(hubDID, hubResolvedDID);
      const request = await auth.signAuthenticationRequest(authenticationRequest);
      const requestBuffer = Buffer.from(request);
      const context = await auth.verifyAuthenticationRequest(requestBuffer);
      expect(context).toEqual(authenticationRequest);
    });
  });

  describe('formAuthenticationResponse', () => {

    it('should form Authenticaiton Request from Authentication Response', async (done) => {
      setResolve(hubDID, hubResolvedDID);
      const response = await auth.formAuthenticationResponse(authenticationRequest, hubDID, { key: 'hello' });
      const jws = new JwsToken(response, registry);
      const payload = await jws.verifySignature(hubPublicKey);
      const payloadObj = JSON.parse(payload);

      expect(payloadObj.iss).toEqual('https://self-issued.me');
      expect(payloadObj.sub).toBeDefined();
      expect(payloadObj.aud).toEqual('https://example.com/endpoint/8377464');
      expect(payloadObj.nonce).toEqual('123456789');
      expect(payloadObj.sub_jwk).toEqual(hubPublicKey);
      expect(payloadObj.did).toEqual(hubDID);
      expect(payloadObj.iat).toBeDefined();
      expect(payloadObj.exp).toBeDefined();
      done();
    });

    it('should form Authenticaiton Request from Authentication Response with expiration', async () => {
      setResolve(hubDID, hubResolvedDID);
      const response = await auth.formAuthenticationResponse(authenticationRequest, hubDID, { key: 'hello' }, new Date());
      const jws = new JwsToken(response, registry);
      const payload = await jws.verifySignature(hubPublicKey);
      const payloadObj = JSON.parse(payload);
      expect(payloadObj.iss).toEqual('https://self-issued.me');
      expect(payloadObj.sub).toBeDefined();
      expect(payloadObj.aud).toEqual('https://example.com/endpoint/8377464');
      expect(payloadObj.nonce).toEqual('123456789');
      expect(payloadObj.sub_jwk).toEqual(hubPublicKey);
      expect(payloadObj.did).toEqual(hubDID);
      expect(payloadObj.iat).toBeDefined();
      expect(payloadObj.exp).toBeDefined();
    });

    it('should throw error because could not find a key for responseDid', async () => {
      setResolve(hubDID, hubResolvedDID);
      try {
        const response = await auth.formAuthenticationResponse(authenticationRequest, exampleDID, { key: 'hello' });
        fail('Auth did not throw');
        console.log(response);
      } catch (err) {
        expect(err).toBeDefined();
      }
    });
  });

  describe('verifyAuthenticationResponse', async () => {

    it('should verify an authentication response', async () => {
      setResolve(hubDID, hubResolvedDID);
      const response = await auth.formAuthenticationResponse(authenticationRequest, hubDID, { key: 'hello' });
      const payloadObj = await auth.verifyAuthenticationResponse(response);
      expect(payloadObj.iss).toEqual('https://self-issued.me');
      expect(payloadObj.sub).toBeDefined();
      expect(payloadObj.aud).toEqual('https://example.com/endpoint/8377464');
      expect(payloadObj.nonce).toEqual('123456789');
      expect(payloadObj.sub_jwk).toEqual(hubPublicKey);
      expect(payloadObj.did).toEqual(hubDID);
      expect(payloadObj.iat).toBeDefined();
      expect(payloadObj.exp).toBeDefined();
    });

    it('should verify an authentication response', async () => {
      setResolve(hubDID, hubResolvedDID);
      const response = await auth.formAuthenticationResponse(authenticationRequest, hubDID, { key: 'hello' });
      const responseBuffer = Buffer.from(response);
      const payloadObj = await auth.verifyAuthenticationResponse(responseBuffer);
      expect(payloadObj.iss).toEqual('https://self-issued.me');
      expect(payloadObj.sub).toBeDefined();
      expect(payloadObj.aud).toEqual('https://example.com/endpoint/8377464');
      expect(payloadObj.nonce).toEqual('123456789');
      expect(payloadObj.sub_jwk).toEqual(hubPublicKey);
      expect(payloadObj.did).toEqual(hubDID);
      expect(payloadObj.iat).toBeDefined();
      expect(payloadObj.exp).toBeDefined();
    });

    it('should throw an error for signer does not match issuer', async () => {
      setResolve(hubDID, hubResolvedDID);

      const milliseconds = 1000;
      const expirationTimeOffsetInMinutes = 5;
      const expiration = new Date(Date.now() + milliseconds * 60 * expirationTimeOffsetInMinutes);
      const iat = Math.floor(Date.now() / milliseconds); // ms to seconds

      const authenticationResponse: AuthenticationResponse = {
        iss: 'https://self-issued.me',
        sub: 'did:test:wrongdid',
        aud: 'https://example.com/endpoint/8377464',
        nonce: '123456789',
        exp: Math.floor(expiration.getTime() / milliseconds),
        iat: iat,
        sub_jwk: hubPublicKey,
        did: 'did:test:wrongdid',
        state: ''
      };

      const token = new JwsToken(authenticationResponse, registry);
      const request = await token.sign(hubkey);
      try {
        const context = await auth.verifyAuthenticationResponse(request);
        fail('Auth did not throw');
        console.log(context);
      } catch (err) {
        console.log(err);
        expect(err).toBeDefined();
      }
    });
  });

  describe('getVerifiedRequest', () => {

    it('should reject for hub keys it does not contain', async () => {
      const payload = {
        description: 'Authentication test'
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

      const unknownPublicKey = await PrivateKeyRsa.generatePrivateKey(`${exampleDID}#unknown-key`);

      const data = await jws.sign(unknownPublicKey);

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
              controller: hubDID,
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

    it(`should encrypt with the DID's public key`, async () => {
      const content = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();
      const request = await auth.getAuthenticatedRequest(content, exampleDID, await newAccessToken(examplekey));
      const jwe = registry.constructJwe(request.toString());
      const jwsstring = await jwe.decrypt(examplekey);
      const jws = registry.constructJws(jwsstring);
      expect(jws.getPayload()).toEqual(content);
    });

  });

  describe('getAuthenticatedResponse', () => {
    fit('should be understood by decrypt and validate', async () => {
      const requestString = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();

      setResolve(hubDID, hubResolvedDID);

      const request = await auth.getAuthenticatedRequest(requestString, hubDID, header['did-access-token']);

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
