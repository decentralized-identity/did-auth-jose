import { DidDocument, DidResolver } from '@decentralized-identity/did-common-typescript';
import PrivateKey from './security/PrivateKey';
import CryptoSuite from './interfaces/CryptoSuite';
import Constants from './Constants';
import PublicKey from './security/PublicKey';
import CryptoFactory from './CryptoFactory';
import { RsaCryptoSuite } from './crypto/rsa/RsaCryptoSuite';
import JweToken from './security/JweToken';
import JwsToken from './security/JwsToken';
import uuid from 'uuid/v4';
import VerifiedRequest from './interfaces/VerifiedRequest';
import VerifiedResponse from './interfaces/VerifiedResponse';
import Challenge from './interfaces/Challenge';
import ChallengeResponse from './interfaces/ChallengeResponse';

/**
 * Named arguments to construct an Authentication object
 */
export interface AuthenticationOptions {
  /** A dictionary with the did document key id mapping to private keys */
  keys: {[name: string]: PrivateKey};
  /** DID Resolver used to retrieve public keys */
  resolver: DidResolver;
  /** Optional parameter to customize supported CryptoSuites */
  cryptoSuites?: CryptoSuite[];
  /** Optional parameter to change the amount of time a token is valid in minutes */
  tokenValidDurationInMinutes?: number;
}

/**
 * Class for decrypting and verifying, or signing and encrypting content in an End to End DID Authentication format
 */
export default class Authentication {

  /** DID Resolver used to retrieve public keys */
  private resolver: DidResolver;
  /** The amount of time a token is valid in minutes */
  private tokenValidDurationInMinutes: number;
  /** Private keys of the authentication owner */
  private keys: {[name: string]: PrivateKey};
  /** Factory for creating JWTs and public keys */
  private factory: CryptoFactory;

  /**
   * Authentication constructor
   * @param options Arguments to a constructor in a named object
   */
  constructor (options: AuthenticationOptions) {
    this.resolver = options.resolver;
    this.tokenValidDurationInMinutes = options.tokenValidDurationInMinutes || Constants.defaultTokenDurationInMinutes;
    this.keys = options.keys;
    this.factory = new CryptoFactory(options.cryptoSuites || [new RsaCryptoSuite()]);
  }

  /** Serializes challenges */
  public async formChallenge(challenge: Challenge): Promise<string> {
    // identity function in place of later signing
    return JSON.stringify(challenge);
  }

  /** Deserializes challenges */
  public async getChallenge(challenge: Buffer | string): Promise<Challenge> {
    // identity function in place of later signature verification
    let challengeString: string;
    if (challenge instanceof Buffer) {
      challengeString = challenge.toString();
    } else {
      challengeString = challenge;
    }
    return JSON.parse(challengeString);
  }

  /**
   * Given a challenge, forms a signed response using a given DID that expires at expiration, or a default expiration.
   * @param challenge Challenge to respond to
   * @param responseDid The DID to respond with
   * @param expiration optional expiration datetime of the response
   */
  public async formChallengeResponse (challenge: Challenge, responseDid: string, expiration?: Date): Promise<string> {
    let key: PrivateKey | undefined;
    for (const keyId in this.keys) {
      if (keyId.startsWith(responseDid)) {
        key = this.keys[keyId];
        break;
      }
    }
    if (!key) {
      throw new Error(`Could not find a key for ${responseDid}`);
    }

    // milliseconds to seconds
    const milliseconds = 1000;
    if (!expiration) {
      const expirationTimeOffsetInMinutes = 5;
      expiration = new Date(Date.now() + milliseconds * 60 * expirationTimeOffsetInMinutes); // 5 minutes from now
    }
    const iat = Math.floor(Date.now() / milliseconds); // ms to seconds
    const response: ChallengeResponse = {
      iat,
      iss: responseDid,
      aud: challenge.client_id,
      exp: Math.floor(expiration.getTime() / milliseconds),
      nonce: challenge.nonce,
      state: challenge.state
    };

    const token = new JwsToken(response, this.factory);
    return token.sign(key, {
      iat: iat.toString(),
      exp: Math.floor(expiration.getTime() / milliseconds).toString()
    });
  }

  /**
   * Verifies the signature on a challengeResponse and returns a ChallengeResponse object
   * @param challengeResponse ChallengeResponse to verify as a string or buffer
   * @returns the challengeResponse as a ChallengeResponse
   */
  public async verifyChallengeResponse (challengeResponse: Buffer | string): Promise<ChallengeResponse> {
    const clockSkew = 5 * 60 * 1000; // 5 minutes
    let jwsToken: JwsToken;
    if (challengeResponse instanceof Buffer) {
      jwsToken = new JwsToken(challengeResponse.toString(), this.factory);
    } else {
      jwsToken = new JwsToken(challengeResponse, this.factory);
    }
    const exp = jwsToken.getHeader().exp;
    if (exp) {
      if (exp * 1000 + clockSkew < Date.now()) {
        throw new Error('Response expired');
      }
    }
    const keyId = jwsToken.getHeader().kid;
    const keyDid = DidDocument.getDidFromKeyId(keyId);
    const results = await this.resolver.resolve(keyDid);
    const didPublicKey = results.didDocument.getPublicKey(keyId);
    if (!didPublicKey) {
      throw new Error('Could not find public key');
    }
    const publicKey = this.factory.constructPublicKey(didPublicKey);
    const content = await jwsToken.verifySignature(publicKey);
    const response: ChallengeResponse = JSON.parse(content);
    if (response.iss !== keyDid) {
      throw new Error('Signing DID does not match issuer');
    }
    return response;
  }

  /**
   * Given a JOSE Authenticated Request, will decrypt the request, resolve the requester's did, and validate the signature.
   * @param request The JOSE Authenticated Request to decrypt and validate
   * @param accessTokenCheck Check the validity of the access token
   * @returns The content of the request as a VerifiedRequest, or a response containing an access token
   */
  public async getVerifiedRequest (request: Buffer, accessTokenCheck: boolean = true): Promise<VerifiedRequest | Buffer> {
    // Load the key specified by 'kid' in the JWE header.
    const requestString = request.toString();
    const jweToken = this.factory.constructJwe(requestString);
    const localKey = this.getPrivateKeyForJwe(jweToken);
    const jwsString = await jweToken.decrypt(localKey);
    const jwsToken = this.factory.constructJws(jwsString);

    // getting metadata for the request
    const jwsHeader = jwsToken.getHeader();
    const requestKid = jwsHeader.kid;
    const requester = DidDocument.getDidFromKeyId(requestKid);
    const requesterKey = await this.getPublicKey(jwsToken);
    const nonce = this.getRequesterNonce(jwsToken);

    if (accessTokenCheck) {
      // verify access token
      const accessTokenString = jwsHeader['did-access-token'];
      if (!accessTokenString) {
        // no access token was given, this should be a seperate endpoint request
        return this.issueNewAccessToken(requester, nonce, localKey, requesterKey);
      }
      if (!await this.verifyJwt(localKey, accessTokenString, requester)) {
        throw new Error('Invalid access token');
      }
    }

    const plaintext = await jwsToken.verifySignature(requesterKey);

    return {
      localKeyId: localKey.kid,
      requesterPublicKey: requesterKey,
      nonce,
      request: plaintext
    };
  }

  /**
   * Given a JOSE Authenticated Response, decrypts and validates the response
   * @param request THe JOSE Authenticated Response
   * @returns the content of the response as a VerifiedResponse
   */
  public async getVerifiedResponse (request: Buffer): Promise <VerifiedResponse> {
    const response = await this.getVerifiedRequest(request, false);
    if (response instanceof Buffer) {
      // this should never happen
      throw new Error('Response verification required an authorization token');
    }
    return {
      localKeyId: response.localKeyId,
      responderPublicKey: response.requesterPublicKey,
      nonce: response.nonce,
      response: response.request
    };
  }

  /**
   * Given the verified request, uses the same keys and metadata to sign and encrypt the response
   * @param request The original JOSE Verified Request request
   * @param response The plaintext response to be signed and encrypted
   * @returns An encrypted and signed form of the response
   */
  public async getAuthenticatedResponse (
    request: VerifiedRequest,
    response: string): Promise<Buffer> {

    const localkey = this.keys[request.localKeyId];
    if (!localkey) {
      throw new Error('Unable to find encryption key used');
    }

    return this.signThenEncryptInternal(request.nonce, localkey, request.requesterPublicKey, response);
  }

  /**
   * Creates an encrypted and authenticated JOSE request
   * @param content the content of the request
   * @param privateKey the private key to sign with
   * @param recipient the DID the request is indended for
   * @param accessToken an access token to be used with the other party
   */
  public async getAuthenticatedRequest (
    content: string,
    privateKey: PrivateKey,
    recipient: string,
    accessToken?: string
  ): Promise<Buffer> {

    const requesterNonce = uuid();

    const result = await this.resolver.resolve(recipient);
    const document: DidDocument = result.didDocument;

    if (!document.publicKey) {
      throw new Error(`Could not find public keys for ${recipient}`);
    }

    // perhaps a more intellegent key choosing algorithm could be implemented here
    const documentKey = document.publicKey[0];

    const publicKey = this.factory.constructPublicKey(documentKey);

    return this.signThenEncryptInternal(requesterNonce, privateKey, publicKey, content, accessToken);
  }

  /**
   * Given a JWE, retrieves the PrivateKey to be used for decryption
   * @param jweToken The JWE to inspect
   * @returns The PrivateKey corresponding to the JWE's encryption
   */
  private getPrivateKeyForJwe (jweToken: JweToken): PrivateKey {
    const keyId = jweToken.getHeader().kid;
    const key = this.keys[keyId];
    if (!key) {
      throw new Error(`Unable to decrypt request; encryption key '${keyId}' not found`);
    }
    return key;
  }

  /**
   * Retrieves the PublicKey used to sign a JWS
   * @param request the JWE string
   * @returns The PublicKey the JWS used for signing
   */
  private async getPublicKey (jwsToken: JwsToken): Promise<PublicKey> {
    const jwsHeader = jwsToken.getHeader();
    const requestKid = jwsHeader.kid;
    const requester = DidDocument.getDidFromKeyId(requestKid);

    // get the Public Key
    const result = await this.resolver.resolve(requester);
    const document: DidDocument = result.didDocument;
    const documentKey = document.getPublicKey(requestKid);
    if (!documentKey) {
      throw new Error(`Unable to verify request; signature key ${requestKid} not found`);
    }
    return this.factory.constructPublicKey(documentKey);
  }

  /**
   * Retrieves the nonce from the JWS
   * @param jwsToken The JWS containing the nonce
   * @returns The nonce
   */
  private getRequesterNonce (jwsToken: JwsToken): string {
    return jwsToken.getHeader()['did-requester-nonce'];
  }

  /**
   * Forms a JWS using the local private key and content, then wraps in JWE using the requesterKey and nonce.
   * @param nonce Nonce to be included in the response
   * @param localKey PrivateKey in which to sign the response
   * @param requesterkey PublicKey in which to encrypt the response
   * @param content The content to be signed and encrypted
   * @returns An encrypted and signed form of the content
   */
  private async signThenEncryptInternal (
    nonce: string,
    localKey: PrivateKey,
    requesterkey: PublicKey,
    content: string,
    accesstoken?: string
  ): Promise<Buffer> {
    const jwsHeaderParameters: any = { 'did-requester-nonce': nonce };
    if (accesstoken) {
      jwsHeaderParameters['did-access-token'] = accesstoken;
    }

    const jwsToken = this.factory.constructJws(content);
    const jwsCompactString = await jwsToken.sign(localKey, jwsHeaderParameters);

    const jweToken = this.factory.constructJwe(jwsCompactString);

    return jweToken.encrypt(requesterkey);
  }

  /**
   * Creates a new access token and wrap it in a JWE/JWS pair.
   * @param subjectDid the DID this access token is issue to
   * @param nonce the nonce used in the original request
   * @param issuerKey the key used in the original request
   * @param requesterKey the requesters key to encrypt the response with
   * @returns A new access token
   */
  private async issueNewAccessToken (subjectDid: string, nonce: string, issuerKey: PrivateKey, requesterKey: PublicKey)
    : Promise<Buffer> {
    // Create a new access token.
    const accessToken = await this.createAccessToken(subjectDid, issuerKey, this.tokenValidDurationInMinutes);

    // Sign then encrypt the new access token.
    return this.signThenEncryptInternal(nonce, issuerKey, requesterKey, accessToken);
  }

  /**
   * Creates an access token for the subjectDid using the privateKey for the validDurationInMinutes
   * @param subjectDid The did this access token is issued to
   * @param privateKey The private key used to generate this access token
   * @param validDurationInMinutes The duration this token is valid for, in minutes
   * @returns Signed JWT in compact serialized format.
   */
  private async createAccessToken (subjectDid: string, privateKey: PrivateKey, validDurationInMinutes: number): Promise<string> {
    return this.factory.constructJws({
      sub: subjectDid,
      iat: new Date(Date.now()),
      exp: new Date(Date.now() + validDurationInMinutes * 60 * 1000)
    }).sign(privateKey);
  }

  /**
   * Verifies:
   * 1. JWT signature.
   * 2. Token's subject matches the given requeter DID.
   * 3. Token is not expired.
   *
   * @param publicKey Public key used to verify the given JWT in JWK JSON object format.
   * @param signedJwtString The signed-JWT string.
   * @param expectedRequesterDid Expected requester ID in the 'sub' field of the JWT payload.
   * @returns true if token passes all validation, false otherwise.
   */
  private async verifyJwt (publicKey: PublicKey, signedJwtString: string, expectedRequesterDid: string): Promise<boolean> {
    if (!publicKey || !signedJwtString || !expectedRequesterDid) {
      return false;
    }

    try {
      const jwsToken = this.factory.constructJws(signedJwtString);

      const verifiedData = await jwsToken.verifySignature(publicKey);

      // Verify that the token was issued to the same person making the current request.
      const token = JSON.parse(verifiedData);
      if (token.sub !== expectedRequesterDid) {
        return false;
      }

      // Verify that the token is not expired.
      const now = new Date(Date.now());
      const expiry = new Date(token.exp);
      if (now > expiry) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }
}
