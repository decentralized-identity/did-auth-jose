import { DidDocument, DidResolver } from '@decentralized-identity/did-common-typescript';
import PrivateKey from './security/PrivateKey';
import CryptoSuite from './interfaces/CryptoSuite';
import Constants from './Constants';
import PublicKey from './security/PublicKey';
import CryptoFactory from './CryptoFactory';
import { RsaCryptoSuite } from './crypto/rsa/RsaCryptoSuite';
import { Secp256k1CryptoSuite } from './crypto/ec/Secp256k1CryptoSuite';
import JweToken from './security/JweToken';
import JwsToken from './security/JwsToken';
import uuid from 'uuid/v4';
import VerifiedRequest from './interfaces/VerifiedRequest';
import AuthenticationRequest from './interfaces/AuthenticationRequest';
import AuthenticationResponse from './interfaces/AuthenticationResponse';

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
    this.factory = new CryptoFactory(options.cryptoSuites || [new RsaCryptoSuite(), new Secp256k1CryptoSuite()]);
  }

  /**
   * Signs the AuthenticationRequest with the private key of the Requester and returns the signed JWT.
   * @param request well-formed AuthenticationRequest object
   * @param responseDid DID of the requester.
   */
  public async signAuthenticationRequest (request: AuthenticationRequest): Promise<string> {
    if (request.response_type !== 'id_token' || request.scope !== 'openid') {
      throw new Error('Authentication Request not formed correctly');
    }
    const requesterDid = request.iss;
    const key: PrivateKey | undefined = this.getKey(requesterDid);
    if (!key) {
      throw new Error(`Could not find a key for ${requesterDid}`);
    }

    const token = new JwsToken(request, this.factory);
    return token.sign(key);
  }

  /**
   * Verifies signature on request and returns AuthenticationRequest.
   * @param request Authentiation Request as a buffer or string.
   */
  public async verifyAuthenticationRequest (request: Buffer | string): Promise<AuthenticationRequest> {
    let jwsToken: JwsToken;
    if (request instanceof Buffer) {
      jwsToken = new JwsToken(request.toString(), this.factory);
    } else {
      jwsToken = new JwsToken(request, this.factory);
    }
    const keyId = jwsToken.getHeader().kid;
    const keyDid = DidDocument.getDidFromKeyId(keyId);
    const content = await this.verifySignature(jwsToken);

    const verifiedRequest: AuthenticationRequest = JSON.parse(content);
    if (verifiedRequest.iss !== keyDid) {
      throw new Error('Signing DID does not match issuer');
    }
    return verifiedRequest;
  }

  /**
   * Given a challenge, forms a signed response using a given DID that expires at expiration, or a default expiration.
   * @param authRequest Challenge to respond to
   * @param responseDid The DID to respond with
   * @param claims Claims that the requester asked for
   * @param expiration optional expiration datetime of the response
   */
  public async formAuthenticationResponse (authRequest: AuthenticationRequest, responseDid: string, claims: any, expiration?: Date): Promise<string> {
    const key: PrivateKey | undefined = this.getKey(responseDid);
    if (!key) {
      throw new Error(`Could not find a key for ${responseDid}`);
    }

    const publicKey: PublicKey = key.getPublicKey();
    const base64UrlThumbprint = await PublicKey.getThumbprint(publicKey);

    // milliseconds to seconds
    const milliseconds = 1000;
    if (!expiration) {
      const expirationTimeOffsetInMinutes = 5;
      expiration = new Date(Date.now() + milliseconds * 60 * expirationTimeOffsetInMinutes); // 5 minutes from now
    }
    const iat = Math.floor(Date.now() / milliseconds); // ms to seconds
    let response: AuthenticationResponse = {
      iss: 'https://self-issued.me',
      sub: base64UrlThumbprint,
      aud: authRequest.client_id,
      nonce: authRequest.nonce,
      exp: Math.floor(expiration.getTime() / milliseconds),
      iat,
      sub_jwk: publicKey,
      did: responseDid,
      state: authRequest.state
    };

    response = Object.assign(response, claims);

    const token = new JwsToken(response, this.factory);
    return token.sign(key, {
      iat: iat.toString(),
      exp: Math.floor(expiration.getTime() / milliseconds).toString()
    });
  }

  /**
   * Private method that gets the private key of the DID from the key mapping.
   * @param did the DID whose private key is used to sign JWT.
   * @returns private key of the DID.
   */
  private getKey (did: string): PrivateKey | undefined {
    let key: PrivateKey | undefined;
    for (const keyId in this.keys) {
      if (keyId.startsWith(did)) {
        key = this.keys[keyId];
        break;
      }
    }
    return key;
  }

  /**
   * helper method that verifies the signature on jws and returns the payload if signature is verified.
   * @param jwsToken signed jws token whose signature will be verified.
   * @returns the payload if jws signature is verified.
   */
  private async verifySignature (jwsToken: JwsToken): Promise<string> {
    const keyId = jwsToken.getHeader().kid;
    const keyDid = DidDocument.getDidFromKeyId(keyId);
    const results = await this.resolver.resolve(keyDid);
    const didPublicKey = results.didDocument.getPublicKey(keyId);
    if (!didPublicKey) {
      throw new Error('Could not find public key');
    }
    const publicKey = this.factory.constructPublicKey(didPublicKey);
    return jwsToken.verifySignature(publicKey);
  }

  /**
   * Verifies the signature on a AuthenticationResponse and returns a AuthenticationResponse object
   * @param authResponse AuthenticationResponse to verify as a string or buffer
   * @returns the authenticationResponse as a AuthenticationResponse Object
   */
  public async verifyAuthenticationResponse (authResponse: Buffer | string): Promise<AuthenticationResponse> {
    const clockSkew = 5 * 60 * 1000; // 5 minutes
    let jwsToken: JwsToken;
    if (authResponse instanceof Buffer) {
      jwsToken = new JwsToken(authResponse.toString(), this.factory);
    } else {
      jwsToken = new JwsToken(authResponse, this.factory);
    }
    const exp = jwsToken.getHeader().exp;
    if (exp) {
      if (exp * 1000 + clockSkew < Date.now()) {
        throw new Error('Response expired');
      }
    }
    const keyId = jwsToken.getHeader().kid;
    const keyDid = DidDocument.getDidFromKeyId(keyId);
    const content = await this.verifySignature(jwsToken);
    const response: AuthenticationResponse = JSON.parse(content);
    if (response.did !== keyDid) {
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
