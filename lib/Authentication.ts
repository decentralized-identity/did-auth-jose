import { DidDocument, DidResolver } from 'did-common-typescript';
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
      if (!this.verifyJwt(localKey, accessTokenString, requester)) {
        throw new Error('Invalid access token');
      }
    }

    const plaintext = jwsToken.verifySignature(requesterKey);

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
  private verifyJwt (publicKey: PublicKey, signedJwtString: string, expectedRequesterDid: string): boolean {
    if (!publicKey || !signedJwtString || !expectedRequesterDid) {
      return false;
    }

    try {
      const jwsToken = this.factory.constructJws(signedJwtString);

      const verifiedData = jwsToken.verifySignature(publicKey);

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
