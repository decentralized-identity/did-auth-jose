import { DidDocument, IDidResolver } from '@decentralized-identity/did-common-typescript';
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
import AesCryptoSuite from './crypto/aes/AesCryptoSuite';
import IKeyStore from './keyStore/IKeyStore';
import KeyStoreMem from './keyStore/KeyStoreMem';
import { ProtectionFormat } from './keyStore/ProtectionFormat';

/**
 * Named arguments to construct an Authentication object
 */
export interface AuthenticationOptions {
  /** An object with the did document key id mapping to private keys */
  keys?: {[name: string]: PrivateKey};
  /** A dictionary with the did document key id mapping to private key references in the keystore */
  keyReferences?: string[];
  /** The keystore */
  keyStore?: IKeyStore;
  /** DID Resolver used to retrieve public keys */
  resolver: IDidResolver;
  /** Optional parameter to customize supported CryptoSuites */
  cryptoSuites?: CryptoSuite[];
  /** Optional parameter to change the amount of time a token is valid in minutes */
  tokenValidDurationInMinutes?: number;
}

/**
 * Class for decrypting and verifying, or signing and encrypting content in an End to End DID Authentication format
 */
export default class Authentication {

  // TODO need to support encryption and signature keys

  /** DID Resolver used to retrieve public keys */
  private resolver: IDidResolver;
  /** The amount of time a token is valid in minutes */
  private tokenValidDurationInMinutes: number;
  /** Private keys of the authentication owner */
  private keys?: {[name: string]: PrivateKey};
  /** Reference to Private keys of the authentication owner */
  private keyReferences?: string[];
  /** The keystore */
  private keyStore: IKeyStore;
  /** Factory for creating JWTs and public keys */
  private factory: CryptoFactory;

  /**
   * Authentication constructor
   * @param options Arguments to a constructor in a named object
   */
  constructor (options: AuthenticationOptions) {
    this.resolver = options.resolver;
    this.tokenValidDurationInMinutes = options.tokenValidDurationInMinutes || Constants.defaultTokenDurationInMinutes;
    if (options.keyStore) {
      this.keyStore = options.keyStore;
    } else {
      this.keyStore = new KeyStoreMem();
    }
    this.keys = options.keys;
    this.keyReferences = options.keyReferences;

    if (!this.keys && !this.keyReferences) {
      throw new Error(`A key by reference (keyReferences) or a key by value (keys) is required`);
    }

    if (this.keys && Object.keys(this.keys).length > 0 && (this.keyReferences && this.keyReferences.length > 0)) {
      throw new Error(`Do not mix a key by reference (keyReferences) with a key by value (keys) is required`);
    }

    this.factory = new CryptoFactory(options.cryptoSuites || [new AesCryptoSuite(), new RsaCryptoSuite(), new Secp256k1CryptoSuite()]);
  }

  /**
   * Signs the AuthenticationRequest with the private key of the Requester and returns the signed JWT.
   * @param request well-formed AuthenticationRequest object
   * @returns the signed compact JWT.
   */
  public async signAuthenticationRequest (request: AuthenticationRequest): Promise<string> {
    if (request.response_type !== 'id_token' || request.scope !== 'openid') {
      throw new Error('Authentication Request not formed correctly');
    }

    // Make sure the passed in key is stored in the key store
    let referenceToStoredKey: string;
    if (this.keyReferences && this.keyReferences.length > 0) {
      // for signing always use last key
      referenceToStoredKey = this.keyReferences[this.keyReferences.length - 1];
    } else {
      referenceToStoredKey = await this.getKeyReference(request.iss);
    }
    return this.keyStore.sign(referenceToStoredKey, JSON.stringify(request), ProtectionFormat.CompactJsonJws, this.factory);
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
   * @param keyReference pointing to the signing key
   */
  public async formAuthenticationResponse (authRequest: AuthenticationRequest, responseDid: string, claims: any, expiration?: Date)
  : Promise<string> {
    const referenceToStoredKey = await this.getKeyReference(responseDid);

    const publicKey: PublicKey = await this.keyStore.get(referenceToStoredKey, true) as PublicKey;
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
    return this.keyStore.sign(referenceToStoredKey, JSON.stringify(response), ProtectionFormat.CompactJsonJws, this.factory, {
      iat: iat.toString(),
      exp: Math.floor(expiration.getTime() / milliseconds).toString()
    });
  }

  /**
   * Return a reference to the private key that was passed by caller.
   * If the key was passed in by value, it will be stored in the store and a reference is returned
   * @param iss Issuer identifier
   */
  private async getKeyReference (iss: string): Promise<string> {
    let referenceToStoredKey: string;
    if (this.keys && Object.keys(this.keys).length > 0 ) {
      const key: PrivateKey | undefined = this.getKey(iss);
      if (!key) {
        throw new Error(`Could not find a key for ${iss}`);
      }
      referenceToStoredKey = key.kid;
      await this.keyStore.save(referenceToStoredKey, key);
    } else {
      throw new Error(`No private keys passed`);
    }
    return referenceToStoredKey;
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
    const keyReference = await this.getPrivateKeyForJwe(jweToken);
    const jwsString = await this.keyStore.decrypt(keyReference, requestString, ProtectionFormat.CompactJsonJwe, this.factory);
    const jwsToken = this.factory.constructJws(jwsString);

    // getting metadata for the request
    const jwsHeader = jwsToken.getHeader();
    const requestKid = jwsHeader.kid;
    const requesterDocument = await this.getSignerDidDocumentFromJws(jwsToken);
    const requester = DidDocument.getDidFromKeyId(requestKid);
    const requesterKey = await this.getPublicKey(jwsToken, requesterDocument);
    const nonce = this.getRequesterNonce(jwsToken);

    const requesterKeys = await this.convertPublicKeys(requesterDocument);

    // Get the public key for validation
    const localPublicKey = await this.keyStore.get(keyReference, true) as PublicKey;

    if (accessTokenCheck) {
      // verify access token
      const accessTokenString = jwsHeader['did-access-token'];
      if (!accessTokenString) {
        // no access token was given, this should be a seperate endpoint request
        return this.issueNewAccessToken(requester, nonce, keyReference, requesterKeys);
      }

      if (!await this.verifyJwt(localPublicKey, accessTokenString, requester)) {
        throw new Error('Invalid access token');
      }
    }

    const plaintext = await jwsToken.verifySignature(requesterKey);

    return {
      localKeyId: localPublicKey.kid,
      requesterPublicKey: requesterKey,
      requesterPublicKeys: requesterKeys,
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
    return this.signThenEncryptInternal(request.nonce, request.requesterPublicKeys, response);
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
    recipient: string,
    accessToken?: string
  ): Promise<Buffer> {
    const requesterNonce = uuid();

    const result = await this.resolver.resolve(recipient);
    const document: DidDocument = result.didDocument;
    const publicKeys = await this.convertPublicKeys(document);

    return this.signThenEncryptInternal(requesterNonce, publicKeys, content, accessToken);
  }

  /**
   * Given a JWE, retrieves the PrivateKey to be used for decryption
   * @param jweToken The JWE to inspect
   * @returns The PrivateKey corresponding to the JWE's encryption
   */
  private async getPrivateKeyForJwe (jweToken: JweToken): Promise<string> {
    const keyId = jweToken.getHeader().kid;
    if (this.keys && Object.keys(this.keys).length > 0) {
      const key = this.keys[keyId];
      if (!key) {
        throw new Error(`Unable to decrypt request; encryption key '${keyId}' not found`);
      }
      await this.keyStore.save(keyId, key);
      return keyId;
    } else {
      if (!this.keyReferences) {
        throw new Error(`Missing key reference for decrypting jwe`);
      }
      const allKeys = await this.keyStore.list();
      let keyReferences = this.keyReferences.filter((reference) => allKeys[reference] && allKeys[reference] === keyId);
      if (!keyReferences) {
        throw new Error(`Key reference for decrypting jwe not found`);
      }
      return keyReferences[0];
    }
  }

  /**
   * Given an array of public keys, returns a key with use 'enc'
   * @param publicKeys Array of public keys
   * @returns a public key with encryption use
   */
  private selectEncryptionKey (publicKeys: PublicKey[]): PublicKey {
    let encryptionKey: PublicKey | undefined = undefined;
    publicKeys.forEach((key) => {
      if (encryptionKey !== undefined) {
        return;
      }
      // RFC 7517 4.2 values defined are case-sensitive "enc" and "sig"
      if (key.use && key.use === 'enc') {
        encryptionKey = key;
      }
    });
    if (!encryptionKey) {
      throw new Error('Could not find a usable encryption key');
    } else {
      return encryptionKey;
    }
  }

  /**
   * Gets @See PublicKey array from a @see DidDocument
   * @param document DID Document to convert public keys from
   * @returns an array of all understood public keys
   */
  private async convertPublicKeys (document: DidDocument): Promise<PublicKey[]> {
    let documentKeys: PublicKey[] = [];
    document.publicKey.forEach((key) => {
      try {
        const publicKey = this.factory.constructPublicKey(key);
        documentKeys.push(publicKey);
      } catch (error) {
        console.log(`Unable to interpret key ${key.id}: ${error.message}`);
      }
    });
    return documentKeys;
  }

  /**
   * Retrieves the PublicKey used to sign a JWS
   * @param request the JWE string
   * @returns The PublicKey the JWS used for signing
   */
  private async getPublicKey (jwsToken: JwsToken, document: DidDocument): Promise<PublicKey> {
    const jwsHeader = jwsToken.getHeader();
    const requestKid = jwsHeader.kid;
    const documentKey = document.getPublicKey(requestKid);
    if (!documentKey) {
      throw new Error(`Unable to verify request; signature key ${requestKid} not found`);
    }
    return this.factory.constructPublicKey(documentKey);
  }

  /**
   * Gets the DID document of the signer of the JWS token
   * @param jwsToken JWS token in which to get the DID Document of the signing key
   * @returns the Signers DID Document
   */
  private async getSignerDidDocumentFromJws (jwsToken: JwsToken): Promise<DidDocument> {
    const jwsHeader = jwsToken.getHeader();
    const requestKid = jwsHeader.kid;
    const requester = DidDocument.getDidFromKeyId(requestKid);
    const result = await this.resolver.resolve(requester);
    return result.didDocument;
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
   * @param requesterkeys PublicKeys in which to find one to encrypt the response
   * @param content The content to be signed and encrypted
   * @returns An encrypted and signed form of the content
   */
  private async signThenEncryptInternal (
    nonce: string,
    requesterkeys: PublicKey[],
    content: string,
    accesstoken?: string
  ): Promise<Buffer> {

    const requesterkey = this.selectEncryptionKey(requesterkeys);

    const jwsHeaderParameters: any = { 'did-requester-nonce': nonce };
    if (accesstoken) {
      jwsHeaderParameters['did-access-token'] = accesstoken;
    }
    // Make sure the passed in key is stored in the key store
    let referenceToStoredKey: string;
    if (this.keyReferences && this.keyReferences.length > 0) {
      // for signing always use last key
      referenceToStoredKey = await new Promise<string>((resolve, reject) => {
        let signingKey: string | undefined = undefined;
        this.keyReferences!.forEach(async (keyReference) => {
          if (signingKey !== undefined) {
            return;
          } else {
            const key = await this.keyStore.get(keyReference, true);
            if (key instanceof PublicKey) {
              // RFC 7517 4.2 values defined are case-sensitive "enc" and "sig"
              if (key.use && key.use === 'sig') {
                signingKey = keyReference;
                resolve(keyReference);
              }
            }
          }
        });
        reject('Could not find a key with use equal to sig');
      });
    } else {
      if (!this.keys) {
        throw new Error(`No private keys passed into Authentication`);
      }

      const kid = await new Promise<string>((resolve, reject) => {
        let signingKey: PrivateKey | undefined = undefined;
        Object.values(this.keys!).forEach((key) => {
          if (signingKey !== undefined) {
            return;
          } else {
            // RFC 7517 4.2 values defined are case-sensitive "enc" and "sig"
            if (key.use && key.use === 'sig') {
              signingKey = key;
              resolve(key.kid);
            }
          }
        });
        reject('Could nto find a key with use equal to sig');
      });
      referenceToStoredKey = await this.getKeyReference(kid);
    }

    const jwsCompactString = await this.keyStore.sign(referenceToStoredKey, content, ProtectionFormat.CompactJsonJws, this.factory, jwsHeaderParameters);
    const jweToken = this.factory.constructJwe(jwsCompactString);

    return jweToken.encrypt(requesterkey);
  }

  /**
   * Creates a new access token and wrap it in a JWE/JWS pair.
   * @param subjectDid the DID this access token is issue to
   * @param nonce the nonce used in the original request
   * @param issuerKeyReference A reference to the key used in the original request
   * @param requesterKey the requesters key to encrypt the response with
   * @returns A new access token
   */
  private async issueNewAccessToken (subjectDid: string, nonce: string, issuerKeyReference: string, requesterKeys: PublicKey[])
    : Promise<Buffer> {
    // Create a new access token.
    const accessToken = await this.createAccessToken(subjectDid, issuerKeyReference, this.tokenValidDurationInMinutes);

    // Sign then encrypt the new access token.
    return this.signThenEncryptInternal(nonce, requesterKeys, accessToken);
  }

  /**
   * Creates an access token for the subjectDid using the privateKey for the validDurationInMinutes
   * @param subjectDid The did this access token is issued to
   * @param privateKeyReference The private key used to generate this access token
   * @param validDurationInMinutes The duration this token is valid for, in minutes
   * @returns Signed JWT in compact serialized format.
   */
  private async createAccessToken (subjectDid: string, privateKeyReference: string, validDurationInMinutes: number): Promise<string> {
    const payload: any = this.factory.constructJws({
      sub: subjectDid,
      iat: new Date(Date.now()),
      exp: new Date(Date.now() + validDurationInMinutes * 60 * 1000)
    });
    return this.keyStore.sign(privateKeyReference, payload.content, ProtectionFormat.CompactJsonJws, this.factory);
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
