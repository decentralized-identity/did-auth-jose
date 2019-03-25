/**
 * Node packages
 */
import { HttpResolver } from '@decentralized-identity/did-common-typescript';
const didAuth = require('@decentralized-identity/did-auth-jose');

/**
 * Constants
 */
const discoveryEndpoint = 'HTTP_RESOLVER_ENDPOINT_HERE'; // e.g. https://beta.discover.did.microsoft.com/
const REDIRECT_URL = 'server.example.com'; // server url that client will send Authentication Response to
const state = 'af0ifjsldkj'; // Base64Encoded opaque box for the server to put information (e.g. session id)
const nonce = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString(16); // nonce created server-side

/**
 * Fill in the server DID to use
 */
const DID = 'YOUR_SERVER_DID_HERE';

/**
 * Fill in your full private key, including the `kid` field. The key must:
 * - Be an RSA private key in JWK format
 * - Match one of the public keys registered for your DID
 * - Include a "kid" field with the plain (not fully-qualified) key ID, e.g. "key-1"
 */
const PRIVATE_KEY = { kid: 'key-1' };

/**
 * Wrap the private key with new kid that includes the DID.
 */
const kid = `${DID}${PRIVATE_KEY.kid}`;
const privateKey = didAuth.RsaPrivateKey.wrapJwk(kid, PRIVATE_KEY);

/**
 * Create a keys object that contains (kid, privateKey) key-value pair.
 */
const keys = { kid: privateKey };

/**
 * Instantiate {@link Authentication} Class
 */
const resolver = new HttpResolver(discoveryEndpoint);
const auth = new didAuth.Authentication({
  keys,
  resolver
});

/**
 * Form the Authentication Request.
 * Send Authentication Request to client via:
 * 1. customized navigator.did.requestAuthentication function for desktop browser-browser extension flow
 * 2. creating a QR code and scanning the QR code using User Agent app on mobile device for desktop browser-mobile device flow.
 * 3. deep-linking to the User Agent on mobile app for mobile browser-mobile device flow.
 */
async function sendAuthenticationRequest () {

  /**
   * form {@link AuthenticationRequest} and sign it.
   */
  const authRequest = {
    iss: DID,
    response_type: 'id_token',
    client_id: REDIRECT_URL,
    scope: 'openid',
    state: state,
    nonce: nonce,
    claims: undefined
  };

  const jwsAuthRequest = await auth.signAuthenticationRequest(authRequest); // send jws to client.
  return jwsAuthRequest;
}

  /**
   * If Authentication Request is successfully verified and approved on client, client will send {@link AuthenticationResponse} to REDIRECT_URL.
   * Verify {@link AuthenticationResponse}, if succuessfully verified, will return back the payload containing DID.
   * Store DID from response for the particular session.
   */
async function verifyAuthenticationResponse (req: any) {
  const authResponse = req.body.id_token;
  const verifiedAuthResponse = await auth.verifyAuthenticationResponse(authResponse);
  return verifiedAuthResponse;
}
