/**
 * Node packages
 */
const didCommon = require('@decentralized-identity/did-common-typescript');
const didAuth = require('@decentralized-identity/did-auth-jose');

/**
 * Constants
 */
const discoveryEndpoint = 'HTTP_RESOLVER_ENDPOINT_HERE'; // e.g. https://beta.discover.did.microsoft.com/
const redirectUrl = 'server.example.com'; // server url that client will send Authentication Response to

/**
 * Fill in the client DID to use
 */
const clientDID = 'YOUR_Client_DID_HERE';

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
const newKid = `${clientDID}${PRIVATE_KEY.kid}`;
const privateKey = didAuth.RsaPrivateKey.wrapJwk(newKid, PRIVATE_KEY);

/**
 * Create a keys object that contains (kid, privateKey) key-value pair.
 */
const keys = { kid: privateKey };

/**
 * Instantiate {@link Authentication} Class
 */
const resolver = new didCommon.HttpResolver(discoveryEndpoint);
const auth = new didAuth.Authentication({
  keys,
  resolver
});

/**
 * The UA gets the signed {@link AuthenticationRequest} from server.
 * Verify the {@link AuthenticationRequest} and form the {@link AuthenticationResponse}.
 * Send the {@link AuthenticationResponse} to the redirect url contained in the {@link AuthenticationRequest}.
 * @param jws Authentication Request in the form of a JWS.
 */
async function clientExample (jws: string) {

  const authenticationRequest = await didAuth.verifyAuthenticationRequest(jws);
  const signedAuthenticationResponse = await didAuth.formAuthenticationResponse(authenticationRequest, clientDID, {});
  return signedAuthenticationResponse;
}
