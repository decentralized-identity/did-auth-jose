
/** Partial OpenID id token response */
export default interface ChallengeResponse {
  /** Did used to sign the response */
  iss: string;
  /** Issuer of the challenge */
  aud: string;
  /** Expiration as a UTC datetime */
  exp: number;
  /** Issued at as a UTC datetime */
  iat: number;
  /** Nonce of the challenge */
  nonce: string;
  /** Opaque value used by issuer for state */
  state: string | undefined;
}
