
/** Partial OpenID authentication request challenge */
export default interface Challenge {
  /** DID of the issuer of the challenge. This should match the signature */
  client_id: string;
  /** Opaque value used by issuer for state */
  state: string | undefined;
  /** Challenge Nonce */
  nonce: string;
}
