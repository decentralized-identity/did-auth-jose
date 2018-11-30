import EcPublicKey from '../../../lib/crypto/ec/EcPublicKey';

describe('EcPublicKey', async () => {
  it('constructor should throw when no publicKeyJwk', async () => {

    const key = {
      id: 'key-1',
      type: 'Secp256k1VerificationKey2018'
    };

    expect(() => new EcPublicKey(key)).toThrowError(
      'Cannot parse Elliptic Curve key.'
    );
  });

  it('constructor should throw when no kid\'s do not match', async () => {

    const key = {
      id: 'key-1',
      type: 'Secp256k1VerificationKey2018',
      publicKeyJwk: {
        kid: 'key-2',
        x: 'skdjc4398ru',
        y: 'skdjc4398ru',
        crv: 'P-256K'
      }
    };

    expect(() => new EcPublicKey(key)).toThrowError(
      'JWK kid does not match Did publickey id.'
    );
  });

  it('constructor should throw when missing x from jwk', async () => {

    const key = {
      id: 'key-1',
      type: 'Secp256k1VerificationKey2018',
      publicKeyJwk: {
        kid: 'key-1',
        y: 'skdjc4398ru',
        crv: 'P-256K'
      }
    };

    expect(() => new EcPublicKey(key)).toThrowError(
      'JWK missing required parameters.'
    );
  });

  it('constructor should throw when missing y from jwk', async () => {

    const key = {
      id: 'key-1',
      type: 'Secp256k1VerificationKey2018',
      publicKeyJwk: {
        kid: 'key-1',
        x: 'skdjc4398ru',
        crv: 'P-256K'
      }
    };

    expect(() => new EcPublicKey(key)).toThrowError(
      'JWK missing required parameters.'
    );
  });

  it('constructor should throw when missing crv from jwk', async () => {

    const key = {
      id: 'key-1',
      type: 'Secp256k1VerificationKey2018',
      publicKeyJwk: {
        kid: 'key-1',
        x: 'skdjc4398ru',
        y: 'skdjc4398ru'
      }
    };

    expect(() => new EcPublicKey(key)).toThrowError(
      'JWK missing required parameters.'
    );
  });
});
