import EcPrivateKey from '../../../lib/crypto/ec/EcPrivateKey';
import { KeyOperation } from '../../../lib/security/PublicKey';

describe('EcPrivateKey', async () => {
  it('constructor should throw when no jwk.d', async () => {

    const key = {
      id: 'key-1',
      type: 'EdDsaSAPublicKeySecp256k1',
      publicKeyJwk: {
        kid: 'key-1',
        x: 'skdjc4398ru',
        y: 'skdjc4398ru',
        crv: 'P-256K'
      }
    };

    expect(() => new EcPrivateKey(key)).toThrowError(
      'd required for private elliptic curve key.'
    );
  });

  it('it should create a private key', async () => {
    const ecKey = await EcPrivateKey.generatePrivateKey('key-1');
    expect(ecKey).toBeDefined();
    expect(ecKey.kty).toEqual('EC');
    expect(ecKey.kid).toEqual('key-1');
    expect(ecKey.key_ops).toEqual([KeyOperation.Sign, KeyOperation.Verify]);
    expect(ecKey.defaultEncryptionAlgorithm).toEqual('none');
    expect(ecKey.crv).toEqual('P-256K');
    expect(ecKey.defaultSignAlgorithm).toEqual('ES256K');
    expect(ecKey.d).toBeDefined();
    expect(ecKey.x).toBeDefined();
    expect(ecKey.y).toBeDefined();
  });
});
