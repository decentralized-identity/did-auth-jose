
import KeyStoreMem from '../../lib/keyStore/KeyStoreMem';
import { ProtectionFormat } from '../../lib/keyStore/ProtectionFormat';
import EcPrivateKey from '../../lib/crypto/ec/EcPrivateKey';
import { Secp256k1CryptoSuite } from '../../lib/crypto/ec/Secp256k1CryptoSuite';
import RsaPrivateKey from '../../lib/crypto/rsa/RsaPrivateKey';
import { RsaCryptoSuite } from '../../lib/crypto/rsa/RsaCryptoSuite';
import { CryptoFactory } from '../../lib';

describe('KeyStoreMem', () => {

  const cryptoFactory: CryptoFactory = new CryptoFactory([new RsaCryptoSuite(), new Secp256k1CryptoSuite()]);
  it('should create a new EC signature', async (done) => {

    const jwk = await EcPrivateKey.generatePrivateKey('key1');

    // Setup registration environment
    const keyStore = new KeyStoreMem();
    await keyStore.save('key', jwk);
    const ecKey = await keyStore.get('key', false) as EcPrivateKey;
    expect(ecKey.kty).toBe('EC');
    expect(ecKey.d).toEqual(jwk.d);

    // Get public key
    const ecPublic: any = await keyStore.get('key', true);
    expect(ecPublic.kty).toBe('EC');
    expect(ecPublic.d).toBeUndefined();

    // Check signature
    const signature = await keyStore.protect('key', 'abc', ProtectionFormat.FlatJsonJws, cryptoFactory);
    expect(signature).toBeDefined();
    done();
  });

  it('should create a new RSA signature', async (done) => {

    const jwk = await RsaPrivateKey.generatePrivateKey('key1');

    // Setup registration environment
    const keyStore = new KeyStoreMem();
    await keyStore.save('key', jwk);
    const signature = await keyStore.protect('key', 'abc', ProtectionFormat.FlatJsonJws, cryptoFactory);
    expect(signature).toBeDefined();
    done();
  });

  it('should throw because key is not found in store', async (done) => {

    // Setup registration environment
    const keyStore = new KeyStoreMem();
    let throwCaught = false;
    const signature = await keyStore.protect('key', 'abc', ProtectionFormat.FlatJsonJws, cryptoFactory)
    .catch(() => {
      throwCaught = true;
    });
    expect(signature).toBeUndefined();
    expect(throwCaught).toBe(true);
    done();
  });

  it('should throw because an oct key does not have a public key', async (done) => {

    // Setup registration environment
    const jwk: any = {
      kty: 'oct',
      use: 'sig',
      k: 'AAEE'
    };

    const keyStore = new KeyStoreMem();
    await keyStore.save('key', jwk);
    let throwCaught = false;
    const signature = await keyStore.get('key', true)
    .catch((err) => {
      throwCaught = true;
      expect(err.message).toBe('A secret does not has a public key');
    });
    expect(signature).toBeUndefined();
    expect(throwCaught).toBe(true);
    done();
  });

  it('should throw because format passed is not a signature format', async (done) => {

    // Setup registration environment
    const jwk = await RsaPrivateKey.generatePrivateKey('key1');

    const keyStore = new KeyStoreMem();
    await keyStore.save('key', jwk);
    let throwCaught = false;
    const signature = await keyStore.protect('key', 'abc', ProtectionFormat.CompactJsonJwe, cryptoFactory)
    .catch((err) => {
      throwCaught = true;
      expect(err.message).toBe('Non signature format passed: 2');
    });
    expect(signature).toBeUndefined();
    expect(throwCaught).toBe(true);
    done();
  });

  it('should throw because key type is not supported', async (done) => {

    // Setup registration environment
    const keyStore = new KeyStoreMem();
    const jwk: any = {
      kid: 'key1',
      use: 'sig',
      kty: 'oct',
      k: 'AAEE'
    };

    await keyStore.save('key', jwk);

    let throwCaught = false;
    const signature = await keyStore.protect('key', 'abc', ProtectionFormat.FlatJsonJws, cryptoFactory)
    .catch(() => {
      throwCaught = true;
    });
    expect(signature).toBeUndefined();
    expect(throwCaught).toBe(true);
    done();
  });
});
