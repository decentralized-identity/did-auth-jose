import EcPrivateKey from '../../../lib/crypto/ec/EcPrivateKey';
import { Secp256k1CryptoSuite } from '../../../lib/crypto/ec/Secp256k1CryptoSuite';

describe('Secp256k1CryptoSuite', async () => {
  it('it should return empty encryptors', async () => {
    const cryptoSuite = new Secp256k1CryptoSuite();
    const encrypters: any = cryptoSuite.getEncrypters();
    expect(encrypters).toBeDefined();
    expect(encrypters.length).toBeUndefined();
  });

  it('it should return expected signers', async () => {
    const cryptoSuite = new Secp256k1CryptoSuite();
    const signers: any = cryptoSuite.getSigners();
    expect(signers).toBeDefined();
    expect(signers['ES256K']).toBeDefined();
    expect(signers['ES256K']['sign']).toEqual(Secp256k1CryptoSuite.sign);
    expect(signers['ES256K']['verify']).toEqual(Secp256k1CryptoSuite.verify);
  });

  it('it should return expected KeyConstructors and subsequent key for Secp256k1VerificationKey2018', async () => {
    const cryptoSuite = new Secp256k1CryptoSuite();
    const keyConstructors: any = cryptoSuite.getKeyConstructors();
    expect(keyConstructors).toBeDefined();
    expect(keyConstructors['Secp256k1VerificationKey2018']).toBeDefined();

    const keyData = {
      id: 'key-1',
      type: 'Secp256k1VerificationKey2018',
      publicKeyJwk: {
        kid: 'key-1',
        x: 'skdjc4398ru',
        y: 'skdjc4398ru',
        crv: 'P-256K'
      }
    };

    const keyConstructor = keyConstructors['Secp256k1VerificationKey2018'];
    const key = keyConstructor(keyData);
    expect(key).toBeDefined();
  });

  it('it should return expected KeyConstructors and subsequent key for EdDsaSAPublicKeySecp256k1', async () => {
    const cryptoSuite = new Secp256k1CryptoSuite();
    const keyConstructors: any = cryptoSuite.getKeyConstructors();
    expect(keyConstructors).toBeDefined();
    expect(keyConstructors['EdDsaSAPublicKeySecp256k1']).toBeDefined();

    const keyData = {
      id: 'key-1',
      type: 'EdDsaSAPublicKeySecp256k1',
      publicKeyJwk: {
        kid: 'key-1',
        x: 'skdjc4398ru',
        y: 'skdjc4398ru',
        crv: 'P-256K'
      }
    };

    const keyConstructor = keyConstructors['EdDsaSAPublicKeySecp256k1'];
    const key = keyConstructor(keyData);
    expect(key).toBeDefined();
  });

  it('it should return expected KeyConstructors and subsequent key for EdDsaSASignatureSecp256k1', async () => {
    const cryptoSuite = new Secp256k1CryptoSuite();
    const keyConstructors: any = cryptoSuite.getKeyConstructors();
    expect(keyConstructors).toBeDefined();
    expect(keyConstructors['EdDsaSASignatureSecp256k1']).toBeDefined();

    const keyData = {
      id: 'key-1',
      type: 'EdDsaSASignatureSecp256k1',
      publicKeyJwk: {
        kid: 'key-1',
        x: 'skdjc4398ru',
        y: 'skdjc4398ru',
        crv: 'P-256K'
      }
    };

    const keyConstructor = keyConstructors['EdDsaSASignatureSecp256k1'];
    const key = keyConstructor(keyData);
    expect(key).toBeDefined();
  });

  it('it should return expected KeyConstructors and subsequent key for EcdsaPublicKeySecp256k1', async () => {
    const cryptoSuite = new Secp256k1CryptoSuite();
    const keyConstructors: any = cryptoSuite.getKeyConstructors();
    expect(keyConstructors).toBeDefined();
    expect(keyConstructors['EcdsaPublicKeySecp256k1']).toBeDefined();

    const keyData = {
      id: 'key-1',
      type: 'EcdsaPublicKeySecp256k1',
      publicKeyJwk: {
        kid: 'key-1',
        x: 'skdjc4398ru',
        y: 'skdjc4398ru',
        crv: 'P-256K'
      }
    };

    const keyConstructor = keyConstructors['EcdsaPublicKeySecp256k1'];
    const key = keyConstructor(keyData);
    expect(key).toBeDefined();
  });

  it('it should sign content and verify', async () => {
    const ecKey = await EcPrivateKey.generatePrivateKey('key-1');
    const signature = await Secp256k1CryptoSuite.sign('{ test: "test"}', ecKey);
    expect(signature).toBeDefined();
    const verify = await Secp256k1CryptoSuite.verify(
      '{ test: "test"}',
      signature,
      ecKey.getPublicKey()
    );
    expect(verify).toBeTruthy();
  });

  it('it should sign content and fail verification when content altered', async () => {
    const ecKey = await EcPrivateKey.generatePrivateKey('key-1');
    const signature = await Secp256k1CryptoSuite.sign('{ test: "test"}', ecKey);
    expect(signature).toBeDefined();
    const verify = await Secp256k1CryptoSuite.verify(
      '{ test: "test_altered"}',
      signature,
      ecKey.getPublicKey()
    );
    expect(verify).toBeFalsy();
  });

  it('it should sign content and fail verification when signature altered', async () => {
    const ecKey = await EcPrivateKey.generatePrivateKey('key-1');
    const signature = await Secp256k1CryptoSuite.sign('{ test: "test"}', ecKey);
    expect(signature).toBeDefined();
    const alteredSignature = signature.substring(0, signature.length - 5); // Trim the signature to break it
    const verify = await Secp256k1CryptoSuite.verify(
      '{ test: "test"}',
      alteredSignature,
      ecKey.getPublicKey()
    );
    expect(verify).toBeFalsy();
  });
});
