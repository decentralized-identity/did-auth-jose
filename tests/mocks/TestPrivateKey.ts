import { TestPublicKey } from './TestPublicKey';
import PrivateKey from '../../lib/security/PrivateKey';

/**
 * A private key object used for testing
 */
export default class TestPrivateKey extends TestPublicKey implements PrivateKey {
  defaultSignAlgorithm = 'test';

  getPublicKey (): TestPublicKey {
    return this;
  }
}
