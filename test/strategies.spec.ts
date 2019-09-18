import { strategyToAlgorithm } from '../src/strategies';

describe('Strategy to algorithm', () => {
  it('maps an encrypted strategy from serialized format to a cipher alogirhtm', () => {
    expect(strategyToAlgorithm('Aes256Gcm')).toEqual('AES-GCM');
    expect(strategyToAlgorithm('Aes256Ofb')).toEqual('AES-OFB');
  });
});
