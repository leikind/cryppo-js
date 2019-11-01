import { signWithPrivateKey, verifyWithPublicKey, serializeRsaSignature, loadRsaSignature } from '../../src/signing/rsa-signature';
import { generateRSAKeyPair } from '../../src/key-pairs/rsa';
import { encodeSafe64 } from '../../src/util';

describe('signing', () => {
  const data = 'Sign me!';
  it('can sign a message with a private key then serialize it', async done => {
      try {
        const keyPair = await generateRSAKeyPair();
        const signatureObj = signWithPrivateKey(keyPair.privateKey, data);
        const serializedPayload = serializeRsaSignature(signatureObj);
        expect(serializedPayload.split('.')[3]).toEqual(encodeSafe64(data));
        done();
      } catch (err) {
        done(err);
      }
    });
  it('can load a signature then verify it', async done => {
    try {
      const keyPair = await generateRSAKeyPair();
      const signatureObj = signWithPrivateKey(keyPair.privateKey, data);
      const serializedPayload = serializeRsaSignature(signatureObj);
      const loadedSignature = loadRsaSignature(serializedPayload);
      expect(verifyWithPublicKey(keyPair.publicKey, loadedSignature)).toEqual(true);
      done();
    } catch (err) {
      done(err);
    }
  });

});
  