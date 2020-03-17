import { CipherStrategy, DerivedKeyOptions, encryptWithKey } from '../src';
import {
  decode64,
  decodeSafe64,
  deSerialize,
  encode64,
  generateRandomKey,
  serialize,
  stringAsBinaryBuffer
} from '../src/util';

describe('Serialize/Deserialize', () => {
  // i.e. from ruby: `zSX\xFC\x8A\xE5\x8D\xAD\xFC\x9B\xCA\xF9\x0Fk\xF7B\x01\xBB\xB8`;
  const b64EncryptedData = `J3pTWPyK5Y2t/JvK+Q9r90IBu7g=`;
  const iv = `/n+\xF4\xB0\x11\x14\xC2\xE3\xD2/J`;
  const at = `\xF5[v\xA4\x13l\xC1\xAD!\x93\xAE\xEB;\x82\xB4\xB8`;
  const ad = 'none';
  const encryptionStrategy = 'Aes256Gcm';

  // tslint:disable-next-line
  const testSerialized = `Aes256Gcm.J3pTWPyK5Y2t_JvK-Q9r90IBu7g=.LS0tCml2OiAhYmluYXJ5IHwtCiAgTDI0cjlMQVJGTUxqMGk5SwphdDogIWJpbmFyeSB8LQogIDlWdDJwQk5zd2EwaGs2N3JPNEswdUE9PQphZDogbm9uZQo=`;
  it('serializes encrypted data', () => {
    expect(
      serialize(encryptionStrategy, decode64(b64EncryptedData), {
        iv: stringAsBinaryBuffer(iv),
        at: stringAsBinaryBuffer(at),
        ad
      })
    ).toEqual(testSerialized);
  });

  it('deserializes encrypted data', () => {
    const deserialized = deSerialize(testSerialized);
    expect(deserialized.encryptionStrategy).toEqual(encryptionStrategy);
    expect(deserialized.decodedPairs.length).toEqual(2);
    expect(encode64(deserialized.decodedPairs[0])).toEqual(b64EncryptedData);
    expect(deserialized.decodedPairs[1]).toEqual({
      iv: stringAsBinaryBuffer(iv),
      at: stringAsBinaryBuffer(at),
      ad
    });
  });

  it('serializes binary data to base64 to comply with YAML specification', async done => {
    try {
      const containsNonUtf8Characters = (str: string) => {
        for (let i = 0; i < str.length; i++) {
          if (str.charCodeAt(i) > 127) {
            return true;
          }
        }
        return false;
      };

      const derived = DerivedKeyOptions.randomFromOptions({});
      const encodedSerialized = derived.serialize();
      const [_, artifacts] = encodedSerialized.split('.');

      const yaml = decodeSafe64(artifacts);
      expect(containsNonUtf8Characters(yaml)).toEqual(false);

      const encrypted = await encryptWithKey({
        key: generateRandomKey(),
        data: 'This is some test data that will be encrypted',
        strategy: CipherStrategy.AES_GCM
      });
      const { serialized } = encrypted;
      const [__, ___, encoded] = serialized.split('.');
      const parsed = decodeSafe64(encoded);
      expect(containsNonUtf8Characters(parsed)).toEqual(false);
      done();
    } catch (err) {
      done(err);
    }
  });
});
