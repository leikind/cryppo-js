import { pki } from 'node-forge';
import { deSerialize, keyLengthFromPublicKeyPem, serialize } from '../util';

export function generateRSAKeyPair(
  bits = 4096
): Promise<{ privateKey: string; publicKey: string; bits: number }> {
  return new Promise((resolve, reject) => {
    // -1 workers to estimate number of cores available
    // https://github.com/digitalbazaar/forge#rsa
    pki.rsa.generateKeyPair({ bits, workers: 0 }, (err, keyPair) => {
      if (err) {
        return reject(err);
      }
      resolve({
        privateKey: pki.privateKeyToPem(keyPair.privateKey),
        publicKey: pki.publicKeyToPem(keyPair.publicKey),
        bits
      });
    });
  });
}

export function encryptPrivateKeyWithPassword({
  privateKeyPem,
  password
}: {
  privateKeyPem: string;
  password: string;
}) {
  const publicKey = pki.privateKeyFromPem(privateKeyPem);
  return pki.encryptRsaPrivateKey(publicKey, password);
}

export async function encryptWithPublicKey({
  publicKeyPem,
  data,
  scheme = 'RSA-OAEP'
}: {
  publicKeyPem: string;
  data: string;
  scheme?: RsaEncryptionScheme;
}) {
  const pk = pki.publicKeyFromPem(publicKeyPem) as pki.rsa.PublicKey;
  const encrypted = pk.encrypt(data, scheme);

  const bitLength = keyLengthFromPublicKeyPem(publicKeyPem);
  const serialized = serialize(`Rsa${bitLength}`, encrypted, <any>{});
  return {
    encrypted,
    serialized
  };
}

export type RsaEncryptionScheme =
  | 'RSAES-PKCS1-V1_5'
  | 'RSA-OAEP'
  | 'RAW'
  | 'NONE'
  | null
  | undefined;

export async function decryptSerializedWithPrivateKey({
  password,
  privateKeyPem,
  serialized,
  scheme = 'RSA-OAEP'
}: {
  password?: string;
  privateKeyPem: string;
  serialized: string;
  scheme?: RsaEncryptionScheme;
}) {
  const encrypted = deSerialize(serialized).decodedPairs[0];
  return decryptWithPrivateKey({
    password,
    privateKeyPem,
    encrypted,
    scheme
  });
}

/**
 * @deprecated
 */
export async function decryptWithPrivateKey({
  password,
  privateKeyPem,
  encrypted,
  scheme = 'RSA-OAEP'
}: {
  password?: string;
  privateKeyPem: string;
  encrypted: string;
  scheme?: RsaEncryptionScheme;
}) {
  const pk = pki.decryptRsaPrivateKey(privateKeyPem, password) as pki.rsa.PrivateKey;
  return pk.decrypt(encrypted, scheme);
}
