import { pki, md } from 'node-forge';
import { encodeSafe64, decodeSafe64 } from '../../src/util';


export interface ISignature {
    signature: string;
    data: string;
}

export function signWithPrivateKey(privateKeyPem: string, data: string): ISignature {
    const mdDigest = md.sha256.create();
    const key = pki.privateKeyFromPem(privateKeyPem) as pki.rsa.PrivateKey;
    mdDigest.update(data, 'utf8');
    const signature = key.sign(mdDigest);
    return {
        signature: signature,
        data: data
    };
}

export function serializeRsaSignature(signatureObj: ISignature): string{
    return `Sign.Rsa4096.${encodeSafe64(signatureObj.signature)}.${encodeSafe64(signatureObj.data)}`;
}

export function loadRsaSignature(serializedPayload: string): ISignature{
    const decomposedPayload = serializedPayload.split('.')
    const signed = decomposedPayload[0]
    const signingStrategy = decomposedPayload[1]
    const encodedSignature = decomposedPayload[2]
    const encodedData = decomposedPayload[3]

    if(signed == "Sign" && signingStrategy == "Rsa4096"){
        return {
            signature: decodeSafe64(encodedSignature),
            data: decodeSafe64(encodedData)
        };
    }else{
        throw new Error("String is not a serialized RSA signature");
    }
}

export function verifyWithPublicKey(publicKeyPem: string, signatureObj: ISignature){
    const key = pki.publicKeyFromPem(publicKeyPem) as pki.rsa.PublicKey;
    const mdDigest = md.sha256.create();
    mdDigest.update(signatureObj.data, 'utf8');
    return key.verify(mdDigest.digest().bytes(), signatureObj.signature)
}