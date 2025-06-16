
import { RpgpPublicKey, RpgpKeyPair, GenerateKeyParams, EncryptParams, DecryptParams, SignParams, VerifyParams } from '../types';
import { PRIMARY_SIGNING_ALGORITHM, ENCRYPTION_SUBKEY_ALGORITHM } from '../constants';

const MOCK_DELAY = 1000; // 1 second delay to simulate network

const generateRandomId = (length = 8): string => Math.random().toString(16).substring(2, 2 + length).toUpperCase();

// In-memory store for "generated" keys (mock)
let mockKeyStorage: RpgpKeyPair[] = [];

const createArmoredKey = (type: string, userId: string, keyId: string, algorithm: string): string => {
  return `-----BEGIN PGP ${type} BLOCK-----
Version: Mocked RPGP JS
Comment: For demonstration purposes only

KeyID: ${keyId}
Algorithm: ${algorithm}
UserID: ${userId}
Content: This is a mock PGP block. Do not use for real security.
RandomBytes: ${generateRandomId(32)}
-----END PGP ${type} BLOCK-----`;
};

export const rpgpMockService = {
  generateKeyPair: async (params: GenerateKeyParams): Promise<RpgpKeyPair> => {
    return new Promise(resolve => {
      setTimeout(() => {
        const keyId = generateRandomId(16);
        const fingerprint = Array.from({ length: 5 }, () => generateRandomId(8)).join(' ');
        const createdAt = new Date();

        const signingKeyAlgo = `${PRIMARY_SIGNING_ALGORITHM} (signing)`;
        const encryptionKeyAlgo = `${ENCRYPTION_SUBKEY_ALGORITHM} (encryption)`;
        
        const keyPair: RpgpKeyPair = {
          keyId,
          fingerprint,
          userId: params.userId,
          // For simplicity, mock key uses same ID but represents primary signing key.
          // A real PGP key would have distinct primary and subkey structures.
          algorithm: signingKeyAlgo, 
          publicKeyArmored: createArmoredKey('PUBLIC KEY', params.userId, keyId, `${signingKeyAlgo} + ${encryptionKeyAlgo}`),
          privateKeyArmored: createArmoredKey('PRIVATE KEY', params.userId, keyId, `${signingKeyAlgo} + ${encryptionKeyAlgo}`),
          createdAt,
        };
        mockKeyStorage.push(keyPair);
        resolve(keyPair);
      }, MOCK_DELAY);
    });
  },

  getPublicKey: async (keyId: string): Promise<RpgpPublicKey | undefined> => {
    return new Promise(resolve => {
      setTimeout(() => {
        const key = mockKeyStorage.find(k => k.keyId === keyId);
        if (key) {
            const { privateKeyArmored, ...publicKey } = key;
            resolve(publicKey);
        } else {
            resolve(undefined);
        }
      }, MOCK_DELAY / 2);
    });
  },
  
  getAllPublicKeys: async (): Promise<RpgpPublicKey[]> => {
     return new Promise(resolve => {
      setTimeout(() => {
        resolve(mockKeyStorage.map(kp => {
            const {privateKeyArmored, ...publicKeyDetails} = kp;
            return publicKeyDetails;
        }));
      }, MOCK_DELAY / 2);
    });
  },

  encryptMessage: async (params: EncryptParams): Promise<string> => {
    return new Promise(resolve => {
      setTimeout(() => {
        const recipients = params.recipientKeyIds.join(', ');
        const ciphertext = `-----BEGIN PGP MESSAGE-----
Version: Mocked RPGP JS
Comment: Encrypted for KeyIDs: ${recipients}

This is a mock encrypted message. Original plaintext was:
"${params.plaintext.substring(0, 50)}${params.plaintext.length > 50 ? '...' : ''}"
RandomBytes: ${generateRandomId(64)}
-----END PGP MESSAGE-----`;
        resolve(ciphertext);
      }, MOCK_DELAY);
    });
  },

  decryptMessage: async (params: DecryptParams): Promise<string> => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const key = mockKeyStorage.find(k => k.keyId === params.privateKeyId);
        if (!key) {
          reject(new Error("Private key not found."));
          return;
        }
        // Simulate passphrase check - extremely simplified
        if (params.passphrase && params.passphrase !== "testpass") {
          reject(new Error("Incorrect passphrase (mock). Try 'testpass'."));
          return;
        }
        if (!params.ciphertext.includes("-----BEGIN PGP MESSAGE-----")) {
            reject(new Error("Invalid ciphertext format (mock)."));
            return;
        }
        const plaintext = `Mock decrypted message: This content was "unlocked" using key ${params.privateKeyId}. Original ciphertext started with: "${params.ciphertext.substring(0, 80)}..."`;
        resolve(plaintext);
      }, MOCK_DELAY);
    });
  },

  signMessage: async (params: SignParams): Promise<string> => { // Returns armored signed message
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const key = mockKeyStorage.find(k => k.keyId === params.privateKeyId);
        if (!key) {
          reject(new Error("Private key not found."));
          return;
        }
        if (params.passphrase && params.passphrase !== "testpass") {
          reject(new Error("Incorrect passphrase (mock). Try 'testpass'."));
          return;
        }
        const signatureBlock = `-----BEGIN PGP SIGNATURE-----
Version: Mocked RPGP JS
Comment: Signed with KeyID: ${params.privateKeyId} (${key.algorithm})

MockSignatureData:${generateRandomId(32)}
-----END PGP SIGNATURE-----`;

        // For simplicity, this mock returns a "clear signed" like message.
        // A real implementation might return a detached signature or a fully armored signed message.
        const signedMessage = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256 (mocked)

${params.message}
${signatureBlock}`;
        resolve(signedMessage);
      }, MOCK_DELAY);
    });
  },
  
  // This mock service will just return the signature part for detached signing.
  createDetachedSignature: async (params: SignParams): Promise<string> => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const key = mockKeyStorage.find(k => k.keyId === params.privateKeyId);
        if (!key) {
          reject(new Error("Private key not found."));
          return;
        }
        if (params.passphrase && params.passphrase !== "testpass") {
          reject(new Error("Incorrect passphrase (mock). Try 'testpass'."));
          return;
        }
        const signatureBlock = `-----BEGIN PGP SIGNATURE-----
Version: Mocked RPGP JS
Comment: Signed with KeyID: ${params.privateKeyId} (${key.algorithm})
Comment: For message: "${params.message.substring(0,30)}..."

MockDetachedSignatureData:${generateRandomId(64)}
-----END PGP SIGNATURE-----`;
        resolve(signatureBlock);
      }, MOCK_DELAY);
    });
  },

  verifyMessage: async (params: VerifyParams): Promise<{isValid: boolean, message: string}> => { // For detached signatures
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const key = mockKeyStorage.find(k => k.keyId === params.signerKeyId || k.publicKeyArmored.includes(params.signerKeyId)); // Simple check
        if (!key) {
          reject(new Error("Signer's public key not found."));
          return;
        }
        if (!params.signature.includes("-----BEGIN PGP SIGNATURE-----") || !params.signature.includes(`KeyID: ${params.signerKeyId}`)) {
            resolve({isValid: false, message: `Mock verification FAILED: Signature format incorrect or KeyID mismatch for ${params.signerKeyId}.`});
            return;
        }
        // Mock verification logic
        const isValid = params.message.length > 0 && params.signature.length > 0;
        const message = isValid 
            ? `Mock verification SUCCESSFUL: Message integrity confirmed with key ${params.signerKeyId} (${key.algorithm}).`
            : `Mock verification FAILED for key ${params.signerKeyId}.`;
        resolve({isValid, message});
      }, MOCK_DELAY);
    });
  },
};
