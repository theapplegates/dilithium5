import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes, utf8ToBytes, bytesToUtf8, hexToBytes, bytesToHex } from '@noble/post-quantum/utils.js';
import { RpgpPublicKey, RpgpKeyPair, GenerateKeyParams, EncryptParams, DecryptParams, SignParams, VerifyParams } from '../types';
import { PRIMARY_SIGNING_ALGORITHM, ENCRYPTION_SUBKEY_ALGORITHM } from '../constants';
import React, { useState } from 'react'
import { rpgpService } from './rpgpService'

// In-memory key stores
const signingKeyStore = new Map<string, { publicKey: Uint8Array; secretKey: Uint8Array }>();
const encryptionKeyStore = new Map<string, { publicKey: Uint8Array; secretKey: Uint8Array }>();
const keyStore = new Map<string, RpgpKeyPair>();

// Helper to create PGP-like armor blocks
function createArmored(
  type: 'PUBLIC KEY' | 'PRIVATE KEY',
  userId: string,
  keyId: string,
  algorithm: string,
  keyHex: string
): string {
  return `-----BEGIN RPGP ${type} BLOCK-----
Version: RPGP-JS
Comment: Algorithm: ${algorithm}; UserID: ${userId}; KeyID: ${keyId}

${keyHex}
-----END RPGP ${type} BLOCK-----`;
}

export const rpgpService = {
  generateKeyPair: async (params: GenerateKeyParams): Promise<RpgpKeyPair> => {
    // Generate signing (Dilithium5) key pair
    const seedSign = randomBytes(32);
    const signKeys = ml_dsa87.keygen(seedSign);

    // Generate encryption (Kyber1024) key pair
    const encKeys = ml_kem1024.keygen();

    // Derive key identifiers
    const keyId = bytesToHex(signKeys.publicKey).substring(0, 16).toUpperCase();
    const fingerprint = bytesToHex(signKeys.publicKey).substring(0, 40).match(/.{1,4}/g)?.join(' ') || keyId;
    const createdAt = new Date();

    const signingAlgo = `${PRIMARY_SIGNING_ALGORITHM} (signing)`;
    const encryptionAlgo = `${ENCRYPTION_SUBKEY_ALGORITHM} (encryption)`;

    // Armor public keys
    const signPubArmored = createArmored('PUBLIC KEY', params.userId, keyId, signingAlgo, bytesToHex(signKeys.publicKey));
    const encPubArmored = createArmored('PUBLIC KEY', params.userId, keyId, encryptionAlgo, bytesToHex(encKeys.publicKey));
    const publicKeyArmored = `${signPubArmored}\n${encPubArmored}`;

    // Armor private keys
    const signPrivArmored = createArmored('PRIVATE KEY', params.userId, keyId, signingAlgo, bytesToHex(signKeys.secretKey));
    const encPrivArmored = createArmored('PRIVATE KEY', params.userId, keyId, encryptionAlgo, bytesToHex(encKeys.secretKey));
    const privateKeyArmored = `${signPrivArmored}\n${encPrivArmored}`;

    const keyPair: RpgpKeyPair = {
      keyId,
      fingerprint,
      userId: params.userId,
      algorithm: `${signingAlgo} + ${encryptionAlgo}`,
      publicKeyArmored,
      privateKeyArmored,
      createdAt,
    };

    // Store keys in memory
    signingKeyStore.set(keyId, { publicKey: signKeys.publicKey, secretKey: signKeys.secretKey });
    encryptionKeyStore.set(keyId, { publicKey: encKeys.publicKey, secretKey: encKeys.secretKey });
    keyStore.set(keyId, keyPair);

    return keyPair;
  },

  getPublicKey: async (keyId: string): Promise<RpgpPublicKey | undefined> => {
    const kp = keyStore.get(keyId);
    if (!kp) return undefined;
    const { privateKeyArmored, ...publicDetails } = kp;
    return publicDetails;
  },

  getAllPublicKeys: async (): Promise<RpgpPublicKey[]> => {
    return Array.from(keyStore.values()).map(kp => {
      const { privateKeyArmored, ...publicDetails } = kp;
      return publicDetails;
    });
  },

  encryptMessage: async (params: EncryptParams): Promise<string> => {
    const keyId = params.recipientKeyIds[0];
    const encKey = encryptionKeyStore.get(keyId);
    if (!encKey) throw new Error(`Encryption key not found for ${keyId}`);

    // Perform KEM
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(encKey.publicKey);

    // Symmetric encryption (AES-GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await crypto.subtle.importKey('raw', sharedSecret, 'AES-GCM', false, ['encrypt']);
    const plainBytes = utf8ToBytes(params.plaintext);
    const cipherBytes = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plainBytes));

    const payload = JSON.stringify({
      kemCipher: bytesToHex(cipherText),
      iv: bytesToHex(iv),
      ciphertext: bytesToHex(cipherBytes),
    });

    return `-----BEGIN PGP MESSAGE-----
Version: RPGP-JS
Comment: Encrypted for KeyID: ${keyId}

${payload}
-----END PGP MESSAGE-----`;
  },

  decryptMessage: async (params: DecryptParams): Promise<string> => {
    const keyId = params.privateKeyId;
    const encKey = encryptionKeyStore.get(keyId);
    if (!encKey) throw new Error(`Decryption key not found for ${keyId}`);

    // Extract and parse payload
    const lines = params.ciphertext.split('\n');
    const payload = lines.slice(4, -1).join('\n');
    const { kemCipher, iv, ciphertext } = JSON.parse(payload);

    // Recover shared secret
    const sharedSecret = ml_kem1024.decapsulate(hexToBytes(kemCipher), encKey.secretKey);
    const aesKey = await crypto.subtle.importKey('raw', sharedSecret, 'AES-GCM', false, ['decrypt']);
    const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBytes(iv) }, aesKey, hexToBytes(ciphertext));
    return bytesToUtf8(new Uint8Array(plainBuffer));
  },

  signMessage: async (params: SignParams): Promise<string> => {
    const signKey = signingKeyStore.get(params.privateKeyId);
    if (!signKey) throw new Error(`Signing key not found for ${params.privateKeyId}`);

    const msgBytes = utf8ToBytes(params.message);
    const sig = ml_dsa87.sign(signKey.secretKey, msgBytes);

    const signatureArmored = `-----BEGIN PGP SIGNATURE-----
Version: RPGP-JS
Comment: Detached signature for KeyID: ${params.privateKeyId}

${bytesToHex(sig)}
-----END PGP SIGNATURE-----`;

    return `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

${params.message}
${signatureArmored}`;
  },

  createDetachedSignature: async (params: SignParams): Promise<string> => {
    const signKey = signingKeyStore.get(params.privateKeyId);
    if (!signKey) throw new Error(`Signing key not found for ${params.privateKeyId}`);

    const msgBytes = utf8ToBytes(params.message);
    const sig = ml_dsa87.sign(signKey.secretKey, msgBytes);
    return `-----BEGIN PGP SIGNATURE-----
Version: RPGP-JS
Comment: Detached signature for KeyID: ${params.privateKeyId}

${bytesToHex(sig)}
-----END PGP SIGNATURE-----';
