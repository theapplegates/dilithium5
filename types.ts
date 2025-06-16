
export interface RpgpPublicKey {
  keyId: string;
  fingerprint: string;
  userId: string;
  publicKeyArmored: string;
  algorithm: string; // e.g., "Dilithium5 (signing)" or "Kyber1024 (encryption)"
  createdAt: Date;
}

// For simplicity, assuming private key is stored with its public part for selection
export interface RpgpKeyPair extends RpgpPublicKey {
  privateKeyArmored: string; // In a real app, this would be heavily protected
}

export interface GenerateKeyParams {
  userId: string; // e.g., "User Name <user@example.com>"
  passphrase?: string;
}

export interface EncryptParams {
  recipientKeyIds: string[]; // Key IDs of recipients' public keys
  plaintext: string;
}

export interface DecryptParams {
  privateKeyId: string; // Key ID of the private key to use
  passphrase?: string;
  ciphertext: string;
}

export interface SignParams {
  privateKeyId: string; // Key ID of the private key to use
  passphrase?: string;
  message: string;
}

export interface VerifyParams {
  signerKeyId: string; // Key ID of the signer's public key
  message: string;
  signature: string; // Detached signature
}

export interface GroundingChunkWeb {
  uri: string;
  title: string;
}

export interface GroundingChunk {
  web: GroundingChunkWeb;
}
