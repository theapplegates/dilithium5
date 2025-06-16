
import React, { useState, useEffect } from 'react';
import { TextArea } from './common/TextArea';
import { Input } from './common/Input';
import { Button } from './common/Button';
import { Alert } from './common/Alert';
import { Spinner } from './common/Spinner';
import { rpgpMockService } from '../services/rpgpMockService';
import { RpgpPublicKey } from '../types'; // Using RpgpPublicKey for selection; service handles private key lookup
import { LockOpenIcon } from '@heroicons/react/24/outline';

interface DecryptSectionProps {
  availableKeys: RpgpPublicKey[]; // These are public keys, but we use their ID to find the mock private key
}

export const DecryptSection: React.FC<DecryptSectionProps> = ({ availableKeys }) => {
  const [ciphertext, setCiphertext] = useState('');
  const [selectedPrivateKeyId, setSelectedPrivateKeyId] = useState<string>('');
  const [passphrase, setPassphrase] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    if (availableKeys.length > 0 && !selectedPrivateKeyId) {
      // Prefer keys that are likely for decryption (Kyber or general purpose)
      const decryptionKey = availableKeys.find(k => k.algorithm.includes('Kyber')) || availableKeys[0];
      setSelectedPrivateKeyId(decryptionKey.keyId);
    }
  }, [availableKeys, selectedPrivateKeyId]);

  const handleDecrypt = async () => {
    if (!ciphertext || !selectedPrivateKeyId) {
      setError('Ciphertext and a private key selection are required.');
      return;
    }
    setError(null);
    setSuccessMessage(null);
    setPlaintext('');
    setIsLoading(true);
    try {
      const result = await rpgpMockService.decryptMessage({
        privateKeyId: selectedPrivateKeyId,
        passphrase,
        ciphertext,
      });
      setPlaintext(result);
      setSuccessMessage('Message decrypted successfully (mocked).');
    } catch (e: any) {
      setError(e.message || 'Failed to decrypt message.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200">Decrypt Message</h2>
      {error && <Alert type="error" message={error} className="mb-4" />}
      {successMessage && !error &&<Alert type="success" message={successMessage} className="mb-4" />}

      <TextArea
        label="Ciphertext to Decrypt"
        id="ciphertext-decrypt"
        value={ciphertext}
        onChange={(e) => setCiphertext(e.target.value)}
        placeholder="Paste the PGP encrypted message here..."
        disabled={isLoading}
        rows={8}
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
            <label htmlFor="privateKeyDecrypt" className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
            Your Private Key (select by ID)
            </label>
            {availableKeys.length > 0 ? (
            <select
                id="privateKeyDecrypt"
                value={selectedPrivateKeyId}
                onChange={(e) => setSelectedPrivateKeyId(e.target.value)}
                className="block w-full pl-3 pr-10 py-2 text-base border-neutral-300 dark:border-neutral-600 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-md bg-white dark:bg-neutral-700 text-neutral-900 dark:text-neutral-100"
                disabled={isLoading}
            >
                {availableKeys.map(key => (
                <option key={key.keyId} value={key.keyId}>
                    {key.userId} (ID: {key.keyId.substring(0,8)}...)
                </option>
                ))}
            </select>
            ) : (
            <Alert type="info" message="No keys available. Please generate one in 'Key Management'." />
            )}
        </div>
        <Input
          label="Passphrase (if key is protected, 'testpass' for mock)"
          id="passphrase-decrypt"
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="Enter passphrase for the selected key"
          disabled={isLoading || !selectedPrivateKeyId}
        />
      </div>
      
      <Button 
        onClick={handleDecrypt} 
        isLoading={isLoading} 
        disabled={isLoading || !ciphertext || !selectedPrivateKeyId || availableKeys.length === 0}
        leftIcon={<LockOpenIcon className="h-5 w-5" />}
      >
        Decrypt Message
      </Button>

      {isLoading && <Spinner text="Decrypting..." />}

      {plaintext && (
        <div>
          <h3 className="text-xl font-semibold text-neutral-800 dark:text-neutral-200 mt-6 mb-2">Decrypted Message (Plaintext)</h3>
          <TextArea
            id="plaintext-output"
            value={plaintext}
            readOnly
            rows={8}
            className="bg-green-50 dark:bg-green-900 border-green-500"
          />
        </div>
      )}
    </div>
  );
};
