
import React, { useState, useEffect, useCallback } from 'react';
import { Input } from './common/Input';
import { Button } from './common/Button';
import { TextArea } from './common/TextArea';
import { Modal } from './common/Modal';
import { Alert } from './common/Alert';
import { Spinner } from './common/Spinner';
import { rpgpMockService } from '../services/rpgpMockService';
import { RpgpPublicKey, RpgpKeyPair } from '../types';
import { PRIMARY_SIGNING_ALGORITHM, ENCRYPTION_SUBKEY_ALGORITHM } from '../constants';
import { UserPlusIcon, KeyIcon, ClipboardDocumentIcon, EyeIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';

interface KeyManagementSectionProps {
  onKeyGenerated: (key: RpgpPublicKey) => void;
  existingKeys: RpgpPublicKey[];
}

export const KeyManagementSection: React.FC<KeyManagementSectionProps> = ({ onKeyGenerated, existingKeys }) => {
  const [userId, setUserId] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [generatedKey, setGeneratedKey] = useState<RpgpKeyPair | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [displayedKeys, setDisplayedKeys] = useState<RpgpPublicKey[]>([]);

  useEffect(() => {
    setDisplayedKeys(existingKeys);
  }, [existingKeys]);


  const handleGenerateKey = async () => {
    if (!userId.match(/^[^<]+<[^@]+@[^>]+>$/)) {
      setError('Invalid User ID format. Expected "Name <email@example.com>".');
      return;
    }
    setError(null);
    setIsLoading(true);
    try {
      const newKey = await rpgpMockService.generateKeyPair({ userId, passphrase });
      setGeneratedKey(newKey);
      onKeyGenerated(newKey); // Notify parent about the public part
      setIsModalOpen(true);
      setUserId('');
      setPassphrase('');
    } catch (e: any) {
      setError(e.message || 'Failed to generate key.');
    } finally {
      setIsLoading(false);
    }
  };
  
  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text)
      .then(() => alert(`${type} copied to clipboard!`))
      .catch(err => alert(`Failed to copy ${type}: ${err}`));
  };

  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200 mb-1">Generate New Key Pair</h2>
        <p className="text-sm text-neutral-600 dark:text-neutral-400 mb-4">
          Primary key for signing: <strong>{PRIMARY_SIGNING_ALGORITHM}</strong>. Subkey for encryption: <strong>{ENCRYPTION_SUBKEY_ALGORITHM}</strong>.
        </p>
        {error && <Alert type="error" message={error} className="mb-4" />}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Input
            label="User ID (e.g., Your Name <you@example.com>)"
            id="userId"
            type="text"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            placeholder="Name <email@example.com>"
            disabled={isLoading}
          />
          <Input
            label="Passphrase (Optional, 'testpass' for mock)"
            id="passphrase"
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Leave blank or use 'testpass'"
            disabled={isLoading}
          />
        </div>
        <Button 
            onClick={handleGenerateKey} 
            isLoading={isLoading} 
            disabled={isLoading || !userId}
            className="mt-4"
            leftIcon={<UserPlusIcon className="h-5 w-5" />}
        >
          Generate Key
        </Button>
      </div>

      <div>
        <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200 mb-4">Available Keys ({displayedKeys.length})</h2>
        {displayedKeys.length === 0 && !isLoading && (
          <Alert type="info" message="No keys generated or imported yet. Generate a key above to get started." />
        )}
        {isLoading && displayedKeys.length === 0 && <Spinner text="Loading keys..." />}
        <div className="space-y-4">
          {displayedKeys.map(key => (
            <div key={key.keyId} className="p-4 border border-neutral-200 dark:border-neutral-700 rounded-lg shadow-sm bg-neutral-50 dark:bg-neutral-800">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-semibold text-primary-600 dark:text-primary-400 flex items-center">
                    <KeyIcon className="h-5 w-5 mr-2" /> {key.userId}
                  </p>
                  <p className="text-xs text-neutral-500 dark:text-neutral-400">Key ID: {key.keyId}</p>
                  <p className="text-xs text-neutral-500 dark:text-neutral-400">Algorithm: {key.algorithm}</p>
                  <p className="text-xs text-neutral-500 dark:text-neutral-400">Created: {new Date(key.createdAt).toLocaleString()}</p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    const fullKey = rpgpMockService.getPublicKey(key.keyId).then(fullKeyDetails => {
                        if (fullKeyDetails) { // Check if fullKeyDetails is not undefined
                            const pairKey = existingKeys.find(k => k.keyId === fullKeyDetails.keyId) as RpgpKeyPair | undefined;
                            if (pairKey) {
                                setGeneratedKey(pairKey); // Need RpgpKeyPair for private key
                                setIsModalOpen(true);
                            } else {
                                // Fallback if RpgpKeyPair not found, show public key only.
                                setGeneratedKey({
                                    ...fullKeyDetails,
                                    privateKeyArmored: "Private key not available in this view."
                                });
                                setIsModalOpen(true);
                            }
                        }
                    });
                  }}
                  leftIcon={<EyeIcon className="h-4 w-4" />}
                >
                  View
                </Button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {generatedKey && (
        <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title="Key Pair Details">
          <div className="space-y-4">
            <Alert type="success" title="Key Pair Generated (Mock)" message={`Key ID: ${generatedKey.keyId}. Remember your passphrase if you set one!`} />
            <div>
              <h4 className="font-semibold mb-1 text-neutral-800 dark:text-neutral-200">User ID:</h4>
              <p className="text-sm p-2 bg-neutral-100 dark:bg-neutral-700 rounded">{generatedKey.userId}</p>
            </div>
            <div>
              <h4 className="font-semibold mb-1 text-neutral-800 dark:text-neutral-200">Public Key ({generatedKey.algorithm}):</h4>
              <TextArea value={generatedKey.publicKeyArmored} readOnly rows={8} className="text-xs font-mono" />
              <Button size="sm" variant="secondary" onClick={() => copyToClipboard(generatedKey.publicKeyArmored, 'Public Key')} className="mt-2" leftIcon={<ClipboardDocumentIcon className="h-4 w-4" />}>Copy Public Key</Button>
            </div>
            {'privateKeyArmored' in generatedKey && generatedKey.privateKeyArmored !== "Private key not available in this view." && (
              <div>
                <h4 className="font-semibold mb-1 text-neutral-800 dark:text-neutral-200">Private Key (Mock - DO NOT USE FOR REAL DATA):</h4>
                 <Alert type="warning" title="Mock Private Key" message="This is a mock private key. Do NOT use for any real sensitive data." />
                <TextArea value={generatedKey.privateKeyArmored} readOnly rows={8} className="text-xs font-mono" />
                <Button size="sm" variant="secondary" onClick={() => copyToClipboard(generatedKey.privateKeyArmored, 'Private Key')} className="mt-2" leftIcon={<ClipboardDocumentIcon className="h-4 w-4" />}>Copy Private Key</Button>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};
