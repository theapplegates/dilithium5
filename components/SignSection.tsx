
import React, { useState, useEffect } from 'react';
import { TextArea } from './common/TextArea';
import { Input } from './common/Input';
import { Button } from './common/Button';
import { Alert } from './common/Alert';
import { Spinner } from './common/Spinner';
import { rpgpMockService } from '../services/rpgpMockService';
import { RpgpPublicKey } from '../types';
import { PencilSquareIcon, ClipboardDocumentIcon } from '@heroicons/react/24/outline';
import React, { useState } from 'react'
import { rpgpService } from '../rpgpService'

export function SignSection({ availableKeys }: SignSectionProps) {
// ← 0) Add this
const [output, setOutput] = useState<string>('')

// ← 1 & 2) Add this handler
async function handleSign() {
  const message      = /* whatever your input state/textarea holds */
  const privateKeyId = /* the key ID the user selected */
  try {
    const sig = await rpgpService.signMessage({ privateKeyId, message })
    setOutput(sig)
  } catch (err) {
    console.error(err)
    setOutput('❌ Signing failed: ' + String(err))
  }
}


interface SignSectionProps {
  availableKeys: RpgpPublicKey[];
}

export const SignSection: React.FC<SignSectionProps> = ({ availableKeys }) => {
  const [message, setMessage] = useState('');
  const [selectedPrivateKeyId, setSelectedPrivateKeyId] = useState<string>('');
  const [passphrase, setPassphrase] = useState('');
  const [signedOutput, setSignedOutput] = useState(''); // Can be signed message or detached signature
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    if (availableKeys.length > 0 && !selectedPrivateKeyId) {
       // Prefer keys that are likely for signing (Dilithium or general purpose)
      const signingKey = availableKeys.find(k => k.algorithm.includes('Dilithium')) || availableKeys[0];
      setSelectedPrivateKeyId(signingKey.keyId);
    }
  }, [availableKeys, selectedPrivateKeyId]);

  const handleSign = async (detached: boolean) => {
    if (!message || !selectedPrivateKeyId) {
      setError('Message and a private key selection are required.');
      return;
    }
    setError(null);
    setSuccessMessage(null);
    setSignedOutput('');
    setIsLoading(true);
    try {
      let result;
      if (detached) {
        result = await rpgpMockService.createDetachedSignature({
            privateKeyId: selectedPrivateKeyId,
            passphrase,
            message,
        });
        setSuccessMessage('Detached signature created successfully (mocked).');
      } else {
        result = await rpgpMockService.signMessage({
            privateKeyId: selectedPrivateKeyId,
            passphrase,
            message,
        });
        setSuccessMessage('Message signed successfully (mocked, clear-signed format).');
      }
      setSignedOutput(result);
      
    } catch (e: any) {
      setError(e.message || 'Failed to sign message.');
    } finally {
      setIsLoading(false);
    }
  };
  
  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text)
      .then(() => setSuccessMessage(`${type} copied to clipboard!`))
      .catch(err => setError(`Failed to copy ${type}: ${err}`));
  };


  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200">Sign Message</h2>
      {error && <Alert type="error" message={error} className="mb-4" />}
      {successMessage && !error && <Alert type="success" message={successMessage} className="mb-4" />}

      <TextArea
        label="Message to Sign"
        id="message-sign"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Enter the message you want to sign..."
        disabled={isLoading}
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
            <label htmlFor="privateKeySign" className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
            Your Signing Key (select by ID)
            </label>
            {availableKeys.length > 0 ? (
            <select
                id="privateKeySign"
                value={selectedPrivateKeyId}
                onChange={(e) => setSelectedPrivateKeyId(e.target.value)}
                className="block w-full pl-3 pr-10 py-2 text-base border-neutral-300 dark:border-neutral-600 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-md bg-white dark:bg-neutral-700 text-neutral-900 dark:text-neutral-100"
                disabled={isLoading}
            >
                {availableKeys.map(key => (
                <option key={key.keyId} value={key.keyId}>
                    {key.userId} (ID: {key.keyId.substring(0,8)}... - {key.algorithm.includes('Dilithium') ? 'Dilithium (suitable for signing)' : key.algorithm})
                </option>
                ))}
            </select>
            ) : (
            <Alert type="info" message="No keys available. Please generate one in 'Key Management'." />
            )}
        </div>
        <Input
          label="Passphrase (if key is protected, 'testpass' for mock)"
          id="passphrase-sign"
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="Enter passphrase for the selected key"
          disabled={isLoading || !selectedPrivateKeyId}
        />
      </div>
      
      <div className="flex space-x-4">
        <Button 
            onClick={() => handleSign(false)} 
            isLoading={isLoading} 
            disabled={isLoading || !message || !selectedPrivateKeyId || availableKeys.length === 0}
            leftIcon={<PencilSquareIcon className="h-5 w-5" />}
        >
            Sign (Clear-Signed)
        </Button>
        <Button 
            onClick={() => handleSign(true)} 
            isLoading={isLoading} 
            disabled={isLoading || !message || !selectedPrivateKeyId || availableKeys.length === 0}
            variant="secondary"
            leftIcon={<PencilSquareIcon className="h-5 w-5" />}
        >
            Create Detached Signature
        </Button>
      </div>

      {isLoading && <Spinner text="Signing..." />}

      {signedOutput && (
        <div>
          <h3 className="text-xl font-semibold text-neutral-800 dark:text-neutral-200 mt-6 mb-2">Signed Output</h3>
          <TextArea
            id="signed-output"
            value={signedOutput}
            readOnly
            rows={10}
            className="font-mono text-sm"
          />
           <Button 
            variant="secondary" 
            size="sm" 
            onClick={() => copyToClipboard(signedOutput, "Signed output")}
            className="mt-2"
            leftIcon={<ClipboardDocumentIcon className="h-4 w-4" />}
          >
            Copy Output
          </Button>
        </div>
      )}
    </div>
  );
};
