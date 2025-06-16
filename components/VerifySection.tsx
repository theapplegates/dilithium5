
import React, { useState, useEffect } from 'react';
import { TextArea } from './common/TextArea';
import { Button } from './common/Button';
import { Alert } from './common/Alert';
import { Spinner } from './common/Spinner';
import { rpgpMockService } from '../services/rpgpMockService';
import { RpgpPublicKey } from '../types';
import { CheckBadgeIcon } from '@heroicons/react/24/outline';

interface VerifySectionProps {
  availableKeys: RpgpPublicKey[];
}

export const VerifySection: React.FC<VerifySectionProps> = ({ availableKeys }) => {
  const [message, setMessage] = useState('');
  const [signature, setSignature] = useState(''); // For detached signatures
  const [selectedSignerKeyId, setSelectedSignerKeyId] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{isValid: boolean, message: string} | null>(null);
  const [error, setError] = useState<string | null>(null);


  useEffect(() => {
    if (availableKeys.length > 0 && !selectedSignerKeyId) {
      const signingKey = availableKeys.find(k => k.algorithm.includes('Dilithium')) || availableKeys[0];
      setSelectedSignerKeyId(signingKey.keyId);
    }
  }, [availableKeys, selectedSignerKeyId]);

  const handleVerify = async () => {
    if (!message || !signature || !selectedSignerKeyId) {
      setError('Original message, signature, and a signer key selection are required for detached signature verification.');
      setVerificationResult(null);
      return;
    }
    setError(null);
    setVerificationResult(null);
    setIsLoading(true);
    try {
      const result = await rpgpMockService.verifyMessage({
        signerKeyId: selectedSignerKeyId,
        message,
        signature,
      });
      setVerificationResult(result);
    } catch (e: any) {
      setError(e.message || 'Failed to verify signature.');
      setVerificationResult(null);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200">Verify Detached Signature</h2>
      <Alert type="info" title="Note on Verification" message="This section currently supports verifying detached PGP signatures. For clear-signed messages, you would typically decrypt/verify them in the 'Decrypt' section (though this mock doesn't fully separate these concerns)." />
      {error && <Alert type="error" message={error} className="mb-4" />}
      
      {verificationResult && (
        <Alert 
            type={verificationResult.isValid ? "success" : "error"} 
            title={verificationResult.isValid ? "Verification Successful (Mock)" : "Verification Failed (Mock)"}
            message={verificationResult.message}
            className="mb-4" 
        />
      )}

      <TextArea
        label="Original Message"
        id="message-verify"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Paste the original, unaltered message here..."
        disabled={isLoading}
        rows={6}
      />

      <TextArea
        label="Detached Signature (PGP SIGNATURE block)"
        id="signature-verify"
        value={signature}
        onChange={(e) => setSignature(e.target.value)}
        placeholder="Paste the PGP signature block here (starts with -----BEGIN PGP SIGNATURE-----)..."
        disabled={isLoading}
        rows={6}
      />

      <div>
        <label htmlFor="signerKeyVerify" className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
          Signer's Public Key (select by ID)
        </label>
        {availableKeys.length > 0 ? (
          <select
            id="signerKeyVerify"
            value={selectedSignerKeyId}
            onChange={(e) => setSelectedSignerKeyId(e.target.value)}
            className="block w-full pl-3 pr-10 py-2 text-base border-neutral-300 dark:border-neutral-600 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-md bg-white dark:bg-neutral-700 text-neutral-900 dark:text-neutral-100"
            disabled={isLoading}
          >
            {availableKeys.map(key => (
              <option key={key.keyId} value={key.keyId}>
                {key.userId} (ID: {key.keyId.substring(0,8)}... - {key.algorithm.includes('Dilithium') ? 'Dilithium (signing)' : key.algorithm})
              </option>
            ))}
          </select>
        ) : (
          <Alert type="info" message="No keys available. Please generate or import a key in 'Key Management'." />
        )}
      </div>
      
      <Button 
        onClick={handleVerify} 
        isLoading={isLoading} 
        disabled={isLoading || !message || !signature || !selectedSignerKeyId || availableKeys.length === 0}
        leftIcon={<CheckBadgeIcon className="h-5 w-5" />}
      >
        Verify Signature
      </Button>

      {isLoading && <Spinner text="Verifying..." />}
    </div>
  );
};
