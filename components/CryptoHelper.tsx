
import React, { useState, useCallback } from 'react';
import { Input } from './common/Input';
import { Button } from './common/Button';
import { Alert } from './common/Alert';
import { Spinner } from './common/Spinner';
import { geminiService } from '../services/geminiService';
import { MOCK_API_KEY_INFO, DEBOUNCE_DELAY } from '../constants';
import { GroundingChunk } from '../types';
import { LightBulbIcon, LinkIcon } from '@heroicons/react/24/outline';

// Basic debounce function
function debounce<F extends (...args: any[]) => any>(func: F, waitFor: number) {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;

  return (...args: Parameters<F>): Promise<ReturnType<F>> => {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    return new Promise((resolve) => {
      timeoutId = setTimeout(() => resolve(func(...args)), waitFor);
    });
  };
}


export const CryptoHelper: React.FC = () => {
  const [term, setTerm] = useState('');
  const [explanation, setExplanation] = useState<string | null>(null);
  const [groundingChunks, setGroundingChunks] = useState<GroundingChunk[] | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isApiKeyMissing = !process.env.API_KEY;

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const fetchExplanation = useCallback(
    debounce(async (currentTerm: string) => {
      if (!currentTerm.trim()) {
        setError("Please enter a term to explain.");
        setExplanation(null);
        setGroundingChunks(undefined);
        return;
      }
      if (isApiKeyMissing) {
        setError(`Gemini API key is missing. ${MOCK_API_KEY_INFO}`);
        setIsLoading(false);
        return;
      }

      setError(null);
      setExplanation(null);
      setGroundingChunks(undefined);
      setIsLoading(true);
      try {
        const result = await geminiService.explainTerm(currentTerm);
        setExplanation(result.explanation);
        setGroundingChunks(result.groundingChunks);
      } catch (e: any) {
        setError(e.message || 'Failed to fetch explanation.');
      } finally {
        setIsLoading(false);
      }
    }, DEBOUNCE_DELAY),
    [isApiKeyMissing] 
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchExplanation(term);
  };
  
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newTerm = e.target.value;
    setTerm(newTerm);
    // Optionally trigger fetch on type, or wait for submit
    // fetchExplanation(newTerm); 
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200">Crypto Term Helper</h2>
      <p className="text-sm text-neutral-600 dark:text-neutral-400">
        Enter a cryptographic term (e.g., "AES", "RSA", "Zero-Knowledge Proof", "Dilithium5", "Kyber1024") and get an explanation from Gemini.
      </p>
      
      {isApiKeyMissing && (
         <Alert type="warning" title="API Key Missing" message={`The Gemini API functionality is disabled because the API_KEY environment variable is not set. ${MOCK_API_KEY_INFO}`} />
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          label="Cryptographic Term"
          id="crypto-term"
          type="text"
          value={term}
          onChange={handleInputChange}
          placeholder="e.g., Public Key Cryptography"
          disabled={isLoading || isApiKeyMissing}
        />
        <Button 
            type="submit" 
            isLoading={isLoading} 
            disabled={isLoading || !term.trim() || isApiKeyMissing}
            leftIcon={<LightBulbIcon className="h-5 w-5" />}
        >
          Explain Term
        </Button>
      </form>

      {isLoading && <Spinner text="Fetching explanation..." />}
      {error && <Alert type="error" message={error} />}
      
      {explanation && (
        <div className="mt-6 p-4 border border-neutral-200 dark:border-neutral-700 rounded-lg bg-neutral-50 dark:bg-neutral-800 shadow">
          <h3 className="text-xl font-semibold text-neutral-800 dark:text-neutral-200 mb-2">Explanation for "{term}"</h3>
          <div className="prose dark:prose-invert max-w-none text-neutral-700 dark:text-neutral-300 whitespace-pre-wrap">
            {explanation}
          </div>
          {groundingChunks && groundingChunks.length > 0 && (
            <div className="mt-4 pt-4 border-t border-neutral-200 dark:border-neutral-700">
              <h4 className="text-md font-semibold text-neutral-700 dark:text-neutral-300 mb-2">Sources (from Google Search):</h4>
              <ul className="list-disc list-inside space-y-1">
                {groundingChunks.map((chunk, index) => (
                  <li key={index} className="text-sm">
                    <a 
                      href={chunk.web.uri} 
                      target="_blank" 
                      rel="noopener noreferrer" 
                      className="text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300 underline flex items-center"
                    >
                      <LinkIcon className="h-4 w-4 mr-1 inline-block" />
                      {chunk.web.title || chunk.web.uri}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
