
import React, { useState, useCallback } from 'react';
import { KeyManagementSection } from './components/KeyManagementSection';
import { EncryptSection } from './components/EncryptSection';
import { DecryptSection } from './components/DecryptSection';
import { SignSection } from './components/SignSection';
import { VerifySection } from './components/VerifySection';
import { CryptoHelper } from './components/CryptoHelper';
import { Tabs, Tab } from './components/common/Tabs';
import { RpgpPublicKey } from './types';
import { KeyIcon, LockClosedIcon, LockOpenIcon, PencilSquareIcon, CheckBadgeIcon, QuestionMarkCircleIcon, SunIcon, MoonIcon } from '@heroicons/react/24/outline';

enum Section {
  KEYS = 'Key Management',
  ENCRYPT = 'Encrypt',
  DECRYPT = 'Decrypt',
  SIGN = 'Sign',
  VERIFY = 'Verify',
  HELPER = 'Crypto Helper',
}

const App: React.FC = () => {
  const [activeSection, setActiveSection] = useState<Section>(Section.KEYS);
  const [keys, setKeys] = useState<RpgpPublicKey[]>([]);
  const [isDarkMode, setIsDarkMode] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('theme') === 'dark' || 
             (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches);
    }
    return false;
  });

  const addKey = useCallback((key: RpgpPublicKey) => {
    setKeys(prevKeys => [...prevKeys, key]);
  }, []);
  
  const toggleDarkMode = useCallback(() => {
    setIsDarkMode(prevMode => {
      const newMode = !prevMode;
      if (newMode) {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
      } else {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
      }
      return newMode;
    });
  }, []);

  React.useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDarkMode]);


  const TABS: Tab[] = [
    { id: Section.KEYS, label: Section.KEYS, icon: KeyIcon },
    { id: Section.ENCRYPT, label: Section.ENCRYPT, icon: LockClosedIcon },
    { id: Section.DECRYPT, label: Section.DECRYPT, icon: LockOpenIcon },
    { id: Section.SIGN, label: Section.SIGN, icon: PencilSquareIcon },
    { id: Section.VERIFY, label: Section.VERIFY, icon: CheckBadgeIcon },
    { id: Section.HELPER, label: Section.HELPER, icon: QuestionMarkCircleIcon },
  ];

  return (
    <div className="min-h-screen bg-neutral-50 dark:bg-neutral-900 text-neutral-900 dark:text-neutral-100 transition-colors duration-300">
      <header className="bg-primary-600 dark:bg-primary-700 text-white shadow-md">
        <div className="container mx-auto px-4 py-6 flex justify-between items-center">
          <h1 className="text-3xl font-bold tracking-tight">PGP Tool <span className="text-sm font-normal">(Mocked RPGP)</span></h1>
          <button
            onClick={toggleDarkMode}
            className="p-2 rounded-full hover:bg-primary-500 dark:hover:bg-primary-600 focus:outline-none focus:ring-2 focus:ring-white"
            aria-label="Toggle dark mode"
          >
            {isDarkMode ? <SunIcon className="h-6 w-6" /> : <MoonIcon className="h-6 w-6" />}
          </button>
        </div>
      </header>
      
      <div className="container mx-auto px-4 py-8">
        <div className="bg-yellow-100 dark:bg-yellow-700 border-l-4 border-yellow-500 dark:border-yellow-400 text-yellow-700 dark:text-yellow-100 p-4 mb-6 rounded-md shadow" role="alert">
          <p className="font-bold">Important Note:</p>
          <p>This application uses a <strong className="font-semibold">mocked version</strong> of the <code>rpgp</code> library. Cryptographic operations are simulated and <strong className="font-semibold">NOT SECURE</strong>. A proper WebAssembly (WASM) build and integration of the actual <code>rpgp</code> Rust library would be required for real cryptographic functionality. The specified algorithms (Dilithium5 for signing, Kyber1024 for encryption) are part of this mock setup.</p>
        </div>

        <Tabs tabs={TABS} activeTabId={activeSection} onTabChange={(id) => setActiveSection(id as Section)} />

        <main className="mt-6 p-6 bg-white dark:bg-neutral-800 shadow-xl rounded-lg">
          {activeSection === Section.KEYS && <KeyManagementSection onKeyGenerated={addKey} existingKeys={keys} />}
          {activeSection === Section.ENCRYPT && <EncryptSection availableKeys={keys} />}
          {activeSection === Section.DECRYPT && <DecryptSection availableKeys={keys} />}
          {activeSection === Section.SIGN && <SignSection availableKeys={keys} />}
          {activeSection === Section.VERIFY && <VerifySection availableKeys={keys} />}
          {activeSection === Section.HELPER && <CryptoHelper />}
        </main>
      </div>

      <footer className="text-center py-8 text-neutral-500 dark:text-neutral-400 border-t border-neutral-200 dark:border-neutral-700 mt-12">
        <p>&copy; {new Date().getFullYear()} PGP Tool (Mocked RPGP). For demonstration purposes only.</p>
      </footer>
    </div>
  );
};

export default App;
