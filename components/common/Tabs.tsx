
import React from 'react';

export interface Tab {
  id: string;
  label: string;
  icon?: React.ForwardRefExoticComponent<Omit<React.SVGProps<SVGSVGElement>, "ref"> & { title?: string | undefined; titleId?: string | undefined; } & React.RefAttributes<SVGSVGElement>>;
}

interface TabsProps {
  tabs: Tab[];
  activeTabId: string;
  onTabChange: (id: string) => void;
}

export const Tabs: React.FC<TabsProps> = ({ tabs, activeTabId, onTabChange }) => {
  return (
    <div className="mb-6 border-b border-neutral-200 dark:border-neutral-700">
      <nav className="-mb-px flex space-x-4 sm:space-x-8" aria-label="Tabs">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`
              ${tab.id === activeTabId
                ? 'border-primary-500 text-primary-600 dark:border-primary-400 dark:text-primary-400'
                : 'border-transparent text-neutral-500 hover:text-neutral-700 hover:border-neutral-300 dark:text-neutral-400 dark:hover:text-neutral-200 dark:hover:border-neutral-500'
              }
              whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm sm:text-base flex items-center group
            `}
            aria-current={tab.id === activeTabId ? 'page' : undefined}
          >
            {tab.icon && <tab.icon className={`
              ${tab.id === activeTabId ? 'text-primary-500 dark:text-primary-400' : 'text-neutral-400 group-hover:text-neutral-500 dark:text-neutral-500 dark:group-hover:text-neutral-300'}
              -ml-0.5 mr-2 h-5 w-5
            `} aria-hidden="true" />}
            {tab.label}
          </button>
        ))}
      </nav>
    </div>
  );
};
