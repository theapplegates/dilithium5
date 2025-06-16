
import React from 'react';
import { InformationCircleIcon, CheckCircleIcon, ExclamationTriangleIcon, XCircleIcon } from '@heroicons/react/24/solid';

type AlertType = 'info' | 'success' | 'warning' | 'error';

interface AlertProps {
  type: AlertType;
  title?: string;
  message: string | React.ReactNode;
  className?: string;
}

const alertStyles: Record<AlertType, { icon: React.ElementType; bg: string; border: string; text: string; titleText: string }> = {
  info: {
    icon: InformationCircleIcon,
    bg: 'bg-blue-50 dark:bg-blue-900',
    border: 'border-blue-500 dark:border-blue-400',
    text: 'text-blue-700 dark:text-blue-200',
    titleText: 'text-blue-800 dark:text-blue-100',
  },
  success: {
    icon: CheckCircleIcon,
    bg: 'bg-green-50 dark:bg-green-900',
    border: 'border-green-500 dark:border-green-400',
    text: 'text-green-700 dark:text-green-200',
    titleText: 'text-green-800 dark:text-green-100',
  },
  warning: {
    icon: ExclamationTriangleIcon,
    bg: 'bg-yellow-50 dark:bg-yellow-900',
    border: 'border-yellow-500 dark:border-yellow-400',
    text: 'text-yellow-700 dark:text-yellow-200',
    titleText: 'text-yellow-800 dark:text-yellow-100',
  },
  error: {
    icon: XCircleIcon,
    bg: 'bg-red-50 dark:bg-red-900',
    border: 'border-red-500 dark:border-red-400',
    text: 'text-red-700 dark:text-red-200',
    titleText: 'text-red-800 dark:text-red-100',
  },
};

export const Alert: React.FC<AlertProps> = ({ type, title, message, className = '' }) => {
  const styles = alertStyles[type];
  const IconComponent = styles.icon;

  return (
    <div className={`p-4 mb-4 border-l-4 rounded-md shadow-sm ${styles.bg} ${styles.border} ${className}`} role="alert">
      <div className="flex">
        <div className="flex-shrink-0">
          <IconComponent className={`h-5 w-5 ${styles.text}`} aria-hidden="true" />
        </div>
        <div className="ml-3">
          {title && <h3 className={`text-sm font-medium ${styles.titleText}`}>{title}</h3>}
          <div className={`text-sm ${styles.text} ${title ? 'mt-1' : ''}`}>
            {typeof message === 'string' ? <p>{message}</p> : message}
          </div>
        </div>
      </div>
    </div>
  );
};
