'use client';

import { useSearchParams } from 'next/navigation';
import SecurityScanner from '../../components/SecurityScanner';
import { useEffect } from 'react';

export default function WidgetPage() {
  const searchParams = useSearchParams();
  
  // Apply theme based on URL parameters
  useEffect(() => {
    const theme = searchParams.get('theme') || 'light';
    
    if (theme === 'dark') {
      document.documentElement.classList.add('dark-theme');
    } else if (theme === 'auto') {
      if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        document.documentElement.classList.add('dark-theme');
      }
      
      // Listen for theme changes
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', event => {
        if (event.matches) {
          document.documentElement.classList.add('dark-theme');
        } else {
          document.documentElement.classList.remove('dark-theme');
        }
      });
    }
  }, [searchParams]);

  return (
    <div className="widget-page">
      <SecurityScanner />
    </div>
  );
}
