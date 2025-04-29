'use client';

import { useSearchParams } from 'next/navigation';
import { useEffect } from 'react';

export default function WidgetThemeHandler() {
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
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      const handleChange = (event: MediaQueryListEvent) => {
        if (event.matches) {
          document.documentElement.classList.add('dark-theme');
        } else {
          document.documentElement.classList.remove('dark-theme');
        }
      };
      
      mediaQuery.addEventListener('change', handleChange);
      
      // Cleanup listener on component unmount
      return () => {
        mediaQuery.removeEventListener('change', handleChange);
      };
    }
  }, [searchParams]);

  // This component doesn't render anything visible
  return null;
}
