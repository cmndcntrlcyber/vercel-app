'use client';

import { Suspense } from 'react';
import SecurityScanner from '../../components/SecurityScanner';

// Create a separate client component for theme handling
import WidgetThemeHandler from './WidgetThemeHandler';

export default function WidgetPage() {
  return (
    <div className="widget-page">
      <Suspense fallback={<div>Loading...</div>}>
        <WidgetThemeHandler />
        <SecurityScanner />
      </Suspense>
    </div>
  );
}
