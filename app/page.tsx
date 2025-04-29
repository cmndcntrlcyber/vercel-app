'use client';

import { useState } from 'react';
import SecurityScanner from '../components/SecurityScanner';
import IntegrationGuide from '../components/IntegrationGuide';

export default function Home() {
  const [activeTab, setActiveTab] = useState<'demo' | 'integration'>('demo');

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-5xl mx-auto text-center">
        <header className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Security Scanner Widget</h1>
          <p className="text-gray-600">
            A customizable security scanner widget that can be embedded in your applications
          </p>
        </header>

        <div className="mb-6 border-b border-gray-200">
          <nav className="flex -mb-px justify-center">
            <button
              onClick={() => setActiveTab('demo')}
              className={`mr-4 py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'demo'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Demo
            </button>
            <button
              onClick={() => setActiveTab('integration')}
              className={`mr-4 py-2 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'integration'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Integration Guide
            </button>
          </nav>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          {activeTab === 'demo' ? (
            <div className="text-center">
              <h2 className="text-xl font-semibold mb-4">Security Scanner Demo</h2>
              <SecurityScanner />
            </div>
          ) : (
            <IntegrationGuide />
          )}
        </div>
      </div>
    </main>
  );
}
