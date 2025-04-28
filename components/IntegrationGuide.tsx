'use client';

import { useState } from 'react';

export default function IntegrationGuide() {
  const [apiKey, setApiKey] = useState('YOUR_API_KEY');
  const [target, setTarget] = useState('https://example.com');
  const [scanType, setScanType] = useState('quick');
  const [theme, setTheme] = useState('light');
  const [width, setWidth] = useState('100%');
  const [height, setHeight] = useState('600px');

  // Generate embed code based on the current configuration
  const generateEmbedCode = () => {
    return `<!-- Security Scanner Widget -->
<div id="security-scanner-container"></div>

<script src="https://security-scanner-widget.vercel.app/embed.js"></script>
<script>
  SecurityScanner.init({
    container: '#security-scanner-container',
    apiKey: '${apiKey}',
    target: '${target}',
    defaultScanType: '${scanType}',
    theme: '${theme}',
    width: '${width}',
    height: '${height}',
    onScanComplete: function(result) {
      console.log('Scan completed:', result);
      // Handle scan results as needed
    }
  });
</script>`;
  };

  // Generate iframe embed code
  const generateIframeCode = () => {
    return `<iframe 
  src="https://security-scanner-widget.vercel.app/widget?apiKey=${apiKey}&target=${encodeURIComponent(target)}&scanType=${scanType}&theme=${theme}" 
  width="${width}" 
  height="${height}" 
  frameborder="0" 
  class="security-scanner-iframe">
</iframe>`;
  };

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">Integration Guide</h2>
      
      <p className="mb-4">
        You can integrate our security scanner widget into your own application using the JavaScript embed code or an iframe.
      </p>
      
      <div className="mb-6">
        <h3 className="text-lg font-medium mb-2">Configuration</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div className="form-group">
            <label htmlFor="apiKey" className="form-label">API Key</label>
            <input
              id="apiKey"
              type="text"
              className="form-input"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="YOUR_API_KEY"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="targetUrl" className="form-label">Default Target URL</label>
            <input
              id="targetUrl"
              type="url"
              className="form-input"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="scanType" className="form-label">Default Scan Type</label>
            <select
              id="scanType"
              className="form-select"
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
            >
              <option value="quick">Quick Scan</option>
              <option value="full">Full Scan</option>
            </select>
          </div>
          
          <div className="form-group">
            <label htmlFor="theme" className="form-label">Theme</label>
            <select
              id="theme"
              className="form-select"
              value={theme}
              onChange={(e) => setTheme(e.target.value)}
            >
              <option value="light">Light</option>
              <option value="dark">Dark</option>
              <option value="auto">Auto (follow system)</option>
            </select>
          </div>
          
          <div className="form-group">
            <label htmlFor="width" className="form-label">Width</label>
            <input
              id="width"
              type="text"
              className="form-input"
              value={width}
              onChange={(e) => setWidth(e.target.value)}
              placeholder="100%"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="height" className="form-label">Height</label>
            <input
              id="height"
              type="text"
              className="form-input"
              value={height}
              onChange={(e) => setHeight(e.target.value)}
              placeholder="600px"
            />
          </div>
        </div>
      </div>
      
      <div className="mb-6">
        <h3 className="text-lg font-medium mb-2">JavaScript Embed Code</h3>
        <p className="mb-2">Copy and paste this code to embed the security scanner in your website:</p>
        
        <div className="bg-gray-100 p-4 rounded-md mb-2 overflow-auto" style={{ maxHeight: '200px' }}>
          <pre><code>{generateEmbedCode()}</code></pre>
        </div>
        
        <button
          className="button button-primary"
          onClick={() => {
            navigator.clipboard.writeText(generateEmbedCode());
            alert('Embed code copied to clipboard!');
          }}
        >
          Copy Code
        </button>
      </div>
      
      <div className="mb-6">
        <h3 className="text-lg font-medium mb-2">Iframe Embed Code</h3>
        <p className="mb-2">Alternatively, you can use an iframe to embed the scanner:</p>
        
        <div className="bg-gray-100 p-4 rounded-md mb-2 overflow-auto" style={{ maxHeight: '200px' }}>
          <pre><code>{generateIframeCode()}</code></pre>
        </div>
        
        <button
          className="button button-primary"
          onClick={() => {
            navigator.clipboard.writeText(generateIframeCode());
            alert('Iframe code copied to clipboard!');
          }}
        >
          Copy Code
        </button>
      </div>
      
      <div>
        <h3 className="text-lg font-medium mb-2">API Documentation</h3>
        <p>
          For more advanced integrations, you can use our API directly. Please refer to our 
          <a href="#" className="text-blue-600 hover:underline"> API documentation</a> for more details.
        </p>
      </div>
    </div>
  );
}
