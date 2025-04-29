'use client';

import { useState, FormEvent, useRef, useEffect } from 'react';
import { Vulnerability, ScanResult, ScanRequest } from '../types';

// Real API function to perform security scans using our backend
const performSecurityScan = async (
  target: string, 
  scanType: string, 
  authToken?: string, 
  advanced?: any
): Promise<ScanResult> => {
  const requestBody: ScanRequest = {
    target,
    scanType,
    advanced
  };

  const headers: HeadersInit = {
    'Content-Type': 'application/json'
  };
  
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  let response;
  try {
    response = await fetch('/api/security-scan', {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody),
      // Set longer timeout for security scans which can take time
      signal: AbortSignal.timeout(120000) // 2 minute timeout
    });

    if (!response.ok) {
      let errorMessage = 'Failed to perform security scan';
      try {
        const errorData = await response.json();
        errorMessage = errorData.error || errorMessage;
      } catch (e) {
        // If not JSON, try to get text
        try {
          errorMessage = await response.text();
        } catch (textError) {
          // Keep default error message
        }
      }
      throw new Error(errorMessage);
    }

    return response.json();
  } catch (error) {
    // Handle fetch errors (network issues, timeouts)
    if (error instanceof TypeError && error.message.includes('NetworkError')) {
      throw new Error('Network error: Unable to connect to the security scanner API. Please check your connection.');
    } else if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error('The security scan timed out. The target may be unavailable or the scan is too intensive.');
    }
    throw error;
  }
};

export default function SecurityScanner() {
  const [target, setTarget] = useState('https://example.com');
  const [scanType, setScanType] = useState('subdomain');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanStatusMessage, setScanStatusMessage] = useState<string>('');
  
  // Advanced options state
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [authToken, setAuthToken] = useState('');
  const [userAgent, setUserAgent] = useState('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
  const [timeout, setTimeout] = useState(30);
  const [customHeaders, setCustomHeaders] = useState('');
  
  // Dark mode detection
  const [isDarkMode, setIsDarkMode] = useState(false);
  
  // Effect to detect dark mode
  useEffect(() => {
    // Check if window is available (client-side)
    if (typeof window !== 'undefined') {
      // Check initial preference
      const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      setIsDarkMode(darkModeMediaQuery.matches);
      
      // Set up listener for changes
      const darkModeChangeHandler = (e: MediaQueryListEvent) => {
        setIsDarkMode(e.matches);
      };
      
      // Add listener
      darkModeMediaQuery.addEventListener('change', darkModeChangeHandler);
      
      // Clean up
      return () => {
        darkModeMediaQuery.removeEventListener('change', darkModeChangeHandler);
      };
    }
  });
  
  // HTML report reference for download
  const reportRef = useRef<HTMLDivElement>(null);

  // Function to validate target input
  const isValidTarget = (input: string): boolean => {
    // Domain regex - basic validation, allows subdomains
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    
    // URL regex - checks for valid protocol and domain structure
    const urlRegex = /^(https?:\/\/)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]*)?$/;
    
    // IP address regex (IPv4)
    const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
    
    return domainRegex.test(input) || urlRegex.test(input) || ipv4Regex.test(input);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (!target) {
      setError('Please enter a target URL, domain, or IP address');
      return;
    }
    
    try {
      setIsScanning(true);
      setError(null);
      setScanResult(null);
      
      // Parse custom headers if provided
      let headersParsed = {};
      if (customHeaders.trim()) {
        try {
          headersParsed = JSON.parse(customHeaders);
        } catch (err) {
          setError('Invalid custom headers JSON format');
          setIsScanning(false);
          return;
        }
      }
      
      // Check if the target is valid
      if (!isValidTarget(target)) {
        setError('Invalid target format. Please enter a valid domain, URL, or IP address.');
        setIsScanning(false);
        return;
      }
      
      // Build advanced options with proper typing for the tool
      const advancedOptions: Record<string, any> = {
        userAgent,
        timeout: parseInt(String(timeout), 10) || 30,
        headers: headersParsed
      };
      
      // Add scan-specific parameters
      if (scanType === 'ports') {
        advancedOptions.ports = "80,443,8080,8443"; // Default common ports
      } else if (scanType === 'subdomain') {
        advancedOptions.threads = 10; // Reasonable thread count
      } else if (scanType === 'fuzz') {
        advancedOptions.threads = 10;
      }
      
      setScanStatusMessage(`Connecting to security scanner at mcp.attck-deploy.net...`);
      
      const result = await performSecurityScan(target, scanType, authToken.trim() || undefined, advancedOptions);
      setScanResult(result);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      setError(`Security scan error: ${errorMessage}`);
      console.error('Scan error:', err);
    } finally {
      setIsScanning(false);
      setScanStatusMessage('');
    }
  };
  
  // Function to download HTML report
  const downloadReport = () => {
    if (!scanResult?.htmlReport) return;
    
    const blob = new Blob([`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Security Scan Report - ${target}</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .critical { color: #d32f2f; font-weight: bold; }
            .high { color: #f44336; font-weight: bold; }
            .medium { color: #ff9800; font-weight: bold; }
            .low { color: #ffc107; font-weight: bold; }
            .info { color: #2196f3; font-weight: bold; }
            .finding { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 4px; }
            h1, h2, h3 { color: #333; }
            .summary-section { background-color: #f5f5f5; padding: 15px; border-radius: 4px; }
          </style>
        </head>
        <body>
          ${scanResult.htmlReport}
        </body>
      </html>
    `], { type: 'text/html' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `security-scan-${target.replace(/[^a-z0-9]/gi, '-')}-${new Date().toISOString().slice(0,10)}.html`;
    link.click();
  };

  // Map scan types to display names
  const scanTypeNames: Record<string, string> = {
    'subdomain': 'Subdomain Discovery',
    'ports': 'Port Scanning',
    'http': 'HTTP Service Analysis',
    'cdn': 'CDN Detection',
    'ssl': 'SSL/TLS Analysis',
    'fuzz': 'Endpoint Fuzzing',
    'dir': 'Directory Enumeration',
    'dns': 'DNS Analysis'
  };

  return (
    <div className="widget-container" style={{
      maxWidth: "800px",
      margin: "0 auto",
      padding: "20px",
      boxSizing: "border-box",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      width: "100%",
      backgroundColor: isDarkMode ? "#111827" : "#ffffff",
      color: isDarkMode ? "#ffffff" : "#1a202c"
    }}>
      <div className="widget-header" style={{
        width: "100%",
        textAlign: "center",
        marginBottom: "30px"
      }}>

        <div className="scan-status">
          {isScanning && <span className="status-badge status-scanning">Scanning...</span>}
          {scanStatusMessage && <p className="status-message">{scanStatusMessage}</p>}
        </div>
        
        <form onSubmit={handleSubmit} style={{
          width: "100%",
          maxWidth: "500px",
          margin: "0 auto",
          display: "flex",
          flexDirection: "column",
          alignItems: "center"
        }}>
          <div style={{
            display: "flex",
            justifyContent: "space-between",
            width: "100%",
            backgroundColor: "#2563eb",
            borderRadius: "8px",
            padding: "20px",
            color: "white",
            marginBottom: "20px"
          }}>
            <div style={{
              flexGrow: 1,
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              alignItems: "flex-start"
            }}>
            </div>
            
            <div style={{
              flexGrow: 1,
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
              alignItems: "flex-end",
              gap: "15px"
            }}>
              <div style={{ width: "100%" }}>
                <label htmlFor="target" className="form-label" style={{
                  display: "block",
                  marginBottom: "5px",
                  fontWeight: "bold",
                  color: "white",
                  textAlign: "left"
                }}>Target URL/Domain/IP</label>
                <input
                  id="target"
                  type="text"
                  className="form-input"
                  style={{
                    width: "100%",
                    padding: "10px",
                    borderRadius: "4px",
                    border: "none",
                    fontSize: "16px"
                  }}
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://example.com or example.com or 192.168.1.1"
                  required
                />
              </div>
              
              <div style={{ width: "100%" }}>
                <label htmlFor="scanType" className="form-label" style={{
                  display: "block",
                  marginBottom: "5px",
                  fontWeight: "bold",
                  color: "white",
                  textAlign: "left"
                }}>Scan Type</label>
                <select
                  id="scanType"
                  className="form-select"
                  style={{
                    width: "100%",
                    padding: "10px",
                    borderRadius: "4px",
                    border: "none",
                    fontSize: "16px",
                    backgroundColor: "white"
                  }}
                  value={scanType}
                  onChange={(e) => setScanType(e.target.value)}
                >
                  <option value="subdomain">Subdomain Discovery</option>
                  <option value="ports">Port Scanning</option>
                  <option value="http">HTTP Service Analysis</option>
                  <option value="cdn">CDN Detection</option>
                  <option value="ssl">SSL/TLS Analysis</option>
                  <option value="fuzz">Endpoint Fuzzing</option>
                  <option value="dir">Directory Enumeration</option>
                  <option value="dns">DNS Analysis</option>
                </select>
              </div>
              
              <button
                type="submit"
                className="button button-primary"
                disabled={isScanning}
                style={{
                  backgroundColor: '#0070f3',
                  color: 'white',
                  border: 'none',
                  padding: '12px 24px',
                  borderRadius: '4px',
                  cursor: isScanning ? 'not-allowed' : 'pointer',
                  opacity: isScanning ? 0.7 : 1,
                  fontSize: '16px',
                  fontWeight: 'bold',
                  width: '100%'
                }}
              >
                {isScanning ? 'Scanning...' : 'Start Security Audit'}
              </button>
            </div>
          </div>
          
          <div className="form-advanced" style={{
            width: "100%",
            textAlign: "center",
            marginBottom: "15px"
          }}>
            <button 
              type="button" 
              className="toggle-advanced"
              onClick={() => setShowAdvanced(!showAdvanced)}
              style={{ 
                background: 'none', 
                border: 'none', 
                color: '#0070f3', 
                cursor: 'pointer',
                textDecoration: 'underline',
                marginBottom: '1rem',
                display: 'block'
              }}
            >
              {showAdvanced ? 'Hide' : 'Show'} Advanced Options
            </button>
            
            {showAdvanced && (
              <div className="advanced-options" style={{ 
                border: isDarkMode ? '1px solid #eaeaea' : '1px solid #eaeaea',
                borderRadius: '5px',
                padding: '1rem',
                marginBottom: '1rem',
                width: '100%',
                backgroundColor: isDarkMode ? '#1a202c' : 'white',
                color: isDarkMode ? '#e2e8f0' : '#1a202c'
              }}>
                <div className="form-group">
                  <label htmlFor="authToken" className="form-label">Authentication Token</label>
                  <input
                    id="authToken"
                    type="password"
                    className="form-input"
                    value={authToken}
                    onChange={(e) => setAuthToken(e.target.value)}
                    placeholder="Bearer token for authenticated scans"
                  />
                </div>
                
                <div className="form-group">
                  <label htmlFor="userAgent" className="form-label">User Agent</label>
                  <input
                    id="userAgent"
                    type="text"
                    className="form-input"
                    value={userAgent}
                    onChange={(e) => setUserAgent(e.target.value)}
                    placeholder="User-Agent header"
                  />
                </div>
                
                <div className="form-group">
                  <label htmlFor="timeout" className="form-label">Timeout (seconds)</label>
                  <input
                    id="timeout"
                    type="number"
                    className="form-input"
                    value={timeout}
                    onChange={(e) => setTimeout(parseInt(e.target.value) || 30)}
                    min="1"
                    max="300"
                  />
                </div>
                
                <div className="form-group">
                  <label htmlFor="customHeaders" className="form-label">Custom Headers (JSON)</label>
                  <textarea
                    id="customHeaders"
                    className="form-textarea"
                    value={customHeaders}
                    onChange={(e) => setCustomHeaders(e.target.value)}
                    placeholder='{"X-Custom-Header": "value", "Another-Header": "value"}'
                    style={{
                      width: '100%',
                      height: '100px',
                      fontFamily: 'monospace'
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        </form>
        
        {error && (
          <div className="results-container error" style={{ 
            color: '#d32f2f', 
            marginTop: '1rem',
            maxWidth: '500px',
            margin: '1rem auto',
            textAlign: 'center' 
          }}>
            <p>{error}</p>
          </div>
        )}
        
        {scanResult && (
          <div className="results-container" style={{ 
            marginTop: '2rem',
            width: '100%',
            maxWidth: '600px',
            margin: '2rem auto',
            border: isDarkMode ? '1px solid #2d3748' : '1px solid #eaeaea',
            borderRadius: '8px',
            padding: '20px',
            boxShadow: isDarkMode ? '0 2px 10px rgba(0,0,0,0.3)' : '0 2px 10px rgba(0,0,0,0.1)',
            backgroundColor: isDarkMode ? '#1a202c' : 'white',
            color: isDarkMode ? 'white' : 'black'
          }}>
            <div className="results-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>Scan Results</h3>
              <button 
                onClick={downloadReport} 
                className="button button-secondary"
                style={{
                  backgroundColor: '#f0f0f0',
                  border: '1px solid #ddd',
                  padding: '0.3rem 0.8rem',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Download HTML Report
              </button>
            </div>
            
            <p style={{ color: isDarkMode ? '#e2e8f0' : '#1a202c' }}>
              <strong>Target:</strong> {scanResult.target}<br />
              <strong>Scan Type:</strong> {scanTypeNames[scanResult.scanType] || scanResult.scanType}<br />
              <strong>Time:</strong> {new Date(scanResult.timestamp).toLocaleString()}
            </p>
            
            <div style={{ marginTop: '1rem' }}>
              <h4 style={{ color: isDarkMode ? 'white' : '#1a202c' }}>Summary</h4>
              <ul style={{ color: isDarkMode ? '#e2e8f0' : '#1a202c' }}>
                <li>Total Vulnerabilities: {scanResult.summary.total}</li>
                <li>Critical: <span style={{ color: '#ff4d4d' }}>{scanResult.summary.critical}</span></li>
                <li>High: <span style={{ color: '#ff6b6b' }}>{scanResult.summary.high}</span></li>
                <li>Medium: <span style={{ color: '#ffa94d' }}>{scanResult.summary.medium}</span></li>
                <li>Low: <span style={{ color: '#ffe066' }}>{scanResult.summary.low}</span></li>
              </ul>
            </div>
            
            {scanResult.vulnerabilities.length > 0 ? (
              <div style={{ marginTop: '1rem' }}>
                <h4>Vulnerabilities</h4>
                {scanResult.vulnerabilities.map((vuln) => (
                  <div key={vuln.id} className="result-item" style={{ 
                    border: '1px solid #eaeaea',
                    borderRadius: '5px',
                    padding: '1rem',
                    marginBottom: '1rem'
                  }}>
                    <h5 className={`severity-${vuln.severity}`} style={{ 
                      color: vuln.severity === 'critical' ? '#d32f2f' : 
                             vuln.severity === 'high' ? '#f44336' : 
                             vuln.severity === 'medium' ? '#ff9800' : 
                             vuln.severity === 'low' ? '#ffc107' : '#2196f3'
                    }}>
                      {vuln.name} <span>({vuln.severity})</span>
                    </h5>
                    <p><strong>Location:</strong> {vuln.location}</p>
                    <p>{vuln.description}</p>
                    <p><strong>Remediation:</strong> {vuln.remediation}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p>No vulnerabilities found.</p>
            )}
            
            {scanResult.rawOutput && (
              <div style={{ marginTop: '2rem' }}>
                <h4 style={{ color: isDarkMode ? 'white' : '#1a202c' }}>Raw Output</h4>
                <pre style={{ 
                  backgroundColor: isDarkMode ? '#2d3748' : '#f5f5f5', 
                  color: isDarkMode ? '#e2e8f0' : '#1a202c',
                  padding: '1rem', 
                  borderRadius: '5px',
                  overflowX: 'auto',
                  fontSize: '0.9rem'
                }}>
                  {scanResult.rawOutput}
                </pre>
              </div>
            )}
            
            <div style={{ display: 'none' }} ref={reportRef}>
              {scanResult.htmlReport}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
