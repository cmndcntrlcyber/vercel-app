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
  
  // FFUF-specific options
  const [wordlist, setWordlist] = useState('common.txt');
  const [extensions, setExtensions] = useState('php,html,js');
  const [httpMethods, setHttpMethods] = useState('GET');
  const [matchCodes, setMatchCodes] = useState('200,301,302,307,401,403');
  const [filterCodes, setFilterCodes] = useState('404');
  const [threads, setThreads] = useState(40);
  const [delay, setDelay] = useState(0);
  const [recursion, setRecursion] = useState(false);
  const [recursionDepth, setRecursionDepth] = useState(1);
  
  // Dark mode detection
  const [isDarkMode, setIsDarkMode] = useState(false);
  // Add state for screen width
  const [screenWidth, setScreenWidth] = useState(1024);
  
  // Effect to detect dark mode and screen width
  useEffect(() => {
    // Check if window is available (client-side)
    if (typeof window !== 'undefined') {
      // Check initial preference
      const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      setIsDarkMode(darkModeMediaQuery.matches);
      
      // Set initial screen width
      setScreenWidth(window.innerWidth);
      
      // Set up listener for dark mode changes
      const darkModeChangeHandler = (e: MediaQueryListEvent) => {
        setIsDarkMode(e.matches);
      };
      
      // Set up listener for window resize
      const handleResize = () => {
        setScreenWidth(window.innerWidth);
      };
      
      // Add listeners
      darkModeMediaQuery.addEventListener('change', darkModeChangeHandler);
      window.addEventListener('resize', handleResize);
      
      // Clean up
      return () => {
        darkModeMediaQuery.removeEventListener('change', darkModeChangeHandler);
        window.removeEventListener('resize', handleResize);
      };
    }
  }, []);
  
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
        // Enhanced FFUF parameters
        advancedOptions.wordlist = wordlist;
        advancedOptions.extensions = extensions;
        advancedOptions.methods = httpMethods;
        advancedOptions.match_codes = matchCodes;
        advancedOptions.filter_codes = filterCodes;
        advancedOptions.threads = threads;
        advancedOptions.delay = delay;
        
        // Add recursion settings if enabled
        if (recursion) {
          advancedOptions.recursion = true;
          advancedOptions.recursion_depth = recursionDepth;
        }
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
      maxWidth: "100%",
      margin: "0 auto",
      padding: "16px",
      boxSizing: "border-box",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      width: "100%",
      backgroundColor: isDarkMode ? "#111827" : "#ffffff",
      color: isDarkMode ? "#ffffff" : "#1a202c",
      borderRadius: "8px"
    }}>
      <div className="widget-header" style={{
        width: "100%",
        textAlign: "center",
        marginBottom: "20px"
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
            flexDirection: screenWidth < 768 ? "column" : "row",
            justifyContent: "space-between",
            width: "100%",
            backgroundColor: "#2563eb",
            borderRadius: "12px",
            padding: screenWidth < 768 ? "16px" : "24px",
            color: "white",
            marginBottom: "20px",
            boxShadow: "0 4px 15px rgba(37, 99, 235, 0.3)"
          }}>
            <div style={{
              flexGrow: 1,
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              alignItems: "flex-start",
              paddingRight: screenWidth < 768 ? "0" : "24px",
              borderRight: screenWidth < 768 ? "none" : "1px solid rgba(255, 255, 255, 0.2)",
              borderBottom: screenWidth < 768 ? "1px solid rgba(255, 255, 255, 0.2)" : "none",
              paddingBottom: screenWidth < 768 ? "12px" : "0",
              marginBottom: screenWidth < 768 ? "12px" : "0"
            }}>
              <h3 style={{ margin: "0 0 10px 0", fontSize: "1.5rem", fontWeight: "bold" }}>Security Scanner</h3>
              <p style={{ margin: "0 0 15px 0", fontSize: "0.95rem", opacity: "0.9" }}>
                Scan websites, domains, and IP addresses for security vulnerabilities
              </p>
              <div style={{ display: "flex", alignItems: "center", marginTop: "auto" }}>
                <div style={{ 
                  backgroundColor: "rgba(255, 255, 255, 0.15)", 
                  padding: "6px 10px", 
                  borderRadius: "4px", 
                  display: "flex", 
                  alignItems: "center",
                  marginRight: "10px"
                }}>
                  <span style={{ fontSize: "0.85rem" }}>Powered by MCP Security Tools</span>
                </div>
              </div>
            </div>
            
            <div style={{
              flexGrow: 1,
              display: "flex",
              flexDirection: "column",
              justifyContent: "space-between",
              alignItems: "flex-start",
              paddingLeft: screenWidth < 768 ? "0" : "24px",
              gap: "16px"
            }}>
              <div style={{ width: "100%" }}>
                <label htmlFor="target" className="form-label" style={{
                  display: "block",
                  marginBottom: "8px",
                  fontWeight: "bold",
                  color: "white",
                  textAlign: "left",
                  fontSize: "0.95rem"
                }}>Target URL/Domain/IP</label>
                <input
                  id="target"
                  type="text"
                  className="form-input"
                  style={{
                    width: "100%",
                    padding: "12px",
                    borderRadius: "6px",
                    border: "none",
                    fontSize: "16px",
                    boxShadow: "0 2px 5px rgba(0, 0, 0, 0.1)"
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
                  marginBottom: "8px",
                  fontWeight: "bold",
                  color: "white",
                  textAlign: "left",
                  fontSize: "0.95rem"
                }}>Scan Type</label>
                <select
                  id="scanType"
                  className="form-select"
                  style={{
                    width: "100%",
                    padding: "12px",
                    borderRadius: "6px",
                    border: "none",
                    fontSize: "16px",
                    backgroundColor: "white",
                    boxShadow: "0 2px 5px rgba(0, 0, 0, 0.1)",
                    appearance: "none",
                    backgroundImage: "url(\"data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e\")",
                    backgroundRepeat: "no-repeat",
                    backgroundPosition: "right 1rem center",
                    backgroundSize: "1em"
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
                  padding: '14px 24px',
                  borderRadius: '6px',
                  cursor: isScanning ? 'not-allowed' : 'pointer',
                  opacity: isScanning ? 0.7 : 1,
                  fontSize: '16px',
                  fontWeight: 'bold',
                  width: '100%',
                  boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
                  transition: 'all 0.2s ease',
                  marginTop: '6px'
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
                border: isDarkMode ? '1px solid #2d3748' : '1px solid #eaeaea',
                borderRadius: '8px',
                padding: '1.25rem',
                marginBottom: '1rem',
                width: '100%',
                backgroundColor: isDarkMode ? '#1a202c' : 'white',
                color: isDarkMode ? '#e2e8f0' : '#1a202c',
                boxShadow: isDarkMode ? '0 4px 10px rgba(0, 0, 0, 0.2)' : '0 4px 10px rgba(0, 0, 0, 0.05)'
              }}>
                {/* General advanced options */}
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
                
                {/* FFUF-specific options */}
                {scanType === 'fuzz' && (
                  <div style={{ 
                    marginTop: '15px', 
                    borderTop: isDarkMode ? '1px solid #2d3748' : '1px solid #eaeaea',
                    paddingTop: '15px'
                  }}>
                    <h4 style={{ 
                      marginTop: 0, 
                      marginBottom: '15px', 
                      fontSize: '1.05rem', 
                      color: isDarkMode ? 'white' : '#333',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}>
                      Fuzzing Parameters
                      <span style={{ 
                        fontSize: '0.8rem', 
                        color: isDarkMode ? '#aaa' : '#666',
                        fontWeight: 'normal'
                      }}>
                        (powered by FFUF)
                      </span>
                    </h4>

                    {/* Organized into logical groups with better styling */}
                    <div style={{ marginBottom: '15px' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '15px', marginBottom: '15px' }}>
                        {/* Target options group */}
                        <div style={{ 
                          flex: '1 1 300px', 
                          padding: '12px',
                          border: isDarkMode ? '1px solid #2d3748' : '1px solid #eaeaea',
                          borderRadius: '6px',
                          backgroundColor: isDarkMode ? '#1e293b' : '#f9fafb'
                        }}>
                          <h5 style={{ 
                            marginTop: 0, 
                            marginBottom: '10px', 
                            fontSize: '0.95rem', 
                            color: isDarkMode ? 'white' : '#333',
                            borderBottom: isDarkMode ? '1px solid #3e4c61' : '1px solid #eaeaea',
                            paddingBottom: '6px'
                          }}>
                            Target Options
                          </h5>
                          
                          <div className="form-group" style={{ marginBottom: '12px' }}>
                            <label htmlFor="wordlist" className="form-label" style={{ fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                              Wordlist
                              <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                    title="Dictionary of paths to check on the target server">
                                ⓘ
                              </span>
                            </label>
                            <select
                              id="wordlist"
                              className="form-select"
                              value={wordlist}
                              onChange={(e) => setWordlist(e.target.value)}
                              style={{
                                width: '100%',
                                padding: '8px',
                                borderRadius: '4px',
                                border: '1px solid #ddd',
                                fontSize: '0.9rem'
                              }}
                            >
                              <option value="common.txt">Common Endpoints (small)</option>
                              <option value="directory-list-2.3-small.txt">Directory List 2.3 (small)</option>
                              <option value="directory-list-2.3-medium.txt">Directory List 2.3 (medium)</option>
                              <option value="big.txt">Big Wordlist (comprehensive)</option>
                              <option value="raft-large-directories.txt">RAFT Large Directories</option>
                              <option value="api-endpoints.txt">API Endpoints</option>
                              <option value="swagger-wordlist.txt">Swagger/OpenAPI Endpoints</option>
                            </select>
                          </div>
                          
                          <div className="form-group" style={{ marginBottom: '12px' }}>
                            <label htmlFor="extensions" className="form-label" style={{ fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                              File Extensions
                              <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                    title="File extensions to append to each wordlist entry (comma-separated)">
                                ⓘ
                              </span>
                            </label>
                            <input
                              id="extensions"
                              type="text"
                              className="form-input"
                              value={extensions}
                              onChange={(e) => setExtensions(e.target.value)}
                              placeholder="php,html,js,asp"
                              style={{
                                width: '100%',
                                padding: '8px',
                                borderRadius: '4px',
                                border: '1px solid #ddd',
                                fontSize: '0.9rem'
                              }}
                            />
                          </div>
                          
                          <div className="form-group">
                            <label htmlFor="httpMethods" className="form-label" style={{ fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                              HTTP Methods
                              <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                    title="HTTP methods to use in requests (comma-separated)">
                                ⓘ
                              </span>
                            </label>
                            <input
                              id="httpMethods"
                              type="text"
                              className="form-input"
                              value={httpMethods}
                              onChange={(e) => setHttpMethods(e.target.value)}
                              placeholder="GET,POST,PUT"
                              style={{
                                width: '100%',
                                padding: '8px',
                                borderRadius: '4px',
                                border: '1px solid #ddd',
                                fontSize: '0.9rem'
                              }}
                            />
                          </div>
                        </div>
                          
                        {/* Matching and filtering options */}
                        <div style={{ 
                          flex: '1 1 300px', 
                          padding: '12px',
                          border: isDarkMode ? '1px solid #2d3748' : '1px solid #eaeaea',
                          borderRadius: '6px',
                          backgroundColor: isDarkMode ? '#1e293b' : '#f9fafb'
                        }}>
                          <h5 style={{ 
                            marginTop: 0, 
                            marginBottom: '10px', 
                            fontSize: '0.95rem', 
                            color: isDarkMode ? 'white' : '#333',
                            borderBottom: isDarkMode ? '1px solid #3e4c61' : '1px solid #eaeaea',
                            paddingBottom: '6px'
                          }}>
                            Response Matching
                          </h5>
                          
                          <div className="form-group" style={{ marginBottom: '12px' }}>
                            <label htmlFor="matchCodes" className="form-label" style={{ fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                              Match Status Codes
                              <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                    title="HTTP status codes to consider as 'found' (comma-separated)">
                                ⓘ
                              </span>
                            </label>
                            <input
                              id="matchCodes"
                              type="text"
                              className="form-input"
                              value={matchCodes}
                              onChange={(e) => setMatchCodes(e.target.value)}
                              placeholder="200,301,302,307"
                              style={{
                                width: '100%',
                                padding: '8px',
                                borderRadius: '4px',
                                border: '1px solid #ddd',
                                fontSize: '0.9rem'
                              }}
                            />
                          </div>
                          
                          <div className="form-group">
                            <label htmlFor="filterCodes" className="form-label" style={{ fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                              Filter Status Codes
                              <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                    title="HTTP status codes to exclude from results (comma-separated)">
                                ⓘ
                              </span>
                            </label>
                            <input
                              id="filterCodes"
                              type="text"
                              className="form-input"
                              value={filterCodes}
                              onChange={(e) => setFilterCodes(e.target.value)}
                              placeholder="404,400,500"
                              style={{
                                width: '100%',
                                padding: '8px',
                                borderRadius: '4px',
                                border: '1px solid #ddd',
                                fontSize: '0.9rem'
                              }}
                            />
                          </div>
                        </div>
                      </div>
                      
                      {/* Performance options */}
                      <div style={{ 
                        padding: '12px',
                        border: isDarkMode ? '1px solid #2d3748' : '1px solid #eaeaea',
                        borderRadius: '6px',
                        backgroundColor: isDarkMode ? '#1e293b' : '#f9fafb'
                      }}>
                        <h5 style={{ 
                          marginTop: 0, 
                          marginBottom: '10px', 
                          fontSize: '0.95rem', 
                          color: isDarkMode ? 'white' : '#333',
                          borderBottom: isDarkMode ? '1px solid #3e4c61' : '1px solid #eaeaea',
                          paddingBottom: '6px'
                        }}>
                          Performance Settings
                        </h5>
                        
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '15px' }}>
                          <div className="form-group" style={{ flex: '1 1 120px' }}>
                            <label htmlFor="threads" className="form-label" style={{ fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                              Threads
                              <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                    title="Number of concurrent requests (higher = faster but more resource intensive)">
                                ⓘ
                              </span>
                            </label>
                            <input
                              id="threads"
                              type="number"
                              className="form-input"
                              value={threads}
                              onChange={(e) => setThreads(parseInt(e.target.value) || 40)}
                              min="1"
                              max="200"
                              style={{
                                width: '100%',
                                padding: '8px',
                                borderRadius: '4px',
                                border: '1px solid #ddd',
                                fontSize: '0.9rem'
                              }}
                            />
                          </div>
                          
                          <div className="form-group" style={{ flex: '1 1 120px' }}>
                            <label htmlFor="delay" className="form-label" style={{ fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                              Delay (ms)
                              <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                    title="Delay between requests in milliseconds (higher = less aggressive scanning)">
                                ⓘ
                              </span>
                            </label>
                            <input
                              id="delay"
                              type="number"
                              className="form-input"
                              value={delay}
                              onChange={(e) => setDelay(parseInt(e.target.value) || 0)}
                              min="0"
                              max="5000"
                              style={{
                                width: '100%',
                                padding: '8px',
                                borderRadius: '4px',
                                border: '1px solid #ddd',
                                fontSize: '0.9rem'
                              }}
                            />
                          </div>
                          
                          <div className="form-group" style={{ flex: '2 1 250px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
                              <input
                                id="recursion"
                                type="checkbox"
                                checked={recursion}
                                onChange={(e) => setRecursion(e.target.checked)}
                                style={{ marginRight: '8px' }}
                              />
                              <label htmlFor="recursion" className="form-label" style={{ margin: 0, fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                                Enable Directory Recursion
                                <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                      title="Automatically scan discovered directories">
                                  ⓘ
                                </span>
                              </label>
                            </div>
                            
                            {recursion && (
                              <div style={{ marginLeft: '24px', marginTop: '8px' }}>
                                <label htmlFor="recursionDepth" className="form-label" style={{ fontSize: '0.85rem', fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                                  Recursion Depth
                                  <span style={{ marginLeft: '5px', cursor: 'help', color: '#6b7280', fontSize: '0.9em' }} 
                                        title="Maximum directory depth to scan (higher values take longer)">
                                    ⓘ
                                  </span>
                                </label>
                                <input
                                  id="recursionDepth"
                                  type="number"
                                  className="form-input"
                                  value={recursionDepth}
                                  onChange={(e) => setRecursionDepth(parseInt(e.target.value) || 1)}
                                  min="1"
                                  max="5"
                                  style={{ 
                                    width: '80px',
                                    padding: '8px',
                                    borderRadius: '4px',
                                    border: '1px solid #ddd',
                                    fontSize: '0.9rem'
                                  }}
                                />
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
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
            marginTop: '1.5rem',
            width: '100%',
            maxWidth: '100%',
            margin: '1.5rem auto',
            border: isDarkMode ? '1px solid #2d3748' : '1px solid #eaeaea',
            borderRadius: '8px',
            padding: '16px',
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
              <div style={{ marginTop: '1.5rem' }}>
                <h4 style={{ 
                  color: isDarkMode ? 'white' : '#1a202c',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  borderBottom: isDarkMode ? '1px solid #2d3748' : '1px solid #eaeaea',
                  paddingBottom: '8px'
                }}>
                  <span>Command Output</span>
                  <span style={{ 
                    fontSize: '0.8rem', 
                    color: isDarkMode ? '#aaa' : '#666',
                    fontWeight: 'normal'
                  }}>
                    Technical Details
                  </span>
                </h4>
                <div style={{ 
                  backgroundColor: isDarkMode ? '#2d3748' : '#f5f5f5', 
                  color: isDarkMode ? '#e2e8f0' : '#1a202c',
                  padding: '12px', 
                  borderRadius: '5px',
                  marginTop: '10px',
                  position: 'relative'
                }}>
                  <div style={{ position: 'absolute', top: '8px', right: '12px' }}>
                    <div style={{ 
                      padding: '2px 8px',
                      fontSize: '0.75rem',
                      backgroundColor: isDarkMode ? '#1a202c' : '#e2e8f0',
                      color: isDarkMode ? '#e2e8f0' : '#1a202c',
                      borderRadius: '4px',
                      fontFamily: 'monospace'
                    }}>
                      {scanType === 'fuzz' ? 'ffuf' : scanType} output
                    </div>
                  </div>
                  
                  <pre style={{ 
                    overflowX: 'auto',
                    fontSize: '0.85rem',
                    marginTop: '12px',
                    fontFamily: 'Consolas, Monaco, "Andale Mono", monospace',
                    maxHeight: '300px'
                  }}>
                    {scanResult.rawOutput}
                  </pre>
                </div>
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
