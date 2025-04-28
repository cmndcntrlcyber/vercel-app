'use client';

import { useState, FormEvent } from 'react';
import { Vulnerability, ScanResult } from '../types';

// Mock API function to simulate a security scan
const performSecurityScan = async (target: string, scanType: string): Promise<ScanResult> => {
  // Simulate API call delay
  await new Promise(resolve => setTimeout(resolve, 1500));

  // Generate some mock vulnerabilities based on scan type
  const vulnerabilities: Vulnerability[] = [];
  
  if (scanType === 'quick' || scanType === 'full') {
    vulnerabilities.push({
      id: '1',
      name: 'Cross-Site Scripting (XSS)',
      severity: 'high',
      description: 'Found potential XSS vulnerability in form submission.',
      location: `${target}/contact`,
      remediation: 'Implement proper input validation and output encoding.'
    });
    
    vulnerabilities.push({
      id: '2',
      name: 'Outdated Software',
      severity: 'medium',
      description: 'The server is running an outdated version of Apache.',
      location: target,
      remediation: 'Update to the latest version and apply security patches.'
    });
  }
  
  if (scanType === 'full') {
    vulnerabilities.push({
      id: '3',
      name: 'Insecure Cookie Configuration',
      severity: 'medium',
      description: 'Cookies are missing secure and HttpOnly flags.',
      location: target,
      remediation: 'Configure cookies with secure and HttpOnly flags.'
    });
    
    vulnerabilities.push({
      id: '4',
      name: 'SQL Injection',
      severity: 'critical',
      description: 'Potential SQL injection vulnerability detected in search function.',
      location: `${target}/search`,
      remediation: 'Use parameterized queries and input validation.'
    });
    
    vulnerabilities.push({
      id: '5',
      name: 'Missing Security Headers',
      severity: 'low',
      description: 'Security headers like Content-Security-Policy are missing.',
      location: target,
      remediation: 'Implement proper security headers.'
    });
  }
  
  return {
    target,
    scanType,
    timestamp: new Date().toISOString(),
    vulnerabilities,
    summary: {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length,
    }
  };
};

export default function SecurityScanner() {
  const [target, setTarget] = useState('https://example.com');
  const [scanType, setScanType] = useState('quick');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    
    if (!target) {
      setError('Please enter a target URL');
      return;
    }
    
    try {
      setIsScanning(true);
      setError(null);
      setScanResult(null);
      
      const result = await performSecurityScan(target, scanType);
      setScanResult(result);
    } catch (err) {
      setError('An error occurred during the scan.');
      console.error(err);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="widget-container">
      <div className="widget-header">
        <h2>Security Vulnerability Scanner</h2>
        {isScanning && <span className="status-badge status-scanning">Scanning...</span>}
      </div>
      
      <div className="widget-content">
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="target" className="form-label">Target URL</label>
            <input
              id="target"
              type="url"
              className="form-input"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="scanType" className="form-label">Scan Type</label>
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
          
          <button
            type="submit"
            className="button button-primary"
            disabled={isScanning}
          >
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </button>
        </form>
        
        {error && (
          <div className="results-container">
            <p style={{ color: 'var(--danger)' }}>{error}</p>
          </div>
        )}
        
        {scanResult && (
          <div className="results-container">
            <h3>Scan Results</h3>
            <p>
              <strong>Target:</strong> {scanResult.target}<br />
              <strong>Scan Type:</strong> {scanResult.scanType === 'quick' ? 'Quick Scan' : 'Full Scan'}<br />
              <strong>Time:</strong> {new Date(scanResult.timestamp).toLocaleString()}
            </p>
            
            <div style={{ marginTop: '1rem' }}>
              <h4>Summary</h4>
              <ul>
                <li>Total Vulnerabilities: {scanResult.summary.total}</li>
                <li>Critical: {scanResult.summary.critical}</li>
                <li>High: {scanResult.summary.high}</li>
                <li>Medium: {scanResult.summary.medium}</li>
                <li>Low: {scanResult.summary.low}</li>
              </ul>
            </div>
            
            {scanResult.vulnerabilities.length > 0 ? (
              <div style={{ marginTop: '1rem' }}>
                <h4>Vulnerabilities</h4>
                {scanResult.vulnerabilities.map((vuln) => (
                  <div key={vuln.id} className="result-item">
                    <h5 className={`severity-${vuln.severity}`}>
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
          </div>
        )}
      </div>
    </div>
  );
}
