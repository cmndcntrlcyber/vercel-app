export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Vulnerability {
  id: string;
  name: string;
  severity: VulnerabilitySeverity;
  description: string;
  location: string;
  remediation: string;
  details?: any; // For tool-specific details
}

export interface ScanResult {
  target: string;
  scanType: string;
  timestamp: string;
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  rawOutput?: string; // Raw tool output
  htmlReport?: string; // HTML report content
}

export interface ScanRequest {
  target: string;
  scanType: string;
  advanced?: {
    userAgent?: string;
    timeout?: number;
    threads?: number;
    headers?: Record<string, string>;
    [key: string]: any; // Additional parameters
  };
}

export interface EmbedOptions {
  target?: string;
  defaultScanType?: 'subdomain' | 'ports' | 'http' | 'cdn' | 'ssl' | 'fuzz' | 'dir' | 'dns';
  theme?: 'light' | 'dark' | 'auto';
  width?: string;
  height?: string;
  apiKey?: string;
  onScanComplete?: (result: ScanResult) => void;
}
