export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Vulnerability {
  id: string;
  name: string;
  severity: VulnerabilitySeverity;
  description: string;
  location: string;
  remediation: string;
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
}

export interface EmbedOptions {
  target?: string;
  defaultScanType?: 'quick' | 'full';
  theme?: 'light' | 'dark' | 'auto';
  width?: string;
  height?: string;
  apiKey?: string;
  onScanComplete?: (result: ScanResult) => void;
}
