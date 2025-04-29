import { NextRequest, NextResponse } from 'next/server';
import { Vulnerability, ScanResult } from '../../../types';

export async function POST(request: NextRequest) {
  try {
    const { target, scanType, advanced } = await request.json();
    
    // Extract authorization if present
    const authHeader = request.headers.get('authorization');
    const token = authHeader ? authHeader.replace('Bearer ', '') : null;
    
    // Map scan type to MCP tool
    // Using the exact tool names allowed by the server: subfinder, naabu, httpx, nuclei, cdncheck, tlsx, ffuf, gobuster, dnsx
    const toolMapping: Record<string, string> = {
      'subdomain': 'subfinder',
      'ports': 'naabu',
      'http': 'httpx',
      'cdn': 'cdncheck',
      'ssl': 'tlsx',
      'fuzz': 'ffuf',
      'dir': 'gobuster',
      'dns': 'dnsx'
    };
    
    const toolName = toolMapping[scanType] || 'subfinder';
    
    // Prepare arguments for the MCP tool
    const args = {
      target,
      ...advanced,
      auth_token: token
    };
    
    // Call MCP tool
    let mcpResult;
    try {
      // Use the remote MCP server directly
      mcpResult = await callMcpTool(toolName, args);
    } catch (mcpError) {
      console.error('MCP tool error:', mcpError);
      return NextResponse.json(
        { error: `MCP tool error: ${mcpError instanceof Error ? mcpError.message : String(mcpError)}` },
        { status: 500 }
      );
    }
    
    // Process results into our application's format
    const processedResult = processSecurityResults(mcpResult, target, scanType);
    
    return NextResponse.json(processedResult);
  } catch (error) {
    console.error('Security scan error:', error);
    return NextResponse.json(
      { error: 'Failed to perform security scan' },
      { status: 500 }
    );
  }
}

// Helper function to call MCP tool using the external MCP server
async function callMcpTool(toolName: string, args: any) {
  console.log(`Calling MCP tool: ${toolName} with args:`, args);
  
  try {
    // Format arguments according to tool requirements
    // For the remote server, we need to format arguments differently based on the tool
    let formattedArgs = '';
    
    // Handle tool-specific argument formatting
    if (toolName === 'subfinder') {
      // subfinder expects -d for domain
      formattedArgs += `-d ${args.target} `;
      if (args.threads) formattedArgs += `-t ${args.threads} `;
      if (args.timeout) formattedArgs += `-timeout ${args.timeout} `;
      // Add silent mode for cleaner output
      formattedArgs += `-silent `;
    } 
    else if (toolName === 'naabu') {
      // naabu expects -host for target
      formattedArgs += `-host ${args.target} `;
      if (args.ports) formattedArgs += `-p ${args.ports} `;
      if (args.threads) formattedArgs += `-c ${args.threads} `;
      // Add silent mode for cleaner output
      formattedArgs += `-silent `;
    }
    else if (toolName === 'httpx') {
      // httpx uses -u for URL
      formattedArgs += `-u ${args.target} `;
      if (args.threads) formattedArgs += `-threads ${args.threads} `;
      // Add silent mode for cleaner output
      formattedArgs += `-silent -json `;
    }
    else if (toolName === 'cdncheck') {
      // cdncheck uses -domain
      formattedArgs += `-domain ${args.target} `;
      if (args.resolver) formattedArgs += `-resolver ${args.resolver} `;
    }
    else if (toolName === 'tlsx') {
      // tlsx uses -u for URL
      formattedArgs += `-u ${args.target} `;
      if (args.port) formattedArgs += `-p ${args.port} `;
      if (args.threads) formattedArgs += `-c ${args.threads} `;
      if (args.resolver) formattedArgs += `-resolver ${args.resolver} `;
      // Add silent mode for cleaner output
      formattedArgs += `-silent -json `;
    }
    else if (toolName === 'ffuf') {
      // ffuf uses -u for URL with FUZZ keyword
      formattedArgs += `-u ${args.target}/FUZZ `;
      if (args.threads) formattedArgs += `-t ${args.threads} `;
      // Add a default wordlist if not provided
      if (args.wordlist) {
        formattedArgs += `-w ${args.wordlist} `;
      } else {
        // Use a common wordlist
        formattedArgs += `-w /usr/share/wordlists/dirb/common.txt `;
      }
      // Add silent mode
      formattedArgs += `-s `;
    }
    else if (toolName === 'gobuster') {
      // gobuster requires a mode (dir is most common)
      formattedArgs += `dir -u ${args.target} `;
      if (args.threads) formattedArgs += `-t ${args.threads} `;
      // Add a default wordlist if not provided
      if (args.wordlist) {
        formattedArgs += `-w ${args.wordlist} `;
      } else {
        // Use a common wordlist
        formattedArgs += `-w /usr/share/wordlists/dirb/common.txt `;
      }
      // Add quiet mode
      formattedArgs += `-q `;
    }
    else if (toolName === 'dnsx') {
      // dnsx uses -d for domain
      formattedArgs += `-d ${args.target} `;
      if (args.threads) formattedArgs += `-t ${args.threads} `;
      if (args.resolver) formattedArgs += `-r ${args.resolver} `;
      // Add silent and JSON output
      formattedArgs += `-silent -json `;
    }
    else if (toolName === 'nuclei') {
      // nuclei uses -u for URL
      formattedArgs += `-u ${args.target} `;
      if (args.threads) formattedArgs += `-c ${args.threads} `;
      // Add silent mode
      formattedArgs += `-silent -json `;
    }
    
    // Add any custom headers if provided
    if (args.headers && typeof args.headers === 'object') {
      const headerString = JSON.stringify(args.headers);
      formattedArgs += `--headers ${headerString} `;
    }

    // Add user agent if provided
    if (args.userAgent) {
      formattedArgs += `--userAgent "${args.userAgent}" `;
    }
    
    // Add timeout if provided
    if (args.timeout) {
      formattedArgs += `--timeout ${args.timeout} `;
    }
    
    // Make a request to the external MCP server
    const response = await fetch('https://mcp.attck-deploy.net/api/run', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-Request-Source': 'vercel-security-scanner'
      },
      body: JSON.stringify({
        tool: toolName,
        args: formattedArgs.trim()
      }),
    });
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => 'No error details available');
      throw new Error(`MCP server responded with status: ${response.status}: ${errorText}`);
    }
    
    let result;
    try {
      result = await response.json();
    } catch (jsonError) {
      // If not valid JSON, try to handle as text
      const text = await response.text();
      result = {
        stdout: text,
        stderr: '',
        returncode: 0
      };
    }
    
    // Process the raw output to extract findings
    const output = result.stdout || result.raw_output || '';
    const stderr = result.stderr || '';
    
    // Log the raw output for debugging
    console.log(`Tool ${toolName} output:`, output);
    if (stderr) console.log(`Tool ${toolName} stderr:`, stderr);
    
    if (result.returncode !== 0 && result.returncode !== undefined) {
      console.warn(`Tool execution returned non-zero code: ${result.returncode}`);
      // We'll continue processing but log the warning
    }
    
    // Parse the output based on the tool and convert to findings
    const findings = parseScanOutput(output, toolName, args.target);
    
    return {
      findings,
      metadata: {
        tool: toolName,
        scanDuration: extractScanDuration(output) || "N/A",
        timestamp: new Date().toISOString()
      },
      raw_output: output
    };
  } catch (error) {
    console.error('Error calling MCP tool:', error);
    throw error;
  }
}

// Helper function to parse scan output and convert to findings
function parseScanOutput(output: string, toolName: string, target: string): any[] {
  const findings: any[] = [];
  
  try {
    // Different parsing logic based on the tool
    if (toolName === 'subfinder') {
      // Try to parse JSON output
      try {
        const lines = output.split('\n').filter(line => line.trim());
        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            findings.push({
              title: "Subdomain Discovery",
              severity: "info",
              description: `Found subdomain: ${data.host || data.subdomain}`,
              location: data.host || data.subdomain || 'Unknown',
              remediation: "Ensure all subdomains have proper security controls"
            });
          } catch (e) {
            // Skip non-JSON lines
          }
        }
      } catch (e) {
        // Fallback to regex parsing if JSON parsing fails
        const subdomainRegex = /(?:https?:\/\/)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z0-9][-a-zA-Z0-9]*/g;
        const matches = output.match(subdomainRegex) || [];
        
        matches.forEach(subdomain => {
          findings.push({
            title: "Subdomain Discovery",
            severity: "info",
            description: `Found subdomain: ${subdomain}`,
            location: subdomain,
            remediation: "Ensure all subdomains have proper security controls"
          });
        });
      }
    } else if (toolName === 'naabu') {
      try {
        const lines = output.split('\n').filter(line => line.trim());
        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            if (data.port) {
              let severity = "low";
              if ([21, 22, 23, 3389, 3306, 1433, 5432].includes(Number(data.port))) {
                severity = "high";
              } else if ([80, 443, 8080, 8443].includes(Number(data.port))) {
                severity = "medium";
              }
              
              findings.push({
                title: `Open Port ${data.port} (${getServiceName(data.port)})`,
                severity,
                description: `Port ${data.port} is open on ${data.host || target}`,
                location: `${data.host || target}:${data.port}`,
                remediation: "Close unnecessary ports or apply proper firewall rules"
              });
            }
          } catch (e) {
            // Skip non-JSON lines
          }
        }
      } catch (e) {
        // Fallback parsing for non-JSON output
        const portRegex = /(?:host|ip|target)[:\s]+([^:\s]+)[:\s]+port[:\s]+(\d+)/gi;
        let match;
        while ((match = portRegex.exec(output)) !== null) {
          const host = match[1];
          const port = match[2];
          
          findings.push({
            title: `Open Port ${port} (${getServiceName(port)})`,
            severity: "medium",
            description: `Port ${port} is open on ${host || target}`,
            location: `${host || target}:${port}`,
            remediation: "Close unnecessary ports or apply proper firewall rules"
          });
        }
      }
    } else if (toolName === 'httpx') {
      try {
        const lines = output.split('\n').filter(line => line.trim());
        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            if (data.url) {
              const technologies = data.technologies || [];
              const techList = Array.isArray(technologies) ? technologies.join(', ') : technologies;
              
              findings.push({
                title: `HTTP Service: ${data.status_code || 'Unknown'}`,
                severity: getSeverityFromStatusCode(data.status_code),
                description: `Found HTTP service at ${data.url}\nTitle: ${data.title || 'N/A'}\nTechnologies: ${techList || 'N/A'}\nServer: ${data.server || 'N/A'}`,
                location: data.url,
                remediation: "Secure HTTP services with proper headers and encryption"
              });
            }
          } catch (e) {
            // Skip non-JSON lines
          }
        }
      } catch (e) {
        // Fallback for non-JSON output
        findings.push({
          title: "HTTP Service Analysis",
          severity: "info",
          description: "HTTP service analysis results (raw format not recognized)",
          location: target,
          remediation: "Review raw output for details"
        });
      }
    } else if (toolName === 'tlsx') {
      try {
        const lines = output.split('\n').filter(line => line.trim());
        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            if (data.host) {
              findings.push({
                title: "SSL/TLS Configuration",
                severity: "medium",
                description: `SSL/TLS details for ${data.host}\nVersion: ${data.tls_version || 'Unknown'}\nCipher: ${data.cipher || 'Unknown'}`,
                location: data.host,
                remediation: "Ensure strong TLS versions (TLS 1.2+) and secure cipher suites"
              });
              
              // Add vulnerable configuration findings
              if (data.tls_version && ['TLS 1.0', 'SSL 3.0', 'SSL 2.0'].includes(data.tls_version)) {
                findings.push({
                  title: "Vulnerable TLS Version",
                  severity: "critical",
                  description: `Outdated TLS version detected: ${data.tls_version}`,
                  location: data.host,
                  remediation: "Disable outdated TLS versions (TLS 1.0, SSL 3.0, SSL 2.0) and use TLS 1.2+ only"
                });
              }
            }
          } catch (e) {
            // Skip non-JSON lines
          }
        }
      } catch (e) {
        // Fallback for non-JSON output
        findings.push({
          title: "SSL/TLS Analysis",
          severity: "info",
          description: "SSL/TLS analysis results (raw format not recognized)",
          location: target,
          remediation: "Review raw output for details"
        });
      }
    } else {
      // Generic finding for other tools
      findings.push({
        title: `${toolName.charAt(0).toUpperCase() + toolName.slice(1).replace(/_/g, ' ')} Results`,
        severity: "info",
        description: `Scan completed for ${target}`,
        location: target,
        remediation: "Review raw output for details"
      });
    }
  } catch (error) {
    console.error(`Error parsing scan output for ${toolName}:`, error);
    findings.push({
      title: "Scan Result",
      severity: "info",
      description: "Unable to parse scan results automatically",
      location: target,
      remediation: "Review raw output for details"
    });
  }
  
  // If no findings were parsed, add a default finding
  if (findings.length === 0) {
    findings.push({
      title: "No Issues Found",
      severity: "info",
      description: `No issues were found in the ${toolName} scan`,
      location: target,
      remediation: "No action needed"
    });
  }
  
  return findings;
}

// Helper function to extract scan duration from output
function extractScanDuration(output: string): string | null {
  const durationRegex = /completed in (\d+[\.\d]*\s*[a-z]+)/i;
  const match = output.match(durationRegex);
  return match ? match[1] : null;
}

// Helper function to get service name from port number
function getServiceName(port: string | number): string {
  const portNum = Number(port);
  const portMap: Record<number, string> = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    1433: 'MSSQL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt'
  };
  
  return portMap[portNum] || 'Unknown';
}

// Helper function to determine severity from HTTP status code
function getSeverityFromStatusCode(statusCode: number | string): string {
  if (!statusCode) return "info";
  
  const code = Number(statusCode);
  if (code >= 500) return "high";
  if (code >= 400) return "medium";
  if (code >= 300) return "low";
  return "info";
}

// Process and format security results
function processSecurityResults(mcpResult: any, target: string, scanType: string): ScanResult {
  // Convert the raw output from the security tools into structured data
  
  // Create vulnerabilities array based on findings
  const vulnerabilities: Vulnerability[] = (mcpResult.findings || []).map((finding: any, index: number) => ({
    id: `vuln-${index + 1}`,
    name: finding.title || `Finding #${index + 1}`,
    severity: finding.severity as any || 'medium',
    description: finding.description || 'No description provided',
    location: finding.location || target,
    remediation: finding.remediation || 'No remediation information available'
  }));
  
  // Generate summary
  const summary = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
  };
  
  return {
    target,
    scanType,
    timestamp: new Date().toISOString(),
    vulnerabilities,
    summary,
    rawOutput: mcpResult.raw_output || '', // Include raw output for detailed report
    htmlReport: generateHtmlReport(vulnerabilities, summary, target, scanType)
  };
}

// Generate HTML report
function generateHtmlReport(
  vulnerabilities: Vulnerability[], 
  summary: any, 
  target: string, 
  scanType: string
): string {
  // Create HTML content for download
  return `
    <div class="security-report">
      <h1>Security Audit Report</h1>
      <div class="report-metadata">
        <p><strong>Target:</strong> ${target}</p>
        <p><strong>Scan Type:</strong> ${scanType}</p>
        <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
      </div>
      
      <div class="summary-section">
        <h2>Summary</h2>
        <ul>
          <li>Total Findings: ${summary.total}</li>
          <li>Critical: ${summary.critical}</li>
          <li>High: ${summary.high}</li>
          <li>Medium: ${summary.medium}</li>
          <li>Low: ${summary.low}</li>
        </ul>
      </div>
      
      <div class="findings-section">
        <h2>Detailed Findings</h2>
        ${vulnerabilities.map(v => `
          <div class="finding ${v.severity}">
            <h3>${v.name} <span class="severity">(${v.severity})</span></h3>
            <p><strong>Location:</strong> ${v.location}</p>
            <p><strong>Description:</strong> ${v.description}</p>
            <p><strong>Remediation:</strong> ${v.remediation}</p>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}
