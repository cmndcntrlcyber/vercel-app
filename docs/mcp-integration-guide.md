# Security Scanner MCP Integration Guide

This guide explains how to set up the ExternalAttacker-MCP server to enable actual security scanning capabilities in our application.

## Prerequisites

1. Go installed (for the security tools)
2. Node.js installed (for the MCP server)

## Step 1: Install Required Security Tools

Install the necessary security tools using Go:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/ffuf/ffuf@latest
go install github.com/OJ/gobuster/v3@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

Ensure these tools are available in your PATH.

## Step 2: Clone and Build the ExternalAttacker-MCP Server

```bash
# Clone the repository
git clone https://github.com/cmndcntrlcyber/ExternalAttacker-MCP.git
cd ExternalAttacker-MCP

# Install dependencies and build
npm install
npm run build
```

## Step 3: Configure MCP Settings

Add the ExternalAttacker-MCP server to your MCP settings file:

### For VSCode Extension

Edit the file located at:
`c:\Users\cmndcntrl\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`

Add the following configuration:

```json
{
  "mcpServers": {
    "securityAuditor": {
      "command": "node",
      "args": ["C:/path/to/ExternalAttacker-MCP/build/index.js"],
      "env": {
        "GO_PATH": "path/to/go/bin"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

Replace `C:/path/to/ExternalAttacker-MCP` with the actual path where you cloned the repository.

## Step 4: Update the callMcpTool Function

Once the MCP server is set up, update the `callMcpTool` function in `app/api/security-scan/route.ts` to use the actual MCP client:

```typescript
// Real implementation using MCP client
async function callMcpTool(serverName: string, toolName: string, args: any) {
  // Use the MCP tool
  const result = await use_mcp_tool({
    server_name: serverName,
    tool_name: toolName,
    arguments: args
  });
  
  return result;
}
```

## Available Scan Types and Tools

The ExternalAttacker-MCP server provides the following security tools:

1. **Subdomain Discovery** (`scan_subdomains`) - Uses subfinder to discover subdomains
2. **Port Scanning** (`scan_ports`) - Uses naabu to scan for open ports
3. **HTTP Service Analysis** (`analyze_http`) - Uses httpx to analyze HTTP services
4. **CDN Detection** (`check_cdn`) - Uses cdncheck to detect CDN usage
5. **SSL/TLS Analysis** (`analyze_ssl`) - Uses tlsx to analyze SSL/TLS configuration
6. **Endpoint Fuzzing** (`fuzz_endpoints`) - Uses ffuf to fuzz web endpoints
7. **Directory Enumeration** (`directory_scan`) - Uses gobuster to enumerate directories
8. **DNS Analysis** (`dns_analysis`) - Uses dnsx for DNS analysis

## Example Usage

Once set up, you can use the security scanner with commands like:

- "Scan example.com for subdomains"
- "Check open ports on 192.168.1.1"
- "Analyze HTTP services on test.com"
- "Check if domain.com uses a CDN"
- "Analyze SSL configuration of site.com"
- "Fuzz endpoints on target.com"

## Security and Rate Limiting

Please use this tool responsibly:

1. Only scan targets you own or have explicit permission to scan
2. Be aware of rate limits to avoid IP blocks
3. Some scans may be intensive and could trigger security alerts

## Troubleshooting

If you encounter issues:

1. Check that all required Go tools are properly installed and in your PATH
2. Verify the MCP server is running and properly configured
3. Look for errors in the server logs
4. Ensure the target is accessible from your network
