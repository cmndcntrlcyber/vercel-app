# Security Scanner Widget

A deployable security vulnerability scanner widget that can be embedded into any web application. This widget allows users to scan target websites for common security vulnerabilities and provides detailed reports.

## Features

- Quick and full security scans
- Detailed vulnerability reports with severity levels
- Embeddable via JavaScript or iframe
- Customizable appearance with theme options
- Easy integration with existing applications

## Deployment to Vercel

This application is designed to be deployed on Vercel. Follow these steps to deploy:

1. Make sure you have the Vercel CLI installed:
   ```
   npm install -g vercel
   ```

2. Login to Vercel:
   ```
   vercel login
   ```

3. Deploy the application:
   ```
   cd vercel-app
   vercel
   ```

4. To deploy to production:
   ```
   vercel --prod
   ```

## Integration

There are two ways to integrate the security scanner widget into your application:

### 1. JavaScript Embed

```html
<!-- Security Scanner Widget -->
<div id="security-scanner-container"></div>

<script src="https://security-scanner-widget.vercel.app/embed.js"></script>
<script>
  SecurityScanner.init({
    container: '#security-scanner-container',
    apiKey: 'YOUR_API_KEY',
    target: 'https://example.com',
    defaultScanType: 'quick',
    theme: 'light',
    width: '100%',
    height: '600px',
    onScanComplete: function(result) {
      console.log('Scan completed:', result);
      // Handle scan results as needed
    }
  });
</script>
```

### 2. Iframe Embed

```html
<iframe 
  src="https://security-scanner-widget.vercel.app/widget?apiKey=YOUR_API_KEY&target=https://example.com&scanType=quick&theme=light" 
  width="100%" 
  height="600px" 
  frameborder="0" 
  class="security-scanner-iframe">
</iframe>
```

## Integration with Apps & Integrations.html

To integrate this widget with your Apps & Integrations page, add the following code to your HTML:

1. Add a new section for the security scanner:

```html
<div class="integration-card">
  <div class="integration-card-header">
    <h3>Security Vulnerability Scanner</h3>
    <span class="badge">Security</span>
  </div>
  <div class="integration-card-content">
    <p>Scan your websites for security vulnerabilities and get detailed reports.</p>
    <div id="security-scanner-container"></div>
  </div>
  <div class="integration-card-footer">
    <button class="integration-button" onclick="toggleSecurityScanner()">Toggle Scanner</button>
  </div>
</div>
```

2. Add the necessary JavaScript to initialize the widget:

```html
<script src="https://security-scanner-widget.vercel.app/embed.js"></script>
<script>
  let securityScannerVisible = false;
  let securityScanner = null;
  
  function toggleSecurityScanner() {
    const container = document.getElementById('security-scanner-container');
    
    if (securityScannerVisible) {
      container.innerHTML = '';
      securityScannerVisible = false;
    } else {
      securityScanner = SecurityScanner.init({
        container: '#security-scanner-container',
        apiKey: 'YOUR_API_KEY',
        target: window.location.origin,
        defaultScanType: 'quick',
        theme: 'light',
        width: '100%',
        height: '500px'
      });
      securityScannerVisible = true;
    }
  }
</script>
```

## Configuration Options

The widget supports the following configuration options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| container | string/element | '#security-scanner-container' | Container element or selector |
| apiKey | string | '' | API key for authentication |
| target | string | 'https://example.com' | Target URL to scan |
| defaultScanType | string | 'quick' | Type of scan ('quick' or 'full') |
| theme | string | 'light' | Widget theme ('light', 'dark', or 'auto') |
| width | string | '100%' | Widget width |
| height | string | '600px' | Widget height |
| onScanComplete | function | null | Callback function for scan completion |

## Development

To run the application locally:

1. Install dependencies:
   ```
   npm install
   ```

2. Start the development server:
   ```
   npm run dev
   ```

3. Open [http://localhost:3000](http://localhost:3000) in your browser to see the result.
