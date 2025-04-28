/**
 * Security Scanner Widget Embed Script
 * v1.0.0
 */
(function() {
  // Define the SecurityScanner object in the global scope
  window.SecurityScanner = {
    // Initialize the widget with the provided options
    init: function(options) {
      // Default options
      const defaults = {
        container: '#security-scanner-container',
        apiKey: '',
        target: 'https://example.com',
        defaultScanType: 'quick',
        theme: 'light',
        width: '100%',
        height: '600px',
        onScanComplete: function() {}
      };

      // Merge provided options with defaults
      const config = Object.assign({}, defaults, options);

      // Find the container element
      const container = typeof config.container === 'string' 
        ? document.querySelector(config.container) 
        : config.container;

      if (!container) {
        console.error('Security Scanner: Container element not found');
        return;
      }

      // Build the widget URL with query parameters
      const baseUrl = 'https://security-scanner-widget.vercel.app/widget';
      const queryParams = [
        `apiKey=${encodeURIComponent(config.apiKey)}`,
        `target=${encodeURIComponent(config.target)}`,
        `scanType=${encodeURIComponent(config.defaultScanType)}`,
        `theme=${encodeURIComponent(config.theme)}`
      ].join('&');

      const widgetUrl = `${baseUrl}?${queryParams}`;

      // Create the iframe element
      const iframe = document.createElement('iframe');
      iframe.src = widgetUrl;
      iframe.width = config.width;
      iframe.height = config.height;
      iframe.style.border = 'none';
      iframe.className = 'security-scanner-iframe';
      iframe.allow = 'clipboard-write';
      iframe.setAttribute('scrolling', 'no');
      iframe.setAttribute('frameborder', '0');

      // Clear the container and append the iframe
      container.innerHTML = '';
      container.appendChild(iframe);

      // Set up message listener for communication with the iframe
      window.addEventListener('message', function(event) {
        // Verify the message origin for security
        if (event.origin !== 'https://security-scanner-widget.vercel.app') {
          return;
        }

        const data = event.data;
        
        // Handle scan complete event
        if (data.type === 'scanComplete' && typeof config.onScanComplete === 'function') {
          config.onScanComplete(data.result);
        }
      });

      // Return the iframe element
      return iframe;
    },

    // Version of the embed script
    version: '1.0.0'
  };
})();
