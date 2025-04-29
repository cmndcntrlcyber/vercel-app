/** @type {import('next').NextConfig} */
const nextConfig = {
  // Set the source directory explicitly
  distDir: '.next',
  // Enable React strict mode for better error catching
  reactStrictMode: true,
  // Optimize images through Next.js Image component
  images: {
    domains: [],
  },
  // Configure webpack if needed
  webpack: (config, { buildId, dev, isServer, defaultLoaders, webpack }) => {
    // Customize webpack config here if needed
    return config;
  },
};

module.exports = nextConfig;
