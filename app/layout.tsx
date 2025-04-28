import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Security Scanner Widget',
  description: 'A security scanner widget that can be integrated into other applications',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
