import "./globals.css";
import React from "react";
import { SecurityBot } from "../components/SecurityBot";
import { CookieBanner } from "../components/CookieBanner";

export const metadata = {
  title: "VibeSec - AI-Powered Security Scanner for AI Code",
  description: "NIELIT Gorakhpur Major Project 2026 by Kartikey Vishwakarma",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" data-theme="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-[var(--bg-main)] text-[var(--text-primary)] min-h-screen">
        {children}
        <SecurityBot />
        <CookieBanner />
      </body>
    </html>
  );
}
