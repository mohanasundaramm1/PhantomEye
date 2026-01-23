import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CYBER SENTINEL | Command Center",
  description: "Elite Predictive Threat Intelligence Module",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark bg-[#050505]">
      <body className="antialiased selection:bg-tactical-red selection:text-white">
        {children}
      </body>
    </html>
  );
}
