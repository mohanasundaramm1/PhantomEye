import type { Metadata } from "next";
import "./globals.css";
import NavBar from "@/components/NavBar";

export const metadata: Metadata = {
  title: "PhantomEye | Threat Intelligence Console",
  description: "Certificate-Transparency brand-impersonation detection and campaign triage",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark bg-[#050505]" suppressHydrationWarning>
      <body className="antialiased selection:bg-tactical-red selection:text-white" suppressHydrationWarning>
        <NavBar />
        <main className="min-h-screen">{children}</main>
      </body>
    </html>
  );
}
