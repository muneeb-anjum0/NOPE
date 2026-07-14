import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NOPE",
  description: "Evidence-first application security orchestration.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
