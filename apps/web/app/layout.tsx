import type { Metadata } from "next";
import { BrandTextEffects } from "@/components/brand-text-effects";
import "./globals.css";

export const metadata: Metadata = {
  title: "NOPE",
  description: "Evidence-first application security orchestration.",
  icons: {
    icon: [{ url: "/icon.svg", type: "image/svg+xml" }],
    shortcut: [{ url: "/icon.svg", type: "image/svg+xml" }],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <BrandTextEffects />
        {children}
      </body>
    </html>
  );
}
