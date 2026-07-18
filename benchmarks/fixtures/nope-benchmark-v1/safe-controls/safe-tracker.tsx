export function SafeTracker({ consent }: { consent: boolean }) {
  if (!consent) return null;
  const script = document.createElement("script");
  script.src = "https://www.googletagmanager.com/gtag/js?id=G-SAFE";
  document.head.appendChild(script);
  return null;
}
