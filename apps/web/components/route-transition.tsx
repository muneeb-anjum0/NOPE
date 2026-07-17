"use client";

import { usePathname } from "next/navigation";

function routeName(pathname: string) {
  if (pathname === "/app/projects/local") return "overview";
  if (pathname === "/app/projects/local/findings") return "findings";
  if (pathname === "/app/projects/local/attack-map") return "attack-map";
  if (pathname === "/app/projects/local/coverage") return "coverage";
  if (pathname === "/app/projects/local/scans") return "scans";
  if (pathname.startsWith("/app/projects/local/scans/")) return "scan-folder";
  if (pathname === "/app/projects/local/assets") return "assets";
  if (pathname === "/app/projects/local/reports") return "reports";
  if (pathname === "/app/projects/local/settings") return "settings";
  return "dashboard";
}

export function RouteTransition({ children }: Readonly<{ children: React.ReactNode }>) {
  const pathname = usePathname();
  const route = routeName(pathname);

  return (
    <div className="route-transition" data-route={route} key={pathname}>
      {children}
    </div>
  );
}
