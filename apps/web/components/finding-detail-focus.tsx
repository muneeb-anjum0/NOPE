"use client";

import { useEffect } from "react";
import { useSearchParams } from "next/navigation";

export function FindingDetailFocus() {
  const searchParams = useSearchParams();
  const findingId = searchParams.get("finding");

  useEffect(() => {
    if (!findingId) return;
    const panel = document.querySelector<HTMLDetailsElement>(".finding-detail-panel");
    if (!panel) return;

    panel.open = true;
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
    panel.classList.remove("finding-detail-pulse");
    window.setTimeout(() => {
      panel.classList.add("finding-detail-pulse");
    }, 30);

    const timer = window.setTimeout(() => {
      panel.classList.remove("finding-detail-pulse");
    }, 1100);
    return () => window.clearTimeout(timer);
  }, [findingId]);

  return null;
}
