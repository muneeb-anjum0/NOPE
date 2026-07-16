"use client";

import { useEffect } from "react";

export function SettingsCollapseReset() {
  useEffect(() => {
    document.querySelectorAll<HTMLDetailsElement>('details[name="settings-sections"], details[name="editable-settings"]').forEach((details) => {
      details.open = false;
    });
  }, []);

  return null;
}
