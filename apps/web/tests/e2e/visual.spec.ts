import { expect, test } from "@playwright/test";
import { freezeForVisuals, login } from "./helpers";

const denseRoutes = [
  ["/app/projects/local", "overview"],
  ["/app/projects/local/findings?scan=scan_stage8_completed&finding=fnd_stage8_idor&detail=open", "findings"],
  ["/app/projects/local/attack-map?scan=scan_stage8_completed", "attack-map"],
  ["/app/projects/local/coverage?scan=scan_stage8_completed", "coverage"],
  ["/app/projects/local/assets?scan=scan_stage8_completed", "assets"],
  ["/app/projects/local/reports", "reports"],
  ["/app/projects/local/settings", "settings"],
] as const;

test.describe("Stage 8 deterministic visuals", () => {
  test("app shell is stable at the configured viewport", async ({ page }, testInfo) => {
    await login(page);
    await page.goto("/app/projects/local");
    await freezeForVisuals(page);
    await expect(page).toHaveScreenshot(`dashboard-shell-${testInfo.project.name}.png`, {
      fullPage: true,
      mask: [page.locator(".scan-history-time"), page.locator("time")],
    });
  });

  for (const [route, name] of denseRoutes) {
    test(`desktop visual for ${name}`, async ({ page }, testInfo) => {
      if (testInfo.project.name !== "chromium-1280") {
        return;
      }
      await login(page);
      await page.goto(route);
      await freezeForVisuals(page);
      await expect(page).toHaveScreenshot(`${name}-1280.png`, {
        fullPage: true,
        mask: [page.locator(".scan-history-time"), page.locator("time")],
      });
    });
  }
});
