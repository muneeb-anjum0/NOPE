import { expect, test } from "@playwright/test";
import { expectNoSeriousAxeViolations, login, visibleAppReady } from "./helpers";

const majorRoutes = [
  ["/", "NOPE"],
  ["/login", "Open your own fresh dashboard"],
  ["/app/projects/local", "Evidence"],
  ["/app/projects/local/scans", "Project folders"],
  ["/app/projects/local/scans/project_stage8", "Upload ZIP"],
  ["/app/projects/local/findings?scan=scan_stage8_completed&finding=fnd_stage8_idor&detail=open", "Finding detail"],
  ["/app/projects/local/rules?scan=scan_stage8_completed", "Promote evidence"],
  ["/app/projects/local/attack-map?scan=scan_stage8_completed", "Attack Map"],
  ["/app/projects/local/coverage?scan=scan_stage8_completed", "Coverage"],
  ["/app/projects/local/assets?scan=scan_stage8_completed", "Asset manifest"],
  ["/app/projects/local/reports", "Export board"],
  ["/app/projects/local/settings", "Settings"],
] as const;

test.describe("Stage 8 accessibility", () => {
  for (const [route, expectedText] of majorRoutes) {
    test(`axe has no serious violations on ${route}`, async ({ page }) => {
      if (route.startsWith("/app")) await login(page);
      await page.goto(route);
      await expect(page.getByText(expectedText).first()).toBeVisible();
      await expectNoSeriousAxeViolations(page);
    });
  }

  test("keyboard focus, modal trap, Escape, and reduced motion remain usable", async ({ page }) => {
    await login(page);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/app/projects/local/scans");
    await visibleAppReady(page);

    await page.keyboard.press("Tab");
    await expect(page.locator(":focus")).toBeVisible();

    await page.getByRole("button", { name: /New folder/i }).click();
    const dialog = page.getByRole("dialog", { name: "Create project folder" });
    await expect(dialog).toBeVisible();
    await expect(page.getByLabel("Folder name")).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(dialog.locator(":focus")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();

    await page.getByRole("button", { name: /Collapse sidebar/i }).click();
    await expect(page.getByRole("button", { name: /Expand sidebar/i })).toBeVisible();
    await page.keyboard.press("Tab");
    await expect(page.locator(":focus")).toBeVisible();
  });
});
