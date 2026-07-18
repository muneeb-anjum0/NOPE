import { expect, test } from "@playwright/test";
import { login, visibleAppReady } from "./helpers";

test.describe("Stage 8 core browser flows", () => {
  test("landing, login, session persistence, settings logout", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("link", { name: "NOPE home" })).toBeVisible();
    await page.getByRole("link", { name: /^Open dashboard$/i }).first().click();
    await expect(page).toHaveURL(/\/login/);

    await login(page);
    await visibleAppReady(page);
    await page.reload();
    await expect(page).toHaveURL(/\/app\/projects\/local/);
    await expect(page.getByText("Evidence status")).toBeVisible();

    await page.getByRole("button", { name: "Settings" }).press("Enter");
    await expect(page).toHaveURL(/\/settings/);
    await page.getByRole("button", { name: /Sign out/i }).click();
    await expect(page).toHaveURL(/\/$/);
  });

  test("project creation modal, folder navigation, ZIP upload, progress, cancellation, retry, and deletion", async ({ page }) => {
    test.setTimeout(90_000);
    await login(page);
    await page.goto("/app/projects/local/scans");
    await page.getByRole("button", { name: /New folder/i }).click();
    await expect(page.getByRole("dialog", { name: "Create project folder" })).toBeVisible();
    await page.getByLabel("Folder name").fill("Stage 8 Workspace");
    await page.getByLabel("Repo label").fill("stage8/repo");
    await page.getByLabel("Target URL").fill("https://stage8.example.test");
    await page.getByRole("button", { name: "Create folder" }).click();
    await expect(page.getByText("Stage 8 Workspace").first()).toBeVisible();
    await page.waitForLoadState("networkidle");

    await page.getByRole("link", { name: /Stage 8 Workspace/i }).first().click({ noWaitAfter: true });
    await expect(page).toHaveURL(/\/scans\/project_stage8/);
    await expect(page.getByText("Upload ZIP")).toBeVisible();
    await expect(page.locator('[data-scan-launcher-ready="true"]')).toBeVisible();

    const zip = Buffer.from("UEsDBBQAAAAIAAAAAAAAAAAAAAAAAAAAAAAJAAAAUkVBRE1FLm1kAwBQSwECFAAUAAAACAAAAAAAAAAAAAAAAAAAAAAACQAAAAAAAAAAAAAApIEAAAAAUkVBRE1FLm1kUEsFBgAAAAABAAEANwAAACcAAAAAAA==", "base64");
    await page.locator('input[name="repository"]').setInputFiles({ name: "stage8.zip", mimeType: "application/zip", buffer: zip });
    await expect(page.getByText("stage8.zip")).toBeVisible();
    await page.getByLabel(/permission/i).check();
    await page.getByRole("button", { name: "Start evidence scan" }).click({ noWaitAfter: true });
    await expect(page).toHaveURL(/scan=scan_stage8_running/);
    await expect(page.getByText("running").first()).toBeVisible();
    await expect(page.locator(".scan-progress-rail").first()).toBeVisible();

    await page.locator('form:has(input[name="action"][value="cancel"])').getByRole("button", { name: "Cancel" }).click();
    await expect(page).toHaveURL(/action=cancel/);
    await page.locator('form:has(input[name="action"][value="retry"])').first().getByRole("button", { name: "Retry" }).click();
    await expect(page).toHaveURL(/action=retry/);
    await expect(page.getByRole("button", { name: "Delete" }).first()).toBeVisible();
    await page.locator('form[action="/api/delete-scan"]').first().evaluate((form) => {
      (form as HTMLFormElement).requestSubmit();
    });
    await expect(page).toHaveURL(/\/scans\/project_stage8/);
  });

  test("findings filters, DOM load more, details, Qwen actions, tabs, lifecycle states, and error/empty states", async ({ page }) => {
    test.setTimeout(90_000);
    await login(page);
    await page.goto("/app/projects/local/findings?scan=scan_stage8_completed");
    await expect(page.getByText("7 of 8")).toBeVisible();
    await page.getByRole("button", { name: /Load more/i }).click();
    await expect(page.getByText("8 of 8")).toBeVisible();
    await expect(page.getByText("8 shown")).toBeVisible();

    const row = page.getByRole("link", { name: /Invoice lookup may lack owner scope/i });
    await row.click();
    await expect(page).toHaveURL(/finding=fnd_stage8_idor/);
    await expect(page.getByText("Finding detail")).toBeVisible();
    await expect(page.locator(".finding-detail-summary .severity-critical")).toBeVisible();

    await expect(page.getByRole("link", { name: "evidence" })).toBeVisible();
    await page.getByRole("link", { name: "evidence" }).click();
    await expect(page.getByText("Route id flows")).toBeVisible();
    await page.getByRole("link", { name: "code flow" }).click();
    await expect(page.getByText("retrieves data from")).toBeVisible();
    await page.getByRole("link", { name: "overview" }).click();
    await expect(page).toHaveURL(/tab=overview/);
    await page.waitForLoadState("networkidle");
    await expect(page.getByRole("button", { name: "Explain" })).toBeEnabled();

    for (const label of ["Explain", "Challenge", "Fix", "Test", "Patch Review"]) {
      const responsePromise = page.waitForResponse((response) => response.url().includes("/api/ai/finding-action") && response.request().method() === "POST");
      await page.getByRole("button", { name: label }).click();
      await expect((await responsePromise).ok()).toBeTruthy();
      await expect(page.getByText("Gen. by Qwen").first()).toBeVisible({ timeout: 20_000 });
    }

    await page.goto("/app/projects/local/findings?scan=scan_stage8_completed&status=suppressed");
    await expect(page.getByText("suppressed").first()).toBeVisible();
    await page.goto("/app/projects/local/findings?scan=scan_stage8_completed&severity=info");
    await expect(page.getByRole("link", { name: /No HEALTHCHECK defined/ })).toBeVisible();
    await page.goto("/app/projects/local/findings?scan=scan_stage8_completed&query=does-not-exist");
    await expect(page.getByText("No findings yet")).toBeVisible();
  });

  test("attack map, coverage, assets, reports, baselines, drift, and mobile navigation", async ({ page }) => {
    test.setTimeout(90_000);
    await login(page);
    await page.goto("/app/projects/local/attack-map?scan=scan_stage8_completed");
    await expect(page.getByText("GET /app/invoices/:id")).toBeVisible();
    await expect(page.getByText("Missing ownership check")).toBeVisible();

    await page.goto("/app/projects/local/coverage?scan=scan_stage8_completed");
    await expect(page.getByText("Dynamic testing: Partial")).toBeVisible();
    await expect(page.getByText("ZAP baseline")).toBeVisible();

    await page.goto("/app/projects/local/assets?scan=scan_stage8_completed");
    await expect(page.getByText("Asset manifest")).toBeVisible();
    await expect(page.getByText("files and")).toBeVisible();

    await page.goto("/app/projects/local/reports");
    await expect(page.getByRole("link", { name: /PDF review packet/i }).first()).toBeVisible();
    await expect(page.getByRole("link", { name: /SARIF code scanning/i }).first()).toBeVisible();

    await page.goto("/app/projects/local/scans/project_stage8?scan=scan_stage8_completed");
    await expect(page.getByText("Latest drift")).toBeVisible();
    await expect(page.getByText("Stage 8 baseline")).toBeVisible();

    if ((page.viewportSize()?.width ?? 1440) <= 390) {
      await page.getByRole("button", { name: /Collapse sidebar/i }).click();
      await expect(page.getByRole("button", { name: /Expand sidebar/i })).toBeVisible();
    }
  });
});
