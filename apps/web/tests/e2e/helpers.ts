import { expect, type Page } from "@playwright/test";

export async function login(page: Page) {
  await page.goto("/login");
  const email = page.locator('input[name="email"]');
  const password = page.locator('input[name="password"]');
  await expect(email).toBeVisible();
  await email.fill("stage8@example.test");
  await password.fill("stage8-password");
  await expect(email).toHaveValue("stage8@example.test");
  await expect(password).toHaveValue("stage8-password");
  const response = await page.request.post("/api/auth/login", {
    form: { email: "stage8@example.test", password: "stage8-password" },
    maxRedirects: 0,
  });
  expect(response.status()).toBe(303);
  await setFixtureSession(page);
  await page.goto("/app/projects/local");
  await expect(page).toHaveURL(/\/app\/projects\/local/);
}

export async function setFixtureSession(page: Page) {
  const origin = page.url().startsWith("http") ? new URL(page.url()).origin : "http://localhost:3100";
  const urls = Array.from(new Set([origin, "http://localhost:3100", "http://127.0.0.1:3100"]));
  await page.context().addCookies(
    urls.map((url) => ({
      name: "nope_session",
      value: "stage8-e2e-session",
      url,
      httpOnly: true,
      sameSite: "Lax" as const,
    })),
  );
}

export async function installAxe(page: Page) {
  await page.addScriptTag({ path: require.resolve("axe-core/axe.min.js") });
}

export async function expectNoSeriousAxeViolations(page: Page) {
  await installAxe(page);
  const results = await page.evaluate(async () => {
    const axe = (window as typeof window & { axe: { run: (context?: unknown, options?: unknown) => Promise<{ violations: Array<{ id: string; impact?: string; nodes: unknown[] }> }> } }).axe;
    return axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa"] },
    });
  });
  const serious = results.violations.filter((violation) => ["serious", "critical"].includes(violation.impact ?? ""));
  expect(serious, JSON.stringify(serious, null, 2)).toEqual([]);
}

export async function freezeForVisuals(page: Page) {
  await page.addStyleTag({
    content: `
      *, *::before, *::after {
        animation-delay: 0s !important;
        animation-duration: 0s !important;
        caret-color: transparent !important;
        scroll-behavior: auto !important;
        transition-delay: 0s !important;
        transition-duration: 0s !important;
      }
    `,
  });
}

export async function visibleAppReady(page: Page) {
  await expect(page.locator("main")).toBeVisible();
  await expect(page.getByRole("link", { name: "NOPE home" })).toBeVisible();
  await page
    .waitForFunction(
      () => document.getAnimations().every((animation) => animation.playState !== "running"),
      undefined,
      { timeout: 5_000 },
    )
    .catch(() => undefined);
}
