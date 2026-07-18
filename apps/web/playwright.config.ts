import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.NOPE_E2E_PORT ?? 3100);
const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? `http://127.0.0.1:${PORT}`;

const widths = [
  ["chromium-1440", 1440, 1000],
  ["chromium-1280", 1280, 900],
  ["chromium-1024", 1024, 900],
  ["chromium-768", 768, 900],
  ["chromium-390", 390, 844],
  ["chromium-360", 360, 800],
] as const;

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 45_000,
  expect: { timeout: 10_000, toHaveScreenshot: { maxDiffPixelRatio: 0.02 } },
  fullyParallel: true,
  workers: Number(process.env.NOPE_E2E_WORKERS ?? 1),
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [["dot"], ["html", { outputFolder: "playwright-report", open: "never" }]] : [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    actionTimeout: 10_000,
    navigationTimeout: 20_000,
  },
  webServer: process.env.PLAYWRIGHT_BASE_URL
    ? undefined
    : {
        command: `pnpm exec next dev -p ${PORT} -H 127.0.0.1`,
        url: baseURL,
        reuseExistingServer: false,
        timeout: 120_000,
        env: {
          NOPE_E2E_FIXTURE: "1",
          NEXT_PUBLIC_API_URL: "http://127.0.0.1:8000",
          API_URL_INTERNAL: "http://127.0.0.1:8000",
        },
      },
  projects: widths.map(([name, width, height]) => ({
    name,
    use: {
      ...devices["Desktop Chrome"],
      viewport: { width, height },
      isMobile: width < 768,
    },
  })),
});
