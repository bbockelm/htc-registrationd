import { defineConfig, devices } from '@playwright/test';

// Each browser project starts its own demo (see fixtures.ts), so the
// projects never share state. E2E_BROWSERS picks them: a space- or
// comma-separated list of chromium, webkit and firefox.
const known = {
  chromium: devices['Desktop Chrome'],
  webkit: devices['Desktop Safari'],
  firefox: devices['Desktop Firefox'],
} as const;
type Browser = keyof typeof known;

const browsers = (process.env.E2E_BROWSERS ?? 'chromium')
  .split(/[\s,]+/)
  .filter(Boolean)
  .map((name) => {
    if (!(name in known)) {
      throw new Error(`E2E_BROWSERS: unknown browser ${name} (want chromium, webkit or firefox)`);
    }
    return name as Browser;
  });

export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.ts',
  // The tests of a file run in order against one demo.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  // The slowest test waits up to 30s for ce2 to collect its token.
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: browsers.map((name) => ({ name, use: { ...known[name] } })),
});
