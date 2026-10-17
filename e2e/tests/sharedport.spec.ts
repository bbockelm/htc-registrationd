import fs from 'node:fs';
import { expect, test } from '@playwright/test';

// The registrar's web UI on HTCondor's shared port, under a real
// condor_master: test/root/run.sh starts it (collector.test, port 9619 on
// 127.0.0.1) and sets these. Without them the tests are skipped.
const web = process.env.E2E_SHAREDPORT_URL ?? '';
const approvalFile = process.env.E2E_SHAREDPORT_APPROVAL ?? '';
const host = web ? new URL(web).hostname : '';

test.describe.configure({ mode: 'serial' });

// The host names the container; the test CA is not the browser's.
test.use({
  ignoreHTTPSErrors: true,
  launchOptions: { args: host ? [`--host-resolver-rules=MAP ${host} 127.0.0.1`] : [] },
});

test.describe('web UI on the shared port', () => {
  test.skip(!web, 'E2E_SHAREDPORT_URL is not set; test/root/run.sh sets it');
  test.beforeEach(({ browserName }) => {
    test.skip(browserName !== 'chromium', 'resolving the container name needs a Chromium flag');
  });

  async function signIn(page: import('@playwright/test').Page, who: string) {
    await expect(page.getByRole('heading', { name: 'Demo identity provider' })).toBeVisible();
    expect(new URL(page.url()).port).toBe('8443');
    await page.getByRole('button', { name: new RegExp(`^${who}\\b`) }).click();
  }

  test('alice signs in and sees ce1.test, registered by callback', async ({ page }) => {
    await page.goto(`${web}/registrations`);
    await signIn(page, 'alice');
    await expect(page).toHaveURL(`${web}/registrations`);
    const row = page.locator('table tbody tr').filter({ hasText: 'ce1.test' });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText('callback');
  });

  test("alice opens ce1.test's approval URL and approves it", async ({ page }) => {
    const text = fs.readFileSync(approvalFile, 'utf8');
    const url = text.match(/https:\/\/\S+\?code=([A-Z]{4}-[A-Z]{4})/);
    expect(url, `no approval URL in ${text}`).toBeTruthy();
    expect(url![0].startsWith(`${web}/approve?code=`)).toBe(true);

    await page.goto(url![0]);
    await signIn(page, 'alice');
    await expect(page.getByRole('heading', { name: 'Approve CE registration' })).toBeVisible();
    await expect(page.locator('.code')).toHaveText(url![1]);
    const facts = page.locator('dl.facts');
    await expect(facts.locator('dt:text-is("CE name") + dd')).toHaveText('ce1.test');
    await expect(page.getByText('You are authorized to approve ce1.test.')).toBeVisible();
    await page.getByRole('button', { name: 'Approve' }).click();
    await expect(page.getByRole('heading', { name: 'Request approved' })).toBeVisible();
  });
});
