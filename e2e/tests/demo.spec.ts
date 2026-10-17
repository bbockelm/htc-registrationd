import fs from 'node:fs';
import { atIdP, atRegistrar, expect, poll, signIn, signOut, test, type Demo } from '../fixtures';

// The tests share one demo and run in order: ce2 is approved first, and ce1
// is revoked last.
test.describe.configure({ mode: 'serial' });

// ce2Block is ce2's section of `htc-registrationd-demo status`.
function ce2Block(status: string): string {
  return status.split('\n== ').find((s) => s.startsWith('ce2 ')) ?? '';
}

function collectorLine(demo: Demo, ce: string, name: string, verdict: string): boolean {
  return demo.log().includes(`collector: ${ce}'s token, ad Name = ${name}: ${verdict}`);
}

test('mallory is refused, alice approves ce2, and ce2 installs its token', async ({ page, demo }) => {
  const ce2 = demo.ce('ce2');
  expect(ce2.approval_url, 'ce2 published an approval URL').toBeTruthy();
  expect(ce2.code).toMatch(/^[A-Z]{4}-[A-Z]{4}$/);
  const approval = ce2.approval_url!;

  // The registrar's UI sends a browser with no session to sign in.
  await page.goto(demo.web);
  await atIdP(page, demo);

  await page.goto(approval);
  await signIn(page, demo, 'mallory');
  await atRegistrar(page, demo, '/approve');
  await expect(page).toHaveURL(approval);
  await expect(page.getByText('You are not authorized to approve ce2.localhost.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve' })).toHaveCount(0);
  await expect(page.locator('footer')).toContainText('mallory');
  await signOut(page);

  await page.goto(approval);
  await signIn(page, demo, 'alice');
  await expect(page.getByRole('heading', { name: 'Approve CE registration' })).toBeVisible();
  await expect(page.locator('.code')).toHaveText(ce2.code!);
  const facts = page.locator('dl.facts');
  await expect(facts.locator('dt:text-is("CE name") + dd')).toHaveText('ce2.localhost');
  await expect(facts.locator('dt:text-is("Requested from") + dd')).toContainText('127.0.0.1');
  await expect(page.getByText('You are authorized to approve ce2.localhost.')).toBeVisible();

  await page.getByRole('button', { name: 'Approve' }).click();
  await expect(page.getByRole('heading', { name: 'Request approved' })).toBeVisible();
  await expect(page.getByText(/The request from ce2\.localhost was approved by you at/)).toBeVisible();

  // ce2 polls the registrar every 2s.
  let status = '';
  await poll('ce2 to report State: registered', 30_000, async () => {
    status = await demo.run('status');
    return /State:\s+registered/.test(ce2Block(status));
  }, 1_000);
  expect(fs.readFileSync(ce2.token_file, 'utf8').trim()).not.toBe('');
  expect(status).toMatch(/ce2\.localhost\s+approval\s+active\s+\S*alice\s/);

  if (process.env.CONDOR_BIN && demo.started) {
    expect(demo.ready.collector, `the collector did not start: ${demo.ready.collector_note}`).toBe(true);
  }
  // The collector's verdicts are in the demo's output.
  if (demo.ready.collector && demo.started) {
    await poll('the collector to accept ce2\'s ad', 30_000, () =>
      collectorLine(demo, 'ce2.localhost', 'ce2.localhost', 'accepted'));
    expect(collectorLine(demo, 'ce1.localhost', 'ce1.localhost', 'accepted')).toBe(true);
    expect(collectorLine(demo, 'ce1.localhost', 'ce2.localhost', 'rejected')).toBe(true);
  } else if (!demo.ready.collector) {
    test.info().annotations.push({ type: 'collector', description: `not started: ${demo.ready.collector_note}` });
  }
});

test('Cancel at the identity provider returns to the registrar', async ({ page, demo }) => {
  await page.goto(`${demo.web}/approve`);
  await atIdP(page, demo);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await atRegistrar(page, demo, '/oidc/callback');
  await expect(page.getByRole('heading', { name: 'Sign-in cancelled' })).toBeVisible();
  await expect(page.getByText('The identity provider did not sign you in: access was denied.')).toBeVisible();

  await page.getByRole('link', { name: 'Sign in', exact: true }).click();
  await signIn(page, demo, 'bob');
  await atRegistrar(page, demo, '/approve');
  await expect(page.getByRole('heading', { name: 'Approve a CE' })).toBeVisible();
});

test('a typed subject signs in', async ({ page, demo }) => {
  await page.goto(`${demo.web}/approve`);
  await atIdP(page, demo);
  const other = page.getByRole('textbox', { name: 'Subject' });

  // An empty or malformed subject is refused in the page.
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await atIdP(page, demo);
  await other.fill('no spaces allowed');
  await other.press('Enter');
  await atIdP(page, demo);
  await expect(page.getByText(/A subject is 1 to 64/)).toHaveCount(0);

  await other.fill('carol@example.org');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await atRegistrar(page, demo, '/approve');
  await expect(page.getByRole('heading', { name: 'Approve a CE' })).toBeVisible();
  await expect(page.locator('footer')).toContainText('carol@example.org');
});

test('the code form finds a request', async ({ page, demo }) => {
  const ce2 = demo.ce('ce2');
  await page.goto(demo.web);
  await signIn(page, demo, 'alice');
  await atRegistrar(page, demo, '/approve');
  const code = page.getByRole('textbox', { name: 'Code' });

  await code.fill('BCDF');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('A code has eight letters, like BCDF-GHJK.')).toBeVisible();

  // Case and separators do not matter.
  await code.fill(ce2.code!.toLowerCase().replace('-', ' '));
  await page.getByRole('button', { name: 'Continue' }).click();
  await atRegistrar(page, demo, '/approve');
  await expect(page.getByRole('heading', { name: 'Request approved' })).toBeVisible();
  await expect(page.getByText('The registrar has issued the CE its token.')).toBeVisible();
});

test('a session that ends is resumed through the code form', async ({ page, context, demo }) => {
  const ce2 = demo.ce('ce2');
  await page.goto(`${demo.web}/approve`);
  await signIn(page, demo, 'alice');
  await expect(page.getByRole('heading', { name: 'Approve a CE' })).toBeVisible();

  // Signing out in another tab ends the session the first tab's form
  // was rendered in.
  const other = await context.newPage();
  await other.goto(`${demo.web}/approve`);
  await signOut(other);
  await other.close();

  await page.getByRole('textbox', { name: 'Code' }).fill(ce2.code!);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Signed out' })).toBeVisible();
  await expect(page.getByText('Your session has ended.')).toBeVisible();

  await page.getByRole('link', { name: 'Sign in to continue' }).click();
  await signIn(page, demo, 'alice');
  await expect(page).toHaveURL(`${demo.web}/approve?code=${ce2.code}`);
  await expect(page.getByRole('heading', { name: 'Request approved' })).toBeVisible();
});

test('a sign-in started at another name for the registrar finishes', async ({ page, demo }) => {
  const ce2 = demo.ce('ce2');
  const web = new URL(demo.web);
  test.skip(web.hostname !== 'localhost', 'the web UI is not at localhost');
  // The banner and the CE print localhost; the registrar listens on
  // 127.0.0.1.
  const elsewhere = new URL(ce2.approval_url!);
  elsewhere.hostname = '127.0.0.1';
  await page.goto(elsewhere.href);
  await signIn(page, demo, 'alice');
  await expect(page).toHaveURL(ce2.approval_url!);
  await expect(page.getByRole('heading', { name: 'Request approved' })).toBeVisible();
});

test('admin sees every registration and revokes ce1', async ({ page, demo }) => {
  // alice sees only the registration she may manage.
  await page.goto(`${demo.web}/registrations`);
  await signIn(page, demo, 'alice');
  await atRegistrar(page, demo, '/registrations');
  const rows = page.locator('table tbody tr');
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('ce2.localhost');
  await signOut(page);

  await page.goto(`${demo.web}/registrations`);
  await signIn(page, demo, 'admin');
  await atRegistrar(page, demo, '/registrations');
  await expect(page.getByText('All registrations on this registrar.')).toBeVisible();
  await expect(rows).toHaveCount(2);
  const ce1Row = rows.filter({ hasText: 'ce1.localhost' });
  const ce2Row = rows.filter({ hasText: 'ce2.localhost' });
  await expect(ce1Row).toContainText('active');
  await expect(ce2Row).toContainText('alice');

  await ce1Row.getByRole('button', { name: 'Revoke' }).click();
  await atRegistrar(page, demo, '/registrations');
  await expect(page.getByText(/Revoked the registration of ce1\.localhost\./)).toBeVisible();
  await expect(ce1Row).toContainText('revoked');
  await expect(ce1Row.getByRole('button', { name: 'Revoke' })).toHaveCount(0);
  await expect(ce2Row).toContainText('active');

  const list = await demo.run('cli', 'registrar', 'list');
  expect(list).toMatch(/ce1\.localhost\s+callback\s+revoked/);
});
