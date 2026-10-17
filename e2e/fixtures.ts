import { test as base, expect, type Page } from '@playwright/test';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { daemonBin, demoBin, repoRoot } from './paths';

// What the demo writes to its -ready-file once it is up.
export interface ReadyCE {
  key: string;
  name: string;
  method: string;
  config: string;
  token_file: string;
  has_token: boolean;
  approval_url?: string;
  code?: string;
}

export interface Ready {
  dir: string;
  web_url: string;
  issuer_url: string;
  registrar_config: string;
  ces: ReadyCE[];
  collector: boolean;
  collector_note?: string;
}

const startLimitMs = 120_000;
const stopLimitMs = 20_000;

// poll calls cond every intervalMs until it returns true, and throws
// "timed out after <limit>: <what>" once limitMs has passed.
export async function poll(what: string, limitMs: number, cond: () => boolean | Promise<boolean>, intervalMs = 250) {
  const deadline = Date.now() + limitMs;
  for (;;) {
    if (await cond()) {
      return;
    }
    if (Date.now() >= deadline) {
      throw new Error(`timed out after ${limitMs / 1000}s: ${what}`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

export class Demo {
  // logPath is undefined for a demo this suite did not start.
  constructor(
    readonly ready: Ready,
    private readonly logPath?: string,
  ) {}

  get web(): string {
    return this.ready.web_url;
  }

  get issuer(): string {
    return this.ready.issuer_url;
  }

  ce(key: string): ReadyCE {
    const c = this.ready.ces.find((c) => c.key === key);
    if (!c) {
      throw new Error(`the demo has no CE ${key}`);
    }
    return c;
  }

  get started(): boolean {
    return this.logPath !== undefined;
  }

  // log is everything the demo has printed, when this suite started it.
  log(): string {
    return this.logPath ? fs.readFileSync(this.logPath, 'utf8') : '';
  }

  // run runs a demo command (status, cli ..., advertise ...) and returns its
  // output; it rejects when the command fails.
  run(...args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      execFile(
        demoBin,
        ['-dir', this.ready.dir, '-daemon', daemonBin, ...args],
        { timeout: 30_000 },
        (err, stdout, stderr) => {
          const out = stdout + stderr;
          if (err) {
            reject(new Error(`htc-registrationd-demo ${args.join(' ')}: ${err.message}\n${out}`));
          } else {
            resolve(out);
          }
        },
      );
    });
  }
}

function tail(file: string, lines = 40): string {
  try {
    return fs.readFileSync(file, 'utf8').trimEnd().split('\n').slice(-lines).join('\n');
  } catch {
    return '';
  }
}

async function startDemo(dir: string, logPath: string): Promise<{ demo: Demo; proc: ChildProcess }> {
  if (!fs.existsSync(demoBin) || !fs.existsSync(daemonBin)) {
    throw new Error(`${demoBin} or ${daemonBin} is missing; run make demo-build`);
  }
  const readyPath = path.join(dir, 'ready.json');
  // Without CONDOR_BIN the demo runs no HTCondor collector, even if one is
  // on PATH.
  const condorBin = process.env.CONDOR_BIN;
  const args = ['-dir', dir, '-daemon', daemonBin];
  args.push(...(condorBin ? ['-condor-bin', condorBin] : ['-no-collector']), 'run');
  const out = fs.openSync(logPath, 'a');
  // Its own process group, so a demo that ignores SIGTERM can be killed
  // together with the daemons it started.
  const proc = spawn(demoBin, args, { stdio: ['ignore', out, out], detached: true });
  fs.closeSync(out);
  let exited: string | undefined;
  proc.on('exit', (code, signal) => {
    exited = `exited with ${signal ?? code}`;
  });
  try {
    await poll('the demo did not write its ready file', startLimitMs, () => {
      if (exited) {
        throw new Error(`the demo ${exited} before it was ready`);
      }
      return fs.existsSync(readyPath);
    });
  } catch (err) {
    await stopDemo(proc);
    throw new Error(`${(err as Error).message}\n${tail(logPath)}`);
  }
  const ready = JSON.parse(fs.readFileSync(readyPath, 'utf8')) as Ready;
  return { demo: new Demo(ready, logPath), proc };
}

async function stopDemo(proc: ChildProcess): Promise<void> {
  if (proc.exitCode !== null || proc.signalCode !== null) {
    return;
  }
  const done = new Promise<void>((r) => proc.once('exit', () => r()));
  proc.kill('SIGTERM');
  const stopped = await Promise.race([
    done.then(() => true),
    new Promise<boolean>((r) => setTimeout(() => r(false), stopLimitMs)),
  ]);
  if (!stopped && proc.pid) {
    try {
      process.kill(-proc.pid, 'SIGKILL');
    } catch {
      // Already gone.
    }
    await done;
  }
}

let clients = 0;

export const test = base.extend<{ demoLog: void; clientAddress: void }, { demo: Demo }>({
  // One demo per worker; each browser project runs in its own worker.
  // E2E_DEMO_DIR drives a demo already running there (make demo) instead;
  // it must be fresh, with ce2 awaiting approval.
  demo: [
    async ({}, use, workerInfo) => {
      const running = process.env.E2E_DEMO_DIR;
      if (running) {
        const readyPath = path.join(path.resolve(repoRoot, running), 'ready.json');
        if (!fs.existsSync(readyPath)) {
          throw new Error(`${readyPath} is missing; is the demo running there?`);
        }
        await use(new Demo(JSON.parse(fs.readFileSync(readyPath, 'utf8')) as Ready));
        return;
      }
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), `hrd-e2e-${workerInfo.project.name}-`));
      const logPath = path.join(dir, 'demo.log');
      const { demo, proc } = await startDemo(dir, logPath);
      try {
        await use(demo);
      } finally {
        await stopDemo(proc);
        if (process.env.E2E_KEEP) {
          console.log(`demo state kept in ${dir}`);
        } else {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      }
    },
    { scope: 'worker', timeout: startLimitMs + stopLimitMs + 10_000 },
  ],
  // The registrar allows each client address 10 sign-in requests a minute,
  // and the suite signs in more often than that. It reads a client's
  // address from X-Forwarded-For when the connection comes from loopback
  // (a trusted proxy by default), so each test claims its own.
  clientAddress: [
    async ({ context }, use) => {
      clients++;
      await context.setExtraHTTPHeaders({ 'X-Forwarded-For': `192.0.2.${clients % 250}` });
      await use();
    },
    { auto: true },
  ],
  // A failed test carries the demo's output.
  demoLog: [
    async ({ demo }, use, testInfo) => {
      await use();
      if (testInfo.status !== testInfo.expectedStatus && demo.started) {
        await testInfo.attach('demo.log', { body: demo.log(), contentType: 'text/plain' });
      }
    },
    { auto: true },
  ],
});

export { expect };

// atIdP asserts the page is the identity provider's login page.
export async function atIdP(page: Page, demo: Demo) {
  await expect(page).toHaveURL((u) => u.href.startsWith(`${demo.issuer}/authorize?`));
  await expect(page.getByRole('heading', { name: 'Demo identity provider' })).toBeVisible();
}

// atRegistrar asserts the page is on the registrar, at path when given.
export async function atRegistrar(page: Page, demo: Demo, path?: string) {
  const web = new URL(demo.web);
  await expect(page).toHaveURL((u) => u.origin === web.origin && (path === undefined || u.pathname === path));
}

// signIn clicks who's button on the identity provider's login page and
// waits to be back on the registrar.
export async function signIn(page: Page, demo: Demo, who: string) {
  await atIdP(page, demo);
  await page.getByRole('button', { name: new RegExp(`^${who}\\b`) }).click();
  await atRegistrar(page, demo);
}

export async function signOut(page: Page) {
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Signed out' })).toBeVisible();
  await expect(page.getByText('You are signed out.')).toBeVisible();
}
