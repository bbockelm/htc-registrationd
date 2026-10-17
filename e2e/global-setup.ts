import { execFileSync } from 'node:child_process';
import { repoRoot } from './paths';

// Builds the daemon and the demo runner, so `npx playwright test` tests the
// tree it runs in. E2E_SKIP_BUILD=1 uses the binaries already in bin/.
export default function globalSetup(): void {
  if (process.env.E2E_SKIP_BUILD) {
    return;
  }
  execFileSync('make', ['demo-build'], { cwd: repoRoot, stdio: 'inherit', timeout: 300_000 });
}
