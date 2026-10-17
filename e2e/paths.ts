import path from 'node:path';

export const repoRoot = path.resolve(__dirname, '..');
export const demoBin = path.join(repoRoot, 'bin', 'htc-registrationd-demo');
export const daemonBin = path.join(repoRoot, 'bin', 'htc-registrationd');
