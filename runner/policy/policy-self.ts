/** control-ci: the same policy over this repository's whole tree (not a security boundary; fe-policy is). */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

import { evaluateFiles, parseActionAllowlist } from './policy-engine.ts';

const SKIP = new Set(['.git', 'node_modules', 'handoff']);

function walk(dir: string, out: Map<string, string>): void {
  for (const name of readdirSync(dir).sort()) {
    if (SKIP.has(name)) continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.set(path.relative('.', full).split(path.sep).join('/'), readFileSync(full, 'utf8'));
  }
}

const files = new Map<string, string>();
walk('.', files);
const findings = evaluateFiles(files, parseActionAllowlist(JSON.parse(readFileSync('config/actions.json', 'utf8')) as unknown));
for (const finding of findings) console.error(`POLICY ${finding.rule} ${finding.path}: ${finding.detail}`);
console.log(`FE_POLICY_SELF=${findings.length === 0 ? 'PASS' : 'FAIL'} files=${files.size} findings=${findings.length}`);
process.exit(findings.length === 0 ? 0 : 1);
