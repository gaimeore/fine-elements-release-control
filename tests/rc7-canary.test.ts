/**
 * RC7 synthetic canary: the archive is well-formed for the strict reader, the
 * invented tree carries no Fine Elements code, the marker never derives
 * visibly from the run id, and the workflow stays secretless and dispatch-only.
 */
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, test } from 'node:test';

import { parse } from 'yaml';

import { extractSource } from '../runner/build/build-wrapper.ts';
import { RC7_CANDIDATE_IMAGE, RC7_CONFIG, markerFor, syntheticSource, tarOf } from '../runner/build/rc7-canary.ts';
import { assertSandboxInvariants, buildPhaseArgs, dependencyPhaseArgs } from '../runner/build/sandbox.ts';
import { readTar } from '../runner/lib/tar.ts';

describe('RC7 synthetic canary', () => {
  test('the synthetic archive round-trips through the strict tar reader and extracts as plain data', () => {
    const files = syntheticSource();
    const entries = readTar(tarOf(files));
    const read = Object.fromEntries(entries.filter((e) => e.type === 'file').map((e) => [e.path, e.data.toString('utf8')]));
    assert.deepEqual(read, files);
    assert.deepEqual(entries.filter((e) => e.type === 'dir').map((e) => e.path), ['server', 'server/deploy']);
    const dir = mkdtempSync(path.join(tmpdir(), 'rc7-'));
    try { assert.doesNotThrow(() => extractSource(tarOf(files), path.join(dir, 'src'))); } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('the invented tree is exactly four files, scripts that would fail if lifecycle code ran, registry-only lock, Node 22', () => {
    const files = syntheticSource();
    assert.deepEqual(Object.keys(files).sort(), ['.nvmrc', 'package-lock.json', 'package.json', 'server/deploy/build-from-inputs.ts']);
    const pkg = JSON.parse(files['package.json']!) as { scripts: Record<string, string>; dependencies: Record<string, string> };
    assert.match(pkg.scripts.preinstall!, /exit 97$/);
    assert.match(pkg.scripts.postinstall!, /exit 98$/);
    assert.deepEqual(pkg.dependencies, { tsx: '4.23.15' });
    const lock = JSON.parse(files['package-lock.json']!) as { packages: Record<string, { resolved?: string }> };
    for (const [name, entry] of Object.entries(lock.packages)) if (name !== '') assert.match(entry.resolved ?? '', /^https:\/\/registry\.npmjs\.org\//, name);
    assert.equal(Number(files['.nvmrc']!.trim()), RC7_CONFIG.nodeMajor);
    const program = files['server/deploy/build-from-inputs.ts']!;
    assert.doesNotMatch(program, /from ['"](react|@\/|\.\.?\/)/);
    assert.doesNotMatch(Object.values(files).join('\n'), /fine-elements-|DATABASE_URL|PRIVATE KEY/);
  });

  test('the marker is per run and attempt and never contains the run identity', () => {
    const a = markerFor('38470419556', '1');
    assert.equal(a, markerFor('38470419556', '1'));
    assert.notEqual(a, markerFor('38470419556', '2'));
    assert.match(a, /^rc7m[0-9a-f]{40}$/);
    assert.ok(!a.includes('38470419556'));
  });

  test('the candidate is a digest-pinned official node image and both production vectors accept it', () => {
    assert.match(RC7_CANDIDATE_IMAGE, /^docker\.io\/library\/node@sha256:[0-9a-f]{64}$/);
    assert.equal(RC7_CONFIG.nodeMajor, 22);
    assert.doesNotThrow(() => assertSandboxInvariants(dependencyPhaseArgs({ image: RC7_CANDIDATE_IMAGE, depsDir: '/fe/deps', name: 'fe-deps-loop' }), 'dependency'));
    assert.doesNotThrow(() => assertSandboxInvariants(buildPhaseArgs({ image: RC7_CANDIDATE_IMAGE, name: 'fe-build-loop', srcDir: '/fe/src', modulesDir: '/fe/deps/node_modules', snapshotDir: '/fe/snapshot', outDir: '/fe/out', snapshotSha256: 'a'.repeat(64), tsxCli: 'dist/cli.mjs' }), 'build'));
  });

  test('the canary workflow is dispatch-only, secretless, environment-free and never names a privileged environment', () => {
    const text = readFileSync('.github/workflows/rc7-canary.yml', 'utf8');
    const doc = parse(text) as { on: unknown; permissions: unknown; jobs: Record<string, { environment?: unknown; permissions: unknown; steps: { env?: Record<string, string> }[] }> };
    assert.deepEqual(doc.on, { workflow_dispatch: null });
    assert.deepEqual(doc.permissions, {});
    assert.deepEqual(Object.keys(doc.jobs), ['canary']);
    assert.equal(doc.jobs.canary!.environment, undefined);
    assert.deepEqual(doc.jobs.canary!.permissions, { contents: 'read' });
    assert.doesNotMatch(text, /secrets\.|environment:|control-policy|test-source-fetch|test-build|test-deploy|test-verify|test-backup|upload-artifact/);
    const mapped = doc.jobs.canary!.steps.flatMap((s) => Object.keys(s.env ?? {}));
    assert.deepEqual(mapped, ['GH_TOKEN']);
  });
});
