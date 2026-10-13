/**
 * Sandbox vectors (static), the build wrapper's host-side steps, the bundle
 * validator and rendition placement/injection — synthetic data only. RC2
 * never runs Docker or private source; RC7 proves the sandbox on a canary.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { linkSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, describe, test } from 'node:test';

import { assertNodeMajor, extractSource, parseBuildInput, prepareDependencyInputs, tsxCliEntry } from '../runner/build/build-wrapper.ts';
import { assertSandboxInvariants, buildPhaseArgs, dependencyPhaseArgs, loadSandboxConfig, parseSandboxConfig, requireImage } from '../runner/build/sandbox.ts';
import { packBundle, unpackBundle, validateBundleTree } from '../runner/deploy/bundle.ts';
import { injectRenditions, placementsFromSnapshot } from '../runner/deploy/placements.ts';
import { parseManifest } from '../runner/lib/manifest.ts';
import { readTar } from '../runner/lib/tar.ts';

const scratch = mkdtempSync(path.join(tmpdir(), 'fe-sandbox-test-'));
after(() => { rmSync(scratch, { recursive: true, force: true }); });
const dir = (name: string): string => { const d = path.join(scratch, name); mkdirSync(d, { recursive: true }); return d; };
const write = (root: string, rel: string, data: string | Buffer): void => {
  mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
  writeFileSync(path.join(root, rel), data);
};
const sha = (data: string | Buffer): string => createHash('sha256').update(data).digest('hex');
const IMAGE = `docker.io/library/node@sha256:${'a'.repeat(64)}`;
const SNAP = 'b'.repeat(64);

function buildArgs(overrides: Partial<Parameters<typeof buildPhaseArgs>[0]> = {}): string[] {
  return buildPhaseArgs({ image: IMAGE, name: 'fe-build', srcDir: '/fe/src', modulesDir: '/fe/deps/node_modules', snapshotDir: '/fe/snapshot', outDir: '/fe/out', snapshotSha256: SNAP, tsxCli: 'dist/cli.mjs', ...overrides });
}

describe('sandbox vectors', () => {
  test('the build phase: no network, non-root, no caps, no-new-privileges, read-only, private namespaces, limits, no core, no log driver', () => {
    const args = buildArgs();
    assert.doesNotThrow(() => assertSandboxInvariants(args, 'build'));
    const joined = args.join(' ');
    for (const needle of ['--network none', '--user 10001:10001', '--cap-drop ALL', '--security-opt no-new-privileges:true', '--read-only', '--ipc private', '--cgroupns private', '--ulimit core=0', '--log-driver none', '--pids-limit', '--memory 8g', '--cpus 3']) {
      assert.ok(joined.includes(needle), needle);
    }
    assert.ok(!args.includes('-t') && !args.includes('-i'), 'no TTY, no stdin');
    assert.ok(!args.some((a) => /^--(pid|uts|userns)(=|$)/.test(a)), 'PID/UTS/user namespaces stay Docker-private: no flag that docker/cli would reject or that could share them');
    assert.match(args.at(-1)!, /^exec <\/dev\/null >\/out\/\.build\.log 2>&1; exec node \/in\/node_modules\/tsx\/dist\/cli\.mjs \/in\/src\/server\/deploy\/build-from-inputs\.ts/);
    assert.equal(args.filter((a) => a.startsWith('type=bind') && !a.endsWith(',readonly')).length, 1, 'only /out is writable');
  });

  test('the dependency phase: network but no source, lifecycle scripts off, no audit/fund', () => {
    const args = dependencyPhaseArgs({ image: IMAGE, depsDir: '/fe/deps', name: 'fe-deps' });
    assert.doesNotThrow(() => assertSandboxInvariants(args, 'dependency'));
    assert.deepEqual(args.slice(-6), ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--registry=https://registry.npmjs.org/']);
    assert.equal(args.filter((a) => a.startsWith('type=bind')).length, 1, 'only the manifest+lockfile directory is mounted');
  });

  test('every weakening is caught by the invariant check', () => {
    const base = buildArgs();
    const variants: [string, string[]][] = [
      ['network', base.map((a) => (a === 'none' ? 'bridge' : a))],
      ['docker socket', [...base.slice(0, 3), '--mount', 'type=bind,src=/var/run/docker.sock,dst=/s', ...base.slice(3)]],
      ['writable source', base.map((a) => (a === 'type=bind,src=/fe/src,dst=/in/src,readonly' ? 'type=bind,src=/fe/src,dst=/in/src' : a))],
      ['runner temp', base.map((a) => (a.startsWith('type=bind,src=/fe/snapshot') ? 'type=bind,src=/home/runner/work/_temp,dst=/in/snapshot,readonly' : a))],
      ['tty', [...base.slice(0, 1), '-t', ...base.slice(1)]],
      ['privileged', [...base.slice(0, 1), '--privileged', ...base.slice(1)]],
      ['env leak', [...base.slice(0, 1), '--env', 'GITHUB_TOKEN=x', ...base.slice(1)]],
      ['no caps drop', base.filter((a, i) => !(a === '--cap-drop' || base[i - 1] === '--cap-drop'))],
      ['root user', base.map((a) => (a === '10001:10001' ? '0:0' : a))],
      ['pid host', [...base.slice(0, 1), '--pid', 'container:x', ...base.slice(1)]],
      ['pid=host', [...base.slice(0, 1), '--pid=host', ...base.slice(1)]],
      ['uts host', [...base.slice(0, 1), '--uts=host', ...base.slice(1)]],
      ['userns host', [...base.slice(0, 1), '--userns', 'host', ...base.slice(1)]],
      ['joined network', [...base.slice(0, 1), '--network=bridge', ...base.slice(1)]],
      ['joined cap-add', [...base.slice(0, 1), '--cap-add=SYS_ADMIN', ...base.slice(1)]],
    ];
    for (const [name, args] of variants) assert.throws(() => assertSandboxInvariants(args, 'build'), Error, name);
    assert.throws(() => assertSandboxInvariants(dependencyPhaseArgs({ image: IMAGE, depsDir: '/fe/deps', name: 'd' }).filter((a) => a !== '--ignore-scripts'), 'dependency'), /lifecycle/);
  });

  test('the committed sandbox config accepts no image yet (RC7 sets one), so the wrapper fails closed', () => {
    const config = loadSandboxConfig();
    assert.equal(config.nodeImage, null);
    assert.throws(() => requireImage(config), /RC7/);
    assert.throws(() => parseSandboxConfig({ schema: 'fe-sandbox/1', nodeImage: 'node:22', nodeMajor: 22 }), /pinned by digest/);
  });
});

describe('build wrapper host-side steps (data only)', () => {
  test('the verified archive is extracted as data; links and traversal fail closed', () => {
    const repo = dir('canary-repo');
    execFileSync('git', ['init', '-q', repo]);
    write(repo, 'package.json', '{"name":"canary"}');
    write(repo, 'src/index.ts', 'export const canary = 1;\n');
    execFileSync('git', ['-C', repo, 'add', '-A']);
    execFileSync('git', ['-C', repo, '-c', 'user.name=c', '-c', 'user.email=c@example.invalid', 'commit', '-q', '-m', 'c']);
    const archive = execFileSync('git', ['-C', repo, '-c', 'core.autocrlf=false', 'archive', '--format=tar', 'HEAD']);
    const out = dir('extracted');
    extractSource(archive, out);
    assert.equal(readFileSync(path.join(out, 'src/index.ts'), 'utf8'), 'export const canary = 1;\n');

    const header = (name: string, type: string): Buffer => {
      const h = Buffer.alloc(512);
      h.write(name, 0, 'utf8');
      h.write('0000644\0', 100); h.write('00000000000\0', 124); h.write(type, 156);
      return Buffer.concat([h, Buffer.alloc(1024)]);
    };
    assert.throws(() => readTar(header('link', '2')), /link or special/);
    assert.throws(() => readTar(header('../escape', '0')), /safe relative path/);
    assert.throws(() => readTar(header('/abs', '0')), /safe relative path/);
  });

  test('Node major, .npmrc refusal, manifest+lockfile only, tsx entry', () => {
    const src = dir('src-checks');
    write(src, '.nvmrc', '22\n');
    write(src, 'package.json', '{}');
    write(src, 'package-lock.json', '{}');
    write(src, 'server/secret.ts', 'never copied');
    assert.doesNotThrow(() => assertNodeMajor(src, { schema: 'fe-sandbox/1', nodeImage: null, nodeMajor: 22 }));
    assert.throws(() => assertNodeMajor(src, { schema: 'fe-sandbox/1', nodeImage: null, nodeMajor: 24 }), /does not match/);
    const deps = path.join(scratch, 'deps-checks');
    prepareDependencyInputs(src, deps);
    assert.deepEqual(readdirSync(deps).sort(), ['package-lock.json', 'package.json']);
    write(src, '.npmrc', 'registry=https://evil.example/');
    assert.throws(() => prepareDependencyInputs(src, path.join(scratch, 'deps-2')), /npmrc/);
    const modules = dir('modules');
    write(modules, 'tsx/package.json', JSON.stringify({ bin: { tsx: './dist/cli.mjs' } }));
    assert.equal(tsxCliEntry(modules), 'dist/cli.mjs');
  });

  test('the build input is bound to the manifest and its snapshot digest', () => {
    const snapshot = Buffer.from('{"schemaVersion":1,"collections":{}}');
    const manifest = parseManifest({ schema: 'fine-elements-release-manifest/1', target: 'test', sequence: 1, source_repository: 'gaimeore/fine-elements', source_commit: 'a'.repeat(40), source_archive_sha256: 'c'.repeat(64), previous_source_commit: null, migration_ceiling: '0011_x' });
    const good = { schema: 'fe-build-input/1', source_commit: 'a'.repeat(40), manifest_sequence: 1, snapshot_b64: snapshot.toString('base64'), snapshot_sha256: sha(snapshot) };
    assert.equal(parseBuildInput(good, manifest).snapshotSha256, sha(snapshot));
    assert.throws(() => parseBuildInput({ ...good, source_commit: 'b'.repeat(40) }, manifest), /not bound/);
    assert.throws(() => parseBuildInput({ ...good, snapshot_sha256: 'd'.repeat(64) }, manifest), /digest mismatch/);
  });
});

function bundleTree(name: string, extra: Record<string, string> = {}): string {
  const root = dir(name);
  for (const [rel, data] of Object.entries({ '_headers': '/*\n', 'index.html': '<!doctype html>', 'assets/index-abc.js': 'console.log(1)', 'assets/index-abc.css': 'body{}', 'robots.txt': 'User-agent: *', 'sitemap.xml': '<urlset/>', ...extra })) write(root, rel, data);
  return root;
}

describe('bundle validator (data only)', () => {
  test('a clean static bundle passes and packs deterministically', () => {
    const root = bundleTree('clean');
    const files = validateBundleTree(root, 'forbidden');
    assert.equal(files.length, 6);
    const packed = packBundle(root, files);
    assert.deepEqual(packed, packBundle(root, validateBundleTree(root, 'forbidden')));
    const out = dir('unpacked');
    assert.deepEqual(unpackBundle(packed, out), files);
    assert.deepEqual(validateBundleTree(out, 'forbidden'), files);
  });

  for (const [label, extra] of Object.entries<Record<string, string>>({
    'source map': { 'assets/index.js.map': '{}' },
    '_worker.js': { '_worker.js': 'x' },
    '_routes.json': { '_routes.json': '{}' },
    '.assetsignore': { '.assetsignore': 'x' },
    'package.json': { 'package.json': '{}' },
    'server source': { 'server/x.js': 'x' },
    'src source': { 'src/main.js': 'x' },
    'git metadata': { '.gitignore': 'x' },
    'typescript': { 'assets/a.ts': 'x' },
    'unexpected type': { 'download.exe': 'x' },
    'rendition in sandbox output': { 'images/collections/sample/x.webp': 'x' },
    'site rendition in sandbox output': { 'images/site/x.webp': 'x' },
  })) {
    test(`rejects ${label}`, () => { assert.throws(() => validateBundleTree(bundleTree(`bad-${label.replace(/\W/g, '-')}`, extra), 'forbidden')); });
  }

  test('rejects links and requires _headers and index.html', () => {
    const linked = bundleTree('linked');
    linkSync(path.join(linked, 'index.html'), path.join(linked, 'copy.html'));
    assert.throws(() => validateBundleTree(linked, 'forbidden'), /hard link/);
    const sym = bundleTree('sym');
    try { symlinkSync(path.join(sym, 'index.html'), path.join(sym, 'alias.html')); assert.throws(() => validateBundleTree(sym, 'forbidden'), /symbolic link/); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EPERM') throw error; // Windows without symlink privilege
    }
    const noHeaders = dir('no-headers');
    write(noHeaders, 'index.html', 'x');
    assert.throws(() => validateBundleTree(noHeaders, 'forbidden'), /_headers/);
  });

  test('a tampered or path-escaping pack fails on unpack', () => {
    const root = bundleTree('tamper');
    const packed = packBundle(root, validateBundleTree(root, 'forbidden'));
    const tampered = Buffer.from(packed);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0xff;
    assert.throws(() => unpackBundle(tampered, dir('t-out')), /does not match/);
    const header = Buffer.from(JSON.stringify({ files: [{ path: '../x.html', size: 0, sha256: sha('') }] }));
    const length = Buffer.alloc(4); length.writeUInt32BE(header.length, 0);
    assert.throws(() => unpackBundle(Buffer.concat([Buffer.from('FEBUNDLE/1\n'), length, header]), dir('t-out2')), /safe relative path/);
  });
});

describe('rendition placement and injection (trusted control code)', () => {
  const r1 = Buffer.from('synthetic webp 1'); const r2 = Buffer.from('synthetic webp 2');
  const id1 = '00000000-0000-4000-8000-000000000001'; const id2 = '00000000-0000-4000-8000-000000000002';
  const snapshot = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    collections: { 'sample-collection': [{ file: `${id1}-${sha(r1)}.webp`, width: 1, height: 1 }] },
    homepage: { text: {}, aboutPortrait: { file: `${id2}-${sha(r2)}.webp`, width: 1, height: 1 } },
  }));

  test('placements follow the private build contract', () => {
    assert.deepEqual(placementsFromSnapshot(snapshot), [
      { kind: 'collection', publicPath: `images/collections/sample-collection/${id1}-${sha(r1)}.webp`, renditionKey: `renditions/sample-collection/${id1}/web-${sha(r1)}.webp`, sha256: sha(r1) },
      { kind: 'site', publicPath: `images/site/${id2}-${sha(r2)}.webp`, renditionKey: `renditions/site/${id2}/web-${sha(r2)}.webp`, sha256: sha(r2) },
    ]);
    assert.throws(() => placementsFromSnapshot(Buffer.from('{"schemaVersion":1,"collections":{"x":[{"file":"../../evil.webp"}]}}')), /malformed/);
    assert.throws(() => placementsFromSnapshot(Buffer.from('{"schemaVersion":1,"collections":{"../x":[]}}')), /malformed/);
  });

  test('only exact-hash bytes are injected, never over an existing file', () => {
    const placements = placementsFromSnapshot(snapshot);
    const root = bundleTree('inject');
    injectRenditions(root, placements, new Map([[placements[0]!.renditionKey, r1], [placements[1]!.renditionKey, r2]]));
    assert.equal(validateBundleTree(root, 'allowed').length, 8);
    assert.throws(() => validateBundleTree(root, 'forbidden'), /rendition/);
    assert.throws(() => injectRenditions(bundleTree('inject-bad'), placements, new Map([[placements[0]!.renditionKey, r2], [placements[1]!.renditionKey, r2]])), /does not match/);
    assert.throws(() => injectRenditions(root, placements, new Map([[placements[0]!.renditionKey, r1], [placements[1]!.renditionKey, r2]])), /already exists/);
    assert.throws(() => injectRenditions(bundleTree('inject-missing'), placements, new Map()), /missing/);
  });
});
