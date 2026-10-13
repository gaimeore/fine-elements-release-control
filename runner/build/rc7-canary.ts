/**
 * RC7 synthetic sandbox canary (S12K-BIG-RUN-5).
 *
 * Runs the PRODUCTION sandbox path (runSandboxBuild, dependencyPhaseArgs,
 * buildPhaseArgs, assertSandboxInvariants) on an invented source tree that
 * contains no Fine Elements code, and proves the isolation properties live
 * on a GitHub-hosted runner. It holds no credential. The per-run marker and
 * the build logs stay on the host; only fixed tokens and non-secret facts
 * are printed. A second, never-terminating synthetic build proves the time
 * bound and the forced removal through the same build vector.
 */
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { FailClosedError } from '../lib/errors.ts';
import { assertReleaseRun, runContextFrom } from '../lib/github.ts';
import { isCredentialName } from '../lib/job-env.ts';
import { extractSource, prepareDependencyInputs, runSandboxBuild, tsxCliEntry } from './build-wrapper.ts';
import { assertSandboxInvariants, buildPhaseArgs, dependencyPhaseArgs, loadSandboxConfig, parseSandboxConfig, type SandboxConfig } from './sandbox.ts';

/** The RC7 candidate (docker.io/library/node:22-bookworm-slim resolved to its OCI index digest). */
export const RC7_CANDIDATE_IMAGE = 'docker.io/library/node@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392';
export const RC7_CONFIG: SandboxConfig = parseSandboxConfig({ schema: 'fe-sandbox/1', nodeImage: RC7_CANDIDATE_IMAGE, nodeMajor: 22 });

/** Per-run log marker, derived from the run identity; this program never prints it. */
export function markerFor(runId: string, runAttempt: string): string {
  return `rc7m${createHash('sha256').update(`rc7-canary-marker:${runId}:${runAttempt}`).digest('hex').slice(0, 40)}`;
}

/** Minimal ustar writer (directories + regular files) for the synthetic archive. */
export function tarOf(files: Readonly<Record<string, string>>): Buffer {
  const header = (name: string, size: number, type: '0' | '5'): Buffer => {
    const h = Buffer.alloc(512);
    h.write(name, 0, 100, 'utf8');
    h.write(type === '5' ? '0000755\0' : '0000644\0', 100, 'ascii');
    h.write('0000000\0', 108, 'ascii');
    h.write('0000000\0', 116, 'ascii');
    h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'ascii');
    h.write('00000000000\0', 136, 'ascii');
    h.write('        ', 148, 'ascii');
    h.write(type, 156, 'ascii');
    h.write('ustar\0', 257, 'ascii');
    h.write('00', 263, 'ascii');
    let sum = 0;
    for (const byte of h) sum += byte;
    h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'ascii');
    return h;
  };
  const blocks: Buffer[] = [];
  const dirs = new Set<string>();
  for (const name of Object.keys(files).sort()) {
    const parts = name.split('/');
    for (let i = 1; i < parts.length; i += 1) {
      const dir = parts.slice(0, i).join('/');
      if (!dirs.has(dir)) { dirs.add(dir); blocks.push(header(`${dir}/`, 0, '5')); }
    }
    const data = Buffer.from(files[name]!, 'utf8');
    blocks.push(header(name, data.length, '0'), data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

const SYNTHETIC_PACKAGE = {
  name: 'rc7-canary-synthetic',
  version: '1.0.0',
  private: true,
  description: 'RC7 synthetic sandbox canary input. Contains no Fine Elements code.',
  scripts: {
    preinstall: 'echo RC7_LIFECYCLE_RAN_PREINSTALL && exit 97',
    postinstall: 'echo RC7_LIFECYCLE_RAN_POSTINSTALL && exit 98',
  },
  dependencies: { tsx: '4.23.15' },
};

const SYNTHETIC_LOCKFILE = {
  "name": "rc7-canary-synthetic",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "rc7-canary-synthetic",
      "version": "1.0.0",
      "hasInstallScript": true,
      "dependencies": {
        "tsx": "4.23.15"
      }
    },
    "node_modules/@esbuild/aix-ppc64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/aix-ppc64/-/aix-ppc64-0.28.2.tgz",
      "integrity": "sha512-XExcO+dvLKvVtNTibSTBej1NCAbaGhWn9Ww1ZPx80qsahhPFe/8jgWP0IchNe0F3HwkU7n8ejhH8bjonqht8mQ==",
      "cpu": [
        "ppc64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "aix"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/android-arm": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/android-arm/-/android-arm-0.28.2.tgz",
      "integrity": "sha512-kXXoiPVVGQcnIYGOeaovwOURpniDBpSq4A03qkQ+BMQqtGG6HYap3xne9C1O1yo4TR3qxlCX5IqqmX6fFo2Lqg==",
      "cpu": [
        "arm"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/android-arm64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/android-arm64/-/android-arm64-0.28.2.tgz",
      "integrity": "sha512-5YfKeeI8qWfBZIX+u2xZC3Zlb3Os/gLS2sbEKM+I4ZOcsWmHS2WLysCcQZDAFRslDUU5Oiq44gf6PYN1vGwG5A==",
      "cpu": [
        "arm64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/android-x64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/android-x64/-/android-x64-0.28.2.tgz",
      "integrity": "sha512-O387ite7SzUyCcy3JQX4P4bLtEA7bLLkx+esve5JHnyYfNTxcVpXZo9jhdB0lTKN44gztELTdU7nS8Nr16Fs1Q==",
      "cpu": [
        "x64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "android"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/darwin-arm64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.28.2.tgz",
      "integrity": "sha512-n4KqkOQrraxHJcgjM1RvwbigfQKIKJVpM7xp+KsxiyUSrRdIXnt73VhrPAx0fV44hgfmIVKjxMN9J1t5jySVkw==",
      "cpu": [
        "arm64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/darwin-x64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/darwin-x64/-/darwin-x64-0.28.2.tgz",
      "integrity": "sha512-uq6suIWYP37qzGddBKPw5QEQPi6HiLGsO7UmkpfyaYNQ3D+rN6w6WfwH+nuqcGXWvawGwxOEroO4YGnFh95azw==",
      "cpu": [
        "x64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/freebsd-arm64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/freebsd-arm64/-/freebsd-arm64-0.28.2.tgz",
      "integrity": "sha512-n+I0BTSRIoy+d6RPKnEVwql5UwBJolytvY4mAOIEJorKlqgPII8ix6slVVrfZ5Tnj7glIZvloylbB/EJPMWEXw==",
      "cpu": [
        "arm64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/freebsd-x64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/freebsd-x64/-/freebsd-x64-0.28.2.tgz",
      "integrity": "sha512-78XJTJkvPs0kz2w61301PJjXl4g7q3JqiYMZ/M/yVI73EHBrCRTgkhu9oqG7vPqq+a/yadEW8aD+agKlk5xrmg==",
      "cpu": [
        "x64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "freebsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-arm": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-arm/-/linux-arm-0.28.2.tgz",
      "integrity": "sha512-XlDnu2q5yoqems+xay6wSAcg9DDD7K9RLKZEBOMZm3ckNpJBvOX20tSfby8KfrrhINDyv9V2YVZKY/SpoGJI8w==",
      "cpu": [
        "arm"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-arm64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-arm64/-/linux-arm64-0.28.2.tgz",
      "integrity": "sha512-pW4AC0P3it8c7do9MVM4p51FzHzdM/TZrerurgRcHJ2WTa1VQ1CIq18xncfpBJw4ojkiZZrKW2yIBWBP92j6Ug==",
      "cpu": [
        "arm64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-ia32": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-ia32/-/linux-ia32-0.28.2.tgz",
      "integrity": "sha512-CYbnj78HsIeA+DhgUKgFCfvNsTHFhMMrinUrMZpDXJXKN8T3XViTZ/+wtHeVxEWY8ewSzTFN+nRmSwO2tZaLUQ==",
      "cpu": [
        "ia32"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-loong64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-loong64/-/linux-loong64-0.28.2.tgz",
      "integrity": "sha512-buwkd8nsph4R+ajRvw0qM5Hja/TXQow3ptzWO2EbG/cqcIkHloRrdlBtQlshyYGTNFvfkfJ5tpPLVkY4DtsPfQ==",
      "cpu": [
        "loong64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-mips64el": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-mips64el/-/linux-mips64el-0.28.2.tgz",
      "integrity": "sha512-ZVykbDyk7519VwiNb9Lcj9m8XM6v5V9uKPvrEMkkEedVewf+0itkhahp4HDpgERXhwLRpWFypsGbG/J8s0QjJA==",
      "cpu": [
        "mips64el"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-ppc64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-ppc64/-/linux-ppc64-0.28.2.tgz",
      "integrity": "sha512-CAXl+Dtd9UUuJd8pKKdwh6MLm3MUMiqMPmhZ3tTSXPqfyQ3vDl6R5hZdZ/kYojK4ofXtdfSv1tFq8XzWx3heNQ==",
      "cpu": [
        "ppc64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-riscv64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-riscv64/-/linux-riscv64-0.28.2.tgz",
      "integrity": "sha512-GeXCej4IQtU1B+QlDV8W/RRvbzI3O/Stss+/bCXv4lZls5WGRtu2a+3JkA3i4qIUlMXpcHebWpF8AkJhATowuA==",
      "cpu": [
        "riscv64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-s390x": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-s390x/-/linux-s390x-0.28.2.tgz",
      "integrity": "sha512-3H1weTYZPxt/WOhByszQZybS9w5lKzUn1FDMsgEChbHWQwHYQQRfBxgCcZvPhjHfKyJjIievvMmEUawJrdY9Dg==",
      "cpu": [
        "s390x"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/linux-x64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-0.28.2.tgz",
      "integrity": "sha512-4xTZr1FUmSoQW4XIWmit3tzQrUTZM+N3P0XV8xROKYF50XfI7xeO90+1bZvNwxIufQ9hDQVRJH5YhgPVF8A/HQ==",
      "cpu": [
        "x64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "linux"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/netbsd-arm64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/netbsd-arm64/-/netbsd-arm64-0.28.2.tgz",
      "integrity": "sha512-sSATRjPeDBg3pdgHoQfoYBob11Kk1FGa9lui5RIHZCoCkJa9QKlvl3/vKz2usCmYYjs7ymJR/2Nnsqe+Hjt5nw==",
      "cpu": [
        "arm64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "netbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/netbsd-x64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/netbsd-x64/-/netbsd-x64-0.28.2.tgz",
      "integrity": "sha512-lqnzCV+mM0gIADaKihiCg6ifgfU2L3h5E33rNQBN1Y4MaVGnzryzmvvf7UHxprpQdE8hpqLolJ9Rl+SkIRDpyw==",
      "cpu": [
        "x64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "netbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/openbsd-arm64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/openbsd-arm64/-/openbsd-arm64-0.28.2.tgz",
      "integrity": "sha512-AL2qJILH7lNjrDmCQDvdxMfAUIv8KMNZOvrwAQ8i8//ntL9FflhOyMJ8OZSMBb8/AWXe3/5v5S20y3zCoZWKoQ==",
      "cpu": [
        "arm64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "openbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/openbsd-x64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/openbsd-x64/-/openbsd-x64-0.28.2.tgz",
      "integrity": "sha512-QtiuPytchRyC4rwUKhexJdQKvDuZ6hWloi3igqPQNUJCS1/v9EiO3UTOXR6A3FoMo4fnAKbWJdqaIwhOzh8qEw==",
      "cpu": [
        "x64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "openbsd"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/openharmony-arm64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/openharmony-arm64/-/openharmony-arm64-0.28.2.tgz",
      "integrity": "sha512-WkhYDmpTjLvGlScA1rwjRUmhl4k8oXR3cIbtqWmELgU/dFeHHlEllxDvdWcNJV9rbzCexB5vz8gtNewWLgCT7Q==",
      "cpu": [
        "arm64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "openharmony"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/sunos-x64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/sunos-x64/-/sunos-x64-0.28.2.tgz",
      "integrity": "sha512-GPMSkTOtMnv2U2F8gxe4Io6qmVs+YKyp832Etqqxr0hFngmXQ3rzwytelm3GIn7T4VviRUlf3sOgBOiTdvaf7g==",
      "cpu": [
        "x64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "sunos"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/win32-arm64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-arm64/-/win32-arm64-0.28.2.tgz",
      "integrity": "sha512-PIhhEkE9uPBleRBrQEJpUn7MBnibZzbGzYWPmY3x+YoVg/95zbjB4CxPPOQ8l5tYYM4mMaCthF8/1DIfBQQyWQ==",
      "cpu": [
        "arm64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/win32-ia32": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-ia32/-/win32-ia32-0.28.2.tgz",
      "integrity": "sha512-YmJbfTlvU7Sdn9BB+4PRES4oB6pxgS37MAONj+hBr/cpXS1aBPKXxNnDbu+QCWPj0o9dgyxeq79g6c5P8KeuYA==",
      "cpu": [
        "ia32"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/@esbuild/win32-x64": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/@esbuild/win32-x64/-/win32-x64-0.28.2.tgz",
      "integrity": "sha512-5ebpxr3nWMzrL/rnUI755Jkuee0bHL/Gq0WTF9lvcpv73wAp5eu8MfBUgWK9bhWvZjj7yX8etf/8tI8Ney695g==",
      "cpu": [
        "x64"
      ],
      "license": "MIT",
      "optional": true,
      "os": [
        "win32"
      ],
      "engines": {
        "node": ">=18"
      }
    },
    "node_modules/esbuild": {
      "version": "0.28.2",
      "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.28.2.tgz",
      "integrity": "sha512-HKVLS8dvII+xoKW9kmqxbRKrnWEXfJJr/FZhhJmiqIB0e053QNYFqOBouTMO/k5sID4MvCiUCvv8b9M4h32wIA==",
      "hasInstallScript": true,
      "license": "MIT",
      "bin": {
        "esbuild": "bin/esbuild"
      },
      "engines": {
        "node": ">=18"
      },
      "optionalDependencies": {
        "@esbuild/aix-ppc64": "0.28.2",
        "@esbuild/android-arm": "0.28.2",
        "@esbuild/android-arm64": "0.28.2",
        "@esbuild/android-x64": "0.28.2",
        "@esbuild/darwin-arm64": "0.28.2",
        "@esbuild/darwin-x64": "0.28.2",
        "@esbuild/freebsd-arm64": "0.28.2",
        "@esbuild/freebsd-x64": "0.28.2",
        "@esbuild/linux-arm": "0.28.2",
        "@esbuild/linux-arm64": "0.28.2",
        "@esbuild/linux-ia32": "0.28.2",
        "@esbuild/linux-loong64": "0.28.2",
        "@esbuild/linux-mips64el": "0.28.2",
        "@esbuild/linux-ppc64": "0.28.2",
        "@esbuild/linux-riscv64": "0.28.2",
        "@esbuild/linux-s390x": "0.28.2",
        "@esbuild/linux-x64": "0.28.2",
        "@esbuild/netbsd-arm64": "0.28.2",
        "@esbuild/netbsd-x64": "0.28.2",
        "@esbuild/openbsd-arm64": "0.28.2",
        "@esbuild/openbsd-x64": "0.28.2",
        "@esbuild/openharmony-arm64": "0.28.2",
        "@esbuild/sunos-x64": "0.28.2",
        "@esbuild/win32-arm64": "0.28.2",
        "@esbuild/win32-ia32": "0.28.2",
        "@esbuild/win32-x64": "0.28.2"
      }
    },
    "node_modules/fsevents": {
      "version": "2.3.3",
      "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
      "integrity": "sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw==",
      "hasInstallScript": true,
      "license": "MIT",
      "optional": true,
      "os": [
        "darwin"
      ],
      "engines": {
        "node": "^8.16.0 || ^10.6.0 || >=11.0.0"
      }
    },
    "node_modules/tsx": {
      "version": "4.23.15",
      "resolved": "https://registry.npmjs.org/tsx/-/tsx-4.23.15.tgz",
      "integrity": "sha512-Yiex1Ovn8z2xPpOWckIiysV1SSyRMY9BkLF++q0yKiDxCqRhosKfMg3janKkiLBwZ5c/YryloKwGZcrEmtwxKw==",
      "license": "MIT",
      "dependencies": {
        "esbuild": "~0.28.0"
      },
      "bin": {
        "tsx": "dist/cli.mjs"
      },
      "engines": {
        "node": ">=18.0.0"
      },
      "optionalDependencies": {
        "fsevents": "~2.3.3"
      }
    }
  }
};

/**
 * The invented build program. It runs ONLY inside the networkless build
 * container. It writes the marker to stdout and stderr (both must land in the
 * isolated build log, never the job log), probes the isolation from the
 * inside, and reports one RC7_RESULT line without the marker.
 */
const SYNTHETIC_PROGRAM = String.raw`import { existsSync, mkdirSync, readFileSync, readdirSync, statfsSync, unlinkSync, writeFileSync } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { connect } from 'node:net';
import { hostname, networkInterfaces } from 'node:os';

const argv = process.argv;
const arg = (name) => argv[argv.indexOf(name) + 1];
const snapshot = JSON.parse(readFileSync(arg('--snapshot'), 'utf8'));
process.stdout.write(snapshot.marker + '\n');
process.stderr.write(snapshot.marker + '\n');

(async () => {
  if (snapshot.mode === 'loop') { setInterval(() => undefined, 60000); return; }
  const r = {};
  r.nodeVersion = process.versions.node;
  r.uid = process.getuid();
  r.gid = process.getgid();
  const status = readFileSync('/proc/self/status', 'utf8');
  for (const k of ['CapEff', 'CapPrm', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp']) {
    const m = new RegExp('^' + k + ':\\s*(\\S+)', 'm').exec(status);
    r[k] = m ? m[1] : null;
  }
  r.pid1 = readFileSync('/proc/1/cmdline', 'utf8').split('\0')[0].split('/').pop();
  r.processCount = readdirSync('/proc').filter((d) => /^[0-9]+$/.test(d)).length;
  r.hostnameLength = hostname().length;
  r.envNames = Object.keys(process.env).sort();
  r.credentialShapedEnv = r.envNames.filter((n) => /TOKEN|SECRET|PASSWORD|PRIVATE|KEY|DATABASE|CLOUDFLARE|^GH_|^GITHUB_|^ACTIONS_|^RUNNER_|^B2_|^R2_|^AWS_/i.test(n));
  r.hostPaths = {};
  for (const p of ['/var/run/docker.sock', '/run/docker.sock', '/home/runner', '/github', '/runner', '/root/.docker', '/etc/docker', '/var/lib/docker']) r.hostPaths[p] = existsSync(p);
  r.interfaces = Object.keys(networkInterfaces()).sort();
  const timeout = (ms) => new Promise((resolve) => setTimeout(() => resolve('TIMEOUT'), ms));
  r.dns = await Promise.race([lookup('example.com').then(() => 'RESOLVED', (e) => e.code || 'ERR'), timeout(8000)]);
  r.tcp = await new Promise((resolve) => {
    const s = connect({ host: '1.1.1.1', port: 443 });
    const t = setTimeout(() => { s.destroy(); resolve('TIMEOUT'); }, 8000);
    s.on('connect', () => { clearTimeout(t); s.destroy(); resolve('CONNECTED'); });
    s.on('error', (e) => { clearTimeout(t); resolve(e.code || 'ERR'); });
  });
  r.writes = {};
  for (const d of ['/', '/etc', '/usr/local/lib', '/in/src', '/in/src/server/deploy', '/in/node_modules', '/in/node_modules/tsx', '/in/snapshot', '/out', '/tmp', '/work']) {
    const f = (d === '/' ? '' : d) + '/.rc7-write-probe';
    try { writeFileSync(f, 'x'); unlinkSync(f); r.writes[d] = 'WRITABLE'; } catch (e) { r.writes[d] = e.code || 'ERR'; }
  }
  r.mounts = readFileSync('/proc/self/mounts', 'utf8').trim().split('\n').map((l) => {
    const f = l.split(' ');
    return { mnt: f[1], fs: f[2], rw: f[3].split(',')[0] === 'rw', opts: f[3].split(',').filter((o) => !o.includes('=') || /^(size|mode)=/.test(o)).slice(0, 8).join(',') };
  });
  const st = statfsSync('/out');
  r.outStatfs = { bsize: st.bsize, blocks: st.blocks, totalBytes: st.bsize * st.blocks, freeBytes: st.bsize * st.bavail };
  const out = arg('--out');
  mkdirSync(out, { recursive: true });
  writeFileSync(out + '/index.html', '<!doctype html><title>rc7 canary</title>\n');
  writeFileSync(out + '/_headers', '/*\n  X-Content-Type-Options: nosniff\n');
  process.stdout.write('RC7_RESULT ' + JSON.stringify(r) + '\n');
})();
`;

/** The invented source tree; nothing here is Fine Elements code or data. */
export function syntheticSource(): Record<string, string> {
  return {
    '.nvmrc': '22\n',
    'package.json': `${JSON.stringify(SYNTHETIC_PACKAGE, null, 2)}\n`,
    'package-lock.json': `${JSON.stringify(SYNTHETIC_LOCKFILE, null, 2)}\n`,
    'server/deploy/build-from-inputs.ts': SYNTHETIC_PROGRAM,
  };
}

const sha256 = (data: Buffer): string => createHash('sha256').update(data).digest('hex');
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Captures a host command's stdout (only non-secret docker/mount facts are ever requested). */
function sh(command: string, args: readonly string[]): { code: number; out: string } {
  const r = spawnSync(command, [...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 300_000 });
  return { code: r.status ?? 1, out: (r.stdout ?? '').trim() };
}

function hostRun(command: string, args: readonly string[], logFile: string): number {
  const fd = openSync(logFile, 'a', 0o600);
  try { return spawnSync(command, [...args], { stdio: ['ignore', fd, fd], timeout: 600_000 }).status ?? 1; } finally { closeSync(fd); }
}

export interface CleanupState { readonly containers: string[]; readonly feRootExists: boolean; readonly feMounts: number; readonly feLoopDevices: number }

function cleanupState(): CleanupState {
  const names = sh('docker', ['ps', '-a', '--filter', 'name=^fe-', '--format', '{{.Names}}']).out;
  return {
    containers: names === '' ? [] : names.split('\n'),
    feRootExists: existsSync('/fe'),
    feMounts: readFileSync('/proc/self/mounts', 'utf8').split('\n').filter((l) => l.split(' ')[1]?.startsWith('/fe')).length,
    feLoopDevices: sh('sudo', ['losetup', '-a']).out.split('\n').filter((l) => l.includes('/fe/')).length,
  };
}
const isClean = (s: CleanupState): boolean => s.containers.length === 0 && !s.feRootExists && s.feMounts === 0 && s.feLoopDevices === 0;

/** Non-secret summary of `docker inspect` for the running build-vector container. */
function summarize(inspect: Record<string, any>): Record<string, unknown> {
  const h = inspect.HostConfig;
  return {
    image: inspect.Config.Image, user: inspect.Config.User, envNames: (inspect.Config.Env as string[]).map((e) => e.split('=')[0]).sort(),
    capDrop: h.CapDrop, capAdd: h.CapAdd, securityOpt: h.SecurityOpt, readonlyRootfs: h.ReadonlyRootfs, privileged: h.Privileged,
    pidMode: h.PidMode, utsMode: h.UTSMode, ipcMode: h.IpcMode, cgroupnsMode: h.CgroupnsMode, usernsMode: h.UsernsMode, networkMode: h.NetworkMode,
    pidsLimit: h.PidsLimit, memory: h.Memory, memorySwap: h.MemorySwap, nanoCpus: h.NanoCpus, ulimits: h.Ulimits, logDriver: h.LogConfig?.Type,
    autoRemove: h.AutoRemove, binds: h.Binds, devices: h.Devices, tmpfs: h.Tmpfs,
    mounts: (inspect.Mounts as Record<string, unknown>[]).map((m) => ({ type: m.Type, source: m.Source, destination: m.Destination, rw: m.RW })),
  };
}

/** Distinct namespaces of the container's PID 1 versus the host's PID 1. */
function namespaces(containerPid: number): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const ns of ['pid', 'uts', 'ipc', 'net', 'mnt', 'cgroup', 'user']) {
    const inner = sh('sudo', ['readlink', `/proc/${containerPid}/ns/${ns}`]).out;
    const host = sh('sudo', ['readlink', `/proc/1/ns/${ns}`]).out;
    out[ns] = inner !== '' && host !== '' && inner !== host;
  }
  return out;
}

async function loopCanary(marker: string, image: string): Promise<Record<string, unknown>> {
  const root = '/fe';
  const log = `${root}/log`;
  if (sh('sudo', ['install', '-d', '-m', '0755', '-o', String(process.getuid?.() ?? 0), root]).code !== 0) throw new FailClosedError('loop canary root could not be created');
  try {
    mkdirSync(log, { recursive: true, mode: 0o700 });
    extractSource(tarOf(syntheticSource()), `${root}/src`);
    prepareDependencyInputs(`${root}/src`, `${root}/deps`);
    if (sh('sudo', ['chown', '-R', '10001:10001', `${root}/deps`]).code !== 0) throw new FailClosedError('loop canary deps could not be prepared');
    const deps = dependencyPhaseArgs({ image, depsDir: `${root}/deps`, name: 'fe-deps-loop' });
    assertSandboxInvariants(deps, 'dependency');
    if (hostRun('docker', deps, `${log}/deps.log`) !== 0) throw new FailClosedError('loop canary dependency phase failed');
    hostRun('docker', ['rm', '-f', 'fe-deps-loop'], `${log}/host.log`);
    const snapshot = Buffer.from(JSON.stringify({ schema: 'rc7-canary-snapshot/1', mode: 'loop', marker }), 'utf8');
    mkdirSync(`${root}/snapshot`, { recursive: true, mode: 0o755 });
    writeFileSync(`${root}/snapshot/snapshot.json`, snapshot, { mode: 0o644 });
    mkdirSync(`${root}/out`, { recursive: true });
    if (sh('sudo', ['chown', '10001:10001', `${root}/out`]).code !== 0) throw new FailClosedError('loop canary output could not be prepared');
    const args = buildPhaseArgs({
      image, name: 'fe-build-loop', srcDir: `${root}/src`, modulesDir: `${root}/deps/node_modules`, snapshotDir: `${root}/snapshot`,
      outDir: `${root}/out`, snapshotSha256: sha256(snapshot), tsxCli: tsxCliEntry(`${root}/deps/node_modules`),
    });
    assertSandboxInvariants(args, 'build');
    const fd = openSync(`${log}/docker-client.log`, 'a', 0o600);
    const started = Date.now();
    // Canary-only short bound (production: --kill-after=15s 1200).
    const child = spawn('timeout', ['--kill-after=5s', '25', 'docker', ...args], { stdio: ['ignore', fd, fd] });
    const exited = new Promise<number>((resolve) => { child.on('close', (code, signal) => resolve(code ?? (signal === 'SIGKILL' ? 137 : 128))); });
    let inspect: Record<string, any> | null = null;
    for (let i = 0; i < 60 && inspect === null; i += 1) {
      await sleep(500);
      const r = sh('docker', ['inspect', 'fe-build-loop']);
      if (r.code === 0) {
        const parsed = (JSON.parse(r.out) as Record<string, any>[])[0]!;
        if (parsed.State?.Running === true && parsed.State?.Pid > 0) inspect = parsed;
      }
    }
    if (inspect === null) throw new FailClosedError('the loop container never ran');
    await sleep(3000);
    const ns = namespaces(inspect.State.Pid as number);
    const runningBeforeBound = sh('docker', ['inspect', '--format', '{{.State.Running}}', 'fe-build-loop']).out === 'true';
    const exitCode = await exited;
    closeSync(fd);
    const elapsedSeconds = Math.round((Date.now() - started) / 1000);
    const stateAfterBound = sh('docker', ['inspect', '--format', '{{.State.Status}}', 'fe-build-loop']);
    // The production wrapper's very next step after its bound: forced removal.
    hostRun('docker', ['rm', '-f', 'fe-build-loop'], `${log}/host.log`);
    await sleep(1000);
    const goneAfterForcedRemoval = sh('docker', ['inspect', 'fe-build-loop']).code !== 0;
    const loopLog = existsSync(`${root}/out/.build.log`) ? readFileSync(`${root}/out/.build.log`, 'utf8') : '';
    return {
      inspect: summarize(inspect), namespacesDistinctFromHost: ns, runningBeforeBound, timeoutExitCode: exitCode, elapsedSeconds,
      containerStateAfterBound: stateAfterBound.code === 0 ? stateAfterBound.out : 'absent', goneAfterForcedRemoval,
      loopMarkerInIsolatedLog: loopLog.includes(marker),
    };
  } finally {
    hostRun('docker', ['rm', '-f', 'fe-deps-loop', 'fe-build-loop'], '/dev/null');
    hostRun('sudo', ['rm', '-rf', root], '/dev/null');
  }
}

const RO_PATHS = ['/', '/etc', '/usr/local/lib', '/in/src', '/in/src/server/deploy', '/in/node_modules', '/in/node_modules/tsx', '/in/snapshot'];
const VIRTUAL_FS = new Set(['proc', 'sysfs', 'tmpfs', 'devtmpfs', 'devpts', 'mqueue', 'cgroup', 'cgroup2', 'overlay']);
const DOCKER_MANAGED_FILES = new Set(['/etc/hosts', '/etc/hostname', '/etc/resolv.conf']);

export async function main(env: NodeJS.ProcessEnv): Promise<void> {
  const foreign = Object.keys(env).filter((name) => typeof env[name] === 'string' && env[name] !== '' && isCredentialName(name));
  if (foreign.length > 0) throw new FailClosedError(`the canary holds no credential: ${foreign.sort().join(', ')}`);
  const run = runContextFrom(env);
  assertReleaseRun(run);
  const marker = markerFor(run.runId, run.runAttempt);
  const image = RC7_CANDIDATE_IMAGE;
  const digest = image.split('@')[1]!;

  if (sh('docker', ['pull', image]).code !== 0) throw new FailClosedError('the candidate image could not be pulled by digest');
  const imageFacts = sh('docker', ['image', 'inspect', '--format', '{{json .RepoDigests}}|{{.Architecture}}|{{.Os}}', image]).out.split('|');
  const repoDigests = JSON.parse(imageFacts[0] ?? '[]') as string[];

  const wrapper = readFileSync('runner/build/build-wrapper.ts', 'utf8');
  const wrapperBound = wrapper.includes("host.run('timeout', ['--kill-after=15s', '1200', 'docker', ...buildArgs]")
    && wrapper.includes("host.run('docker', ['rm', '-f', 'fe-build']");

  const snapshot = Buffer.from(JSON.stringify({ schema: 'rc7-canary-snapshot/1', mode: 'build', marker }), 'utf8');
  let log = '';
  let files: string[] = [];
  try {
    const result = await runSandboxBuild({ archive: tarOf(syntheticSource()), build: { snapshot, snapshotSha256: sha256(snapshot), sourceCommit: '0'.repeat(40), manifestSequence: 0 }, config: RC7_CONFIG });
    log = result.log.toString('utf8');
    files = result.files.map((f) => f.path).sort();
  } catch (error) {
    const failed = (error as { log?: Buffer }).log?.toString('utf8') ?? '';
    // Synthetic-only log; the marker is redacted before anything is printed.
    console.error(failed.split(marker).join('<marker>').split('\n').slice(-60).join('\n'));
    throw error;
  }
  const line = log.split('\n').find((l) => l.startsWith('RC7_RESULT '));
  if (line === undefined) throw new FailClosedError('the synthetic build reported no result');
  const facts = JSON.parse(line.slice('RC7_RESULT '.length)) as Record<string, any>;
  const markerHits = log.split(marker).length - 1;
  const lifecycleRan = log.includes('RC7_LIFECYCLE_RAN');
  const afterBuild = cleanupState();

  const loop = await loopCanary(marker, image);
  const final = cleanupState();

  const i = loop.inspect as Record<string, any>;
  const ns = loop.namespacesDistinctFromHost as Record<string, boolean>;
  const mounts = facts.mounts as { mnt: string; fs: string; rw: boolean; opts: string }[];
  const outMount = mounts.find((m) => m.mnt === '/out');
  const persistentRw = mounts.filter((m) => m.rw && !VIRTUAL_FS.has(m.fs) && !DOCKER_MANAGED_FILES.has(m.mnt)).map((m) => m.mnt);
  const total = Number(facts.outStatfs.totalBytes);
  const proofs: Record<string, boolean> = {
    IMAGE: repoDigests.some((d) => d.endsWith(`@${digest}`)) && imageFacts[1] === 'amd64' && Number(String(facts.nodeVersion).split('.')[0]) === 22 && i.image === image,
    LIFECYCLE_SCRIPTS_DISABLED: !lifecycleRan,
    NETWORK_ISOLATION: JSON.stringify(facts.interfaces) === '["lo"]' && facts.dns !== 'RESOLVED' && ['ENETUNREACH', 'EHOSTUNREACH', 'EADDRNOTAVAIL', 'EACCES', 'EPERM'].includes(facts.tcp) && i.networkMode === 'none',
    NO_TOKEN_VISIBILITY: facts.credentialShapedEnv.length === 0 && Object.values(facts.hostPaths as Record<string, boolean>).every((v) => !v)
      && !mounts.some((m) => /docker\.sock|^\/home|^\/github|^\/runner|^\/var\/lib\/docker/.test(m.mnt))
      && (i.envNames as string[]).every((n) => ['CI', 'HOME', 'NODE_ENV', 'NODE_VERSION', 'PATH', 'YARN_VERSION'].includes(n)),
    LOG_ISOLATION: markerHits >= 2 && loop.loopMarkerInIsolatedLog === true,
    READONLY_MOUNTS: RO_PATHS.every((p) => facts.writes[p] === 'EROFS') && facts.writes['/out'] === 'WRITABLE' && JSON.stringify(persistentRw) === '["/out"]',
    OUTPUT_BOUND: outMount?.fs === 'ext4' && ['nosuid', 'nodev', 'noexec'].every((o) => outMount.opts.split(',').includes(o)) && total > 600 * 1024 * 1024 && total <= 768 * 1024 * 1024,
    TIME_BOUND: wrapperBound && [124, 137].includes(loop.timeoutExitCode as number) && (loop.elapsedSeconds as number) <= 45 && loop.runningBeforeBound === true && loop.goneAfterForcedRemoval === true,
    RESOURCE_LIMITS: i.user === '10001:10001' && JSON.stringify(i.capDrop) === '["ALL"]' && (i.capAdd === null || i.capAdd.length === 0)
      && (i.securityOpt as string[]).some((o) => /^no-new-privileges([:=]true)?$/.test(o)) && i.readonlyRootfs === true && i.privileged === false
      && i.ipcMode === 'private' && i.cgroupnsMode === 'private' && i.pidMode === '' && i.utsMode === '' && i.usernsMode === ''
      && ns.pid === true && ns.uts === true && ns.ipc === true && ns.net === true && ns.mnt === true && ns.cgroup === true
      && i.pidsLimit === 1024 && i.memory === 8 * 1024 ** 3 && i.memorySwap === 8 * 1024 ** 3 && i.nanoCpus === 3e9
      && (i.ulimits as { Name: string; Soft: number; Hard: number }[]).some((u) => u.Name === 'core' && u.Soft === 0 && u.Hard === 0)
      && i.logDriver === 'none' && i.autoRemove === true && (i.binds === null || i.binds.length === 0) && (i.devices === null || i.devices.length === 0)
      && facts.uid === 10001 && facts.gid === 10001 && /^0+$/.test(facts.CapEff) && facts.NoNewPrivs === '1',
    CLEANUP: isClean(afterBuild) && isClean(final) && JSON.stringify(files) === '["_headers","index.html"]',
    WORK_SCRATCH_WRITABLE: facts.writes['/work'] === 'WRITABLE' && facts.writes['/tmp'] === 'WRITABLE',
    CONFIG_PINNED: loadSandboxConfig().nodeImage === image && loadSandboxConfig().nodeMajor === 22,
  };
  console.log(`RC7_FACTS ${JSON.stringify({ image: { reference: image, repoDigests, architecture: imageFacts[1], os: imageFacts[2] }, inContainer: facts, loop, cleanup: { afterBuild, final }, bundleFiles: files, wrapperBound })}`);
  for (const [name, ok] of Object.entries(proofs)) console.log(`FE_RC7_${name}=${ok ? 'PASS' : 'FAIL'}`);
  if (!Object.values(proofs).every(Boolean)) throw new FailClosedError('an RC7 canary proof failed');
  console.log('FE_RC7_CANARY=PASS');
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.env).catch((error: unknown) => {
    console.error(`FE_RC7_CANARY=FAIL ${error instanceof FailClosedError ? error.message : `${(error as Error)?.name ?? 'failed'} ${(error as NodeJS.ErrnoException)?.code ?? ''}`}`);
    process.exit(1);
  });
}
