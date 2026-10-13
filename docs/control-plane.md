# Release control plane

This repository is the release and backup authority for Fine Elements. It
holds no application source, product assets, data or credentials. Every
privileged job runs only from the protected `production-release` branch,
inside a GitHub Environment holding exactly one credential family.

## Layout

| Path | Purpose |
|---|---|
| `runner/backup/` | master backup lane: verify-scan → write-missing → verify-again → final coverage |
| `runner/source/` | `source-fetch`: read-only fetch and attestation of one exact private commit (git + Node only) |
| `runner/build/` | trusted host wrapper and the networkless sandbox vectors for the private build |
| `runner/deploy/` | select/claim/prepare, bundle validation, rendition injection, deploy, verify |
| `runner/policy/` | the `fe-policy` engine (trusted `pull_request_target`, PR files read as data) |
| `runner/lib/` | target config, handoff crypto, manifests, job credential split, DB seam |
| `config/` | committed public material: target fingerprints, recipient public keys, sandbox image, action pins |
| `release/` | `test.json` / `prod.json` manifests (created only by class-1 PRs to `production-release`) |

## Release manifest (`fine-elements-release-manifest/1`)

Exact fields: `schema`, `target`, `sequence`, `source_repository`
(`gaimeore/fine-elements`), `source_commit` (40 lowercase hex),
`source_archive_sha256`, `previous_source_commit` (null only for sequence 1),
`migration_ceiling`, and for `prod` only `promoted_from_test_sequence`.

The archive digest is always computed as:

```
git -c core.autocrlf=false -c core.eol=lf archive --format=tar <commit> | sha256sum
```

## Target configuration

Each environment that needs operational identifiers holds one
`TARGET_CONFIG_JSON` secret (`fe-target-config/1`: `schema`, `kind`, `target`,
a random 64-hex `salt`, and the kind's exact fields; never a credential).
`config/target-fingerprints.json` commits the SHA-256 of each canonical
config; runners refuse to start on a mismatch. The `control-policy` config
uses `target: "prod"`. All fingerprints and recipients are `null` until their
provisioning gates.

## Handoffs

Artifacts of a public repository are readable by any signed-in user, so
every cross-job artifact is sealed (X25519 → HKDF-SHA256 → AES-256-GCM) to
the consuming environment's public key in `config/recipients.json`, bound to
repository, workflow, target, run id, run attempt, producer job and artifact
name, padded to 1 MiB buckets, and its SHA-256 pinned via the producer's job
output.

## Status

Workflows exist but nothing privileged can run: there is no environment,
secret, deploy key, GitHub App or `production-release` yet, every
fingerprint and recipient is `null`, and no sandbox image is accepted.

## Bootstrap record

- RC3: the first App-origin `fe-policy` check was observed on a docs-only bootstrap PR before branch protection began requiring it.
