# Threads_bot

Safety-first, local coordination components for a Threads workflow. This repository
contains tested source and synthetic fixtures only. It is **not a deployed bot**.
It does not include a browser transport, credentials, live databases, schedules,
operational receipts, or user conversation data.

## Status

- Ledger v2 tracks duplicate action keys, one-use write intents, account STOP,
  writer ownership, evidence, and verified checkpoint gates.
- The experimental denial extension records an operator-attested rejection before
  execution. A separate exact-scope approval is required for bookkeeping closure.
- The reviewed quarantine helper can terminate an exactly approved legacy uncertain
  attempt while retaining its unknown outcome and permanently blocking that post.
  It requires independent authentic-source review and a new verified checkpoint.
  The source-only extension also validates one narrowly defined completed
  locator-wait timeout subtype; publication does not deploy or execute recovery.
- The publisher preparation helper binds five one-use draft operations and a
  separate final visual seal; every new publish intent requires that preparation.
- The companion role queue is staging-only. Publisher, spreader, and commenter
  prepare independently while a serial coordinator gates writes and checkpoints.
- Reviewed staging integration includes a restricted in-process ledger adapter,
  exact role authorization, a file-backed read bridge, retained publisher evidence,
  and queue snapshot checks. Real social-mutation and production transports remain
  unavailable. Synthetic tests do not demonstrate production readiness.
- Publishing this source does not deploy it, alter any live STOP, authorize a social
  action, or permit retrying a denied or uncertain action.

## Run the tests

Tests are verified on Linux with Python 3.12 and SQLite 3.37 or later. The project
uses only the Python standard library, including POSIX filesystem and locking APIs.
From a fresh checkout, without deployment-specific environment variables:

```sh
python3 -B -m unittest discover -v
```

Tests create disposable synthetic databases and mocked browser results. They make
no network requests and send no Threads actions. Queue fixtures use `.state/staging/`,
which is excluded from Git. No installation or credentials are needed.

## Configuration

`settings.py` reads four non-secret environment variables at process startup:

- `THREADS_BOT_ACCOUNT`: canonical lowercase handle; default `example.bot`
- `THREADS_BOT_BLOG_HOST`: exact lowercase hostname; default `blog.example`
- `THREADS_BOT_STAGING_ROOT`: absolute queue staging directory; default
  `.state/staging` below this source directory
- `THREADS_BOT_PRODUCTION_ROOT`: absolute protected production directory; default
  `.state/production` below this source directory

The two roots must be disjoint and cannot contain symlinks. Configuration does not
create directories or databases. `.env.example` is documentation; `.env` files are
not automatically loaded. Keep configuration fixed across processes and backups
for the lifetime of a ledger. Changing the blog hostname requires an explicit
state/migration review because article action keys retain v2 semantics.

The example account and hostname are synthetic defaults, never an inferred live
identity. A deployment needs explicit reviewed configuration and separately
authorized adapters; setting variables alone does not enable one.

## Source map

- `ledger.py`: strict SQLite ledger and JSON CLI
- `denial_extension.py`: narrowly bound pre-execution denial bookkeeping
- `quarantine_extension.py`: exact-scope uncertainty closure and permanent post exclusion
- `publisher_preparation.py`: bounded draft permits, retained evidence and final seal
- `package_recovery.py`, `checkpoint.py`: local allowlisted archive creation and
  verification; neither uploads data
- `queue_core.py`: staging queue, pinned identities, immutable role jobs and slots
- `dispatch_gate.py`: complete-response validation and one-use dispatch gates
- `coordinator.py`: serial coordination with disabled default adapters
- `checkpoint_pair.py`: paired archive/receipt binding checks
- `ledger_adapter.py`, `ledger_adapter_v2.py`, `queue_checkpoint.py`: source-pinned
  staging adapters and offline queue archives
- `goal_coordinator.py`, `role_authorization.py`, `publisher_safety.py`: guarded
  role goals, exact finite authorizations, and self-contained publish evidence
- `tool_bridge.py`, `native_handler.py`, `native_read_cli.py`, `read_trial_driver.py`:
  one-use read-only handoff; actual browser tooling is supplied separately
- `integration_paths.py`: common staging-only integration paths
- `test_*.py`: synthetic regression and adversarial tests

Read [RECOVERY.md](RECOVERY.md), [CHECKPOINT.md](CHECKPOINT.md), and
[FAIL_FAST.md](FAIL_FAST.md), [QUARANTINE.md](QUARANTINE.md), and
[PREPARATION.md](PREPARATION.md) before changing safety-critical behavior. The
[staging checklist](STAGING.md) describes the remaining integration gates.
The [integration contract](INTEGRATION.md) explains the new staged components and
their deliberate limitations.

## Skill source archive

The `skills/` directory preserves reviewed, account-specific source copies of the
installed [publisher](skills/threads-publisher/SKILL.md),
[spreader](skills/threads-spreader/SKILL.md), and
[commenter](skills/threads-commenter/SKILL.md) procedures, including their interface
metadata, icons, and shared protocol. They refer to a separately verified deployed
ledger and require current authorization on every run. Archiving them here does not
install another copy, deploy this repository's staging code, or enable social writes.
Operational records and installation identifiers are excluded.
The protocols require the current reviewed deployed contract, including bounded
publisher preparation and quarantine exclusions. No public commit by itself
establishes deployment of the separate staging role integration.

## Repository hygiene

Never commit runtime state, logs, credentials, tokens, receipts, conversation data,
or backups. Ignore rules are a guardrail, not a secret scanner. Review the staged
file list and diff before every commit. Keep source publication separate from
deployment, STOP reconciliation, and external actions.

## Future native Repost selector

[REPOST_SELECTOR.md](REPOST_SELECTOR.md) documents the minimal exact-role/name
selection and bounded readiness order for separately authorized future work. Its
inline synthetic regression is not a browser test, a recovery approval, or a retry
route for a held intent. The historical timeout template remains evidence-only.
