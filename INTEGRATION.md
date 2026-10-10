# Staging integration contract

This revision combines reviewed role integration with its separate authorization
timing correction. It remains a source-only, staging implementation. No actual
social-mutation handler, automatic scheduler, login flow, production cutover, or
Library transport is enabled.

## Composition and source pins

Use `native_handler.staged_coordinator` for role-specific integration. The generic
coordinator alone does not add publisher preparation checks or goal handling.
The default adapters remain unavailable until an explicit staging composition is
created. Integration state lives below the configured staging root's `integration/`
directory; source code is read separately from the checkout. Importing configuration
does not initialize databases or create state directories.

Ledger adapters execute explicitly hash-pinned public source and accept only their
dedicated disposable staging subdirectories. Both adapter filenames are compatible
entry points against this repository's reviewed ledger baseline, not historical
operational source copies. Their limited command surface excludes initialization,
activation, recovery, denial or uncertainty finalization, STOP clearance, and browser actions.
Changes to pinned source require explicit review and literal pin updates; never
compute a new acceptable pin automatically at runtime.

The adapters in this public revision explicitly pin the quarantine-aware portable
ledger, checkpoint, packager, quarantine and publisher-preparation helpers. They load these helpers and the denial validator from
those checked bytes and retain the same restricted command surface. The unchanged
queue/core source pins remain separate. Earlier v4 work is not part of this public
integration and cannot accept this baseline without its own explicit pin update,
regression tests, and independent review. No v4 production route is enabled here.

## Authorization and role goals

Finite grants bind the exact ordered actions and payloads, role, worker, canonical
browser/tab/account, scheduled slot, policy, and independently supplied evidence.
The timing correction rechecks expiry and rollback after slow policy/validation
work, before consumption, and at the return boundary. It does not extend expiry or
make a returned snapshot valid forever. The current replay store is process-local;
production needs a reviewed durable service and authentic approval provenance.

Publisher permits one complete root plus three continuations. Commenter accepts
exact approved replies without an invented numerical goal. The staged spreader
planner counts only five newly verified reposts, including independently established
same-run progress. Duplicates and already-present actions do not count. Reviewed
reserve candidates cannot manufacture new grants. Exhaustion or deadline produces
an honest shortfall; denial/uncertainty blocks further work. Related actions retain
their own explicit conditions and authorization.

## Durable publisher evidence

The retained proof binds all four ordered parts and distinct owned permalinks,
exact text/parentage, original image bytes/digest, visible-image observation, and
the article preview in the first continuation. Source observations and image bytes
are embedded in the existing proof blob so archive verification does not depend on
old filesystem paths. Input images are bounded to 4 MB, embedded content to 5.5 MB,
and proof to 8 MB. Hashes establish byte integrity, not genuine browser provenance
or visual correctness; trusted native collection remains required.

## Observe-only handoff

`read_trial_driver.py` publishes one-role or three-role `observe` tickets only. The
caller must explicitly supply the canonical protected composer browser/tab pair;
there is no hardcoded real binding or silently omitted protection. Bindings must
use distinct workers/tabs, the trial directory must be empty, and the window is
30–300 seconds. The CLI requires `--protected-browser-id` and `--protected-tab-id`
when publishing. Do not use synthetic examples as actual observations or approval.

`native_read_cli.py` supports only inspect, claim, begin, and complete. An assigned,
authorized native worker supplies genuine read-only observations between begin
and complete. One-use markers, exact ticket/binding checks, final completion, and
fresh timing are required. Missing login, denial, timeout, uncertainty, or mismatch
means preserve the ticket/state and stop. No automatic retry or replacement tab is
allowed. These modules neither invoke a browser nor enable mutations themselves.

Keep all bindings, tickets, observations, approval inputs, runtime databases, logs,
receipts, and backups outside version control. Source tests contain synthetic data
only. Real observe-only trials do not prove production mutation safety or authorize
deployment, live action retries, or STOP reconciliation.

## Mandatory preparation and the older staged publisher

All new ledger publish intents require the bounded preparation source contract.
The existing v3 staging adapter deliberately exposes none of its creation, step,
completion, unknown-resolution or final-seal commands. Its older publisher bundle
payload is also distinct from the new preparation payload. Thus that route stops
at the reserved action before a final intent or browser mutation; do not silently
translate payloads, fabricate a seal, or add commands to get around this boundary.
A supported end-to-end publisher integration would require a separate reviewed
change and authorization. No such route, v4 transport or deployment is added here.

The existing four-part proof validator remains available for read-only historical
evidence validation. Tests retain its strict root/reply/image/preview checks and
archive-after-source-deletion coverage using the explicit historical recovery API.
New preparation tests independently cover the supported five-step helper, final
intent, four receipts, denial closure, and restored archive ACK.
