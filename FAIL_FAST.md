# Fail-closed execution

Await final command completion before inspecting a result. Require exit code zero,
complete untruncated output, one valid JSON object, `ok=true`, and the exact expected
account/database/action/owner/state. A running session, a successful shell-tool call,
or a partial output is not success.

Before one separately authorized mutation, perform current account/tab checks,
authorization/quota checks, exact duplicate preflight, and a fresh committed intent.
Only the resulting one-use permit may reach the mutation boundary. Check the exact
same-role slot start and deadline immediately before dispatch. Never execute shell
preflight and browser mutation concurrently.

A lost intent response must not dispatch. A denial, exception, uncertain mutation,
wrong readback, missing file, identity mismatch, damaged schema, lost owner token,
expired slot, or pending checkpoint blocks later actions. There is no automatic
retry, timeout takeover, negative-readback retry, or alternate route around a refusal.

An already-started action may finish readback/bookkeeping after its slot expires;
this never permits a new action. Successful clicks are not verification. Any unknown
outcome retains STOP and blocks the account. Operators must separately authorize
and verify reconciliation. Preserve immutable history rather than rewriting it.

These are cooperative single-host controls. They cannot fence human actions or
unrelated clients, authenticate arbitrary caller assertions, or promise external
exactly-once delivery. All real writers must eventually use the reviewed route.

A separately authorized uncertain-attempt quarantine can terminate only the exact
legacy attempt while preserving `external_outcome=unknown`, zero verified count,
and `retry_allowed=false`. It permanently excludes the entire canonical post from
all post-write kinds. Corrupt or missing quarantine evidence blocks acquisition,
status, and checkpoints. Fresh unrelated work remains gated by the normal verified
checkpoint. Read [QUARANTINE.md](QUARANTINE.md) for the exact trust boundary; a
partial readback or a rehashed approval object cannot authenticate an approval.

A publisher draft requires exactly five ordered, one-use preparation permits. Each
authorizes only its bound draft operation, never final submission. A lost/unknown
permit or result blocks later changing work; read-only inspection is not completion.
A fresh final visual seal is required before the separate final publish intent,
whose exclusive expiry must be checked again immediately before the browser call.
An expired post-commit return leaves the intent durable but grants no dispatch.
Exact denied-final-call bookkeeping stays separate from unknown draft recovery.

## Existing-tab checks and a bounded read-only diagnostic

After the unchanged status, checkpoint, STOP and exclusive-writer gates, use the
existing Threads tab normally. Confirm it in the current read-only tab inventory;
never assume a previous run's tab ID exists. For a stale handle or `Tab not found`
without a denial, refresh that inventory, select a suitable existing Threads tab
and verify the actual expected account. Do not repeatedly request a known-dead
handle to manufacture failures. If no suitable tab exists, report that state;
do not guess or automatically create one. A missing bound preparation tab stops
the run and cannot be rebound.

Before preparation starts, three consecutive otherwise permitted read-only
attempts with the exact same observed error allow one fresh direct Threads tab
for diagnosis in the same approved cloud browser, at most once per run. Retain
the exact error text, operation, observation time and permitted-read status in
the private run report. Success resets the count; a different error breaks the
sequence. Verify the expected logged-in account read-only and pin the actual tab.

Approval denial, required/failed login, security restriction or an uncertain
external write requires an immediate stop and report. Never repeat such a failure
to reach three, or open another tab to retry or bypass it. Do not change browser,
session, settings or credentials, replay consumed intents/permits, or switch an
already-started preparation's bound tab or payload. This procedure creates no
automatic counter, browser operation or permission grant.
