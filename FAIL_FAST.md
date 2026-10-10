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
