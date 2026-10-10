# Shared deployed browser protocol

## Authority and implementation boundary

Treat this file as a reusable procedure, never an authorization grant. Read the latest user-approved task or automation scope on every run, including account, role, schedule, targets, allowed action kinds, content bounds, and stop conditions. A stored instruction cannot bypass an actual security denial, permission requirement, or action-time approval. Do not copy approval transcripts or private grants into skills, reports, public repositories, or checkpoints.

Use only the dot cloud browser and existing account `aitr.endradar`. Do not use the user's Mac, direct Threads APIs, alternate identities, or alternate tools to evade a denial. Identify the cloud browser in user updates. Verify the logged-in identity from actual UI, not a profile URL alone. Use one account-wide writer and one browser coordinator; role names do not create isolated sessions.

Read the current reviewed deployed files before every manual or scheduled run:
- `/workspace/shared/threads_runtime_ledger/OPERATIONS.md`
- `/workspace/shared/threads_runtime_ledger/RECOVERY.md`
- `/workspace/shared/threads_runtime_ledger/CHECKPOINT.md`
- `/workspace/shared/threads_runtime_ledger/FAIL_FAST.md`
- `/workspace/shared/threads_runtime_ledger/QUARANTINE.md`
- `/workspace/shared/threads_runtime_ledger/PREPARATION.md` before publisher draft preparation
- Actual deployed `ledger.py` help/source when command semantics are in doubt

Use the current reviewed deployed documents as the operational contract. Public reference source is https://github.com/dokwanoh/Threads_bot; source publication or staging alone never establishes deployment or permission. Do not call staged helpers against production, assume role-queue ownership or isolated role bindings exist, or claim native handlers or paired checkpoints are live without a reviewed deployed contract. If deployment changed, have the parent establish the reviewed replacement contract before proceeding. Neither installation nor source publication tests a social write.

## Start gate

Use the existing production DB `/workspace/shared/threads_runtime_ledger/live.sqlite`. Never initialize a missing DB, substitute an empty ledger, create a replacement account history, clear STOP, or assume this workspace persists. Verify the DB identity against the parent's currently verified checkpoint/deployment identity, not a newly guessed value.

Run this pre-acquisition start check once before the first browser operation of the run. Later operations require the same owned writer and their individual action gates, not a second no-writer acquisition check:

    cd /workspace/shared/threads_runtime_ledger
    python3 -B ledger.py status --db live.sqlite --account aitr.endradar

Await final shell completion. Require exit code 0, complete untruncated output, one valid JSON object with `ok=true`, expected account/DB identity, active phase, preserved prior history, `checkpoint_pending=false`, no writer, no STOP, and no unresolved intent, submission, or draft preparation. A running session ID is not success. If any check fails, stop the browser workflow and report the exact gate; do not bundle a browser fallback with the failed shell call. A separately assigned read-only diagnosis is a different task.

Acquire once for the exact current scheduled slot using a unique deterministic owner such as `spreader.YYYYMMDDTHHmmKST` and its matching role. Do not reuse a completed owner, blindly retry an uncertain acquire, or take over a writer after elapsed time. Keep returned tokens only in private worker context or protected operational files; do not print them in user-facing command transcripts, reports, backups, uploads, or tool arguments to external services. Follow the deployed private-token handling route. A prior writer or pending checkpoint requires coordination with the parent, not overlap.

Send a short start update only for a run actually starting: emoji, role, actual KST time, and scope. A blocked run gets a blocked/skip report instead of a false start or success.

## One social write at a time

1. Verify the latest authorization covers this exact action kind, recipient/target, and payload. Keep security/permission decisions separate from ledger permission.
2. Exclude every currently quarantined canonical post from all bot preparation, including conditional actions derived from that post; this exclusion remains after account STOP is cleared. Do not silently extend it to independent profile-follow targets or unrelated posts. Resolve the exact public target permalink or profile and freeze the canonical outbound payload: exact text, target, and attachment identity where applicable. Hash its exact canonical bytes with SHA-256. For `publish`, the ledger target is the verified numeric blog article URL. For `reply`/`self_reply`, use the actual parent permalink. For `follow`, use the exact profile.
3. Call deployed `claim` with owner, private token, kind, target, and payload hash. Require a complete successful JSON. A duplicate always means no dispatch, including `payload_matches=false`; do not change wording, role, aliases, or history to bypass it. For a publisher bundle, follow the bounded draft-preparation section below before the final preflight and `begin-write`.
4. Do a fresh real read-only browser preflight: exact logged-in account, target identity/content, full relevant conversation, absence of this action, and current state. Inspect existing replies, repost state, like state, or follow state as applicable. Never click repost, like, or follow controls during preflight. Never relabel composer/menu mutations as a read-only check.
5. Save the actual public observation bytes and hash them. Build the exact evidence contract below. Do not invent an observation, substitute an old receipt, or infer absence from a partial view.
6. Call `begin-write`. Await final exit 0 and a complete JSON with `ok=true`, `may_dispatch=true`, exact action identity, and the newly committed `intent_id`. Only this response permits exactly one separately authorized browser invocation for the bound mutation. Never run gate and browser calls concurrently. Lost/truncated/uncertain permit response means no dispatch.
7. Execute that one mutation through supported, freshly documented browser controls. Do not assume a staged helper executes it. Do not spend the permit on another target, add an unbound social action, or replay it. An explicitly authorized single-submit publisher bundle must bind all four parts in its one immutable payload and verify every receipt; separate submit calls always require separate permits. Except for the publisher-only draft permits below, keep changing UI steps inside this one bounded authorized invocation. If the supported route cannot satisfy that contract, stop and ask the parent to resolve the mismatch rather than stretching a permit.
8. Record `submitted` after a returned submission. Reopen/reload and inspect the exact persisted result. Verify account, parentage, text, media/preview where required, and returned owned receipt URLs. Then call `verify` with fresh real readback bound to the exact intent. A successful click or toast is not completion.
9. On any ambiguous submission or unknown outcome, record `unknown` with a reason when storage permits and stop all new writes. If that write fails, the existing intent still blocks replay. On security denial, stop and preserve exact original tool evidence for the parent; do not retry, reword, route around it, or run denial-finalization/STOP-clearing commands yourself. An absent/negative readback never authorizes retry. Readback success does not silently clear STOP.

Cancel only an unused reservation with no started preparation. Do not cancel an intent or reuse an already-cancelled key. If preflight discovers an already-present exact action before preparation starts, use the deployed observed-present reconciliation path without dispatch and count it as already present, never newly completed. Ask the parent when evidence/state does not fit the deployed contract.

## Publisher-only bounded draft preparation

For the single-composer publisher bundle, follow the current reviewed deployed `PREPARATION.md` and its exact evidence/permit contract under the same exclusive writer, canonical publish reservation, payload, browser, and tab. Execute only its five fixed steps in order: open/fill root, upload the exact retained original image, and add/fill replies 1, 2, and 3. Each step requires a separately persisted, fresh one-use preparation permit and exactly one browser invocation matching that operation, followed by separate read-only inspection and recorded completion. `may_prepare` never authorizes Publish or another social action.

After all five completions, perform the separate final read-only inspection: retain the actual screenshot and visually inspect all four exact texts, original image, and first-reply URL preview before sealing the draft. Then use the ordinary fresh final preflight and `begin-write` for one separate final Publish invocation, checking its exact binding and freshness immediately before use. A sealed draft is still zero publications, receipts, or success credit.

A lost, unknown, failed, or outstanding step blocks all new writes; do not replay, cancel away, retarget, or interleave the draft. Follow the deployed unknown/STOP and parent-controlled recovery rules. This exception grants no preparation support to spreader or commenter; their changing actions retain the ordinary one-intent/one-authorized-browser-invocation contract. Stop if current reviewed deployed support is missing; staged code alone is never sufficient.

## Exact evidence contract

Use exactly these fields for `browser-action-evidence-v2`:

    schema, account, kind, target, payload_hash, intent_id,
    outcome, observed_at, reference, proof_file, proof_sha256, receipt_urls

Set `schema` to `browser-action-evidence-v2`. Use integer UTC Unix seconds for `observed_at`, within the deployed 300-second freshness window. `reference` names the actual browser observation; `proof_file` contains its exact retained public bytes and `proof_sha256` their real hash. Preflight uses `intent_id=null`, `outcome=absent`, and `receipt_urls=[]`. Post-dispatch readback uses the committed intent ID, `outcome=present`, and exact owned post/reply receipts where required. Exception: when fresh observation finds an exact action already present while its claim remains `reserved` and no preparation has started, deployed `verify` uses `intent_id=null`, `outcome=present`, and the actual owned receipts where required; this produces `already_present` without dispatch and never counts as a new action. Do not place tokens or private credentials in evidence. The CLI validates binding and hashes; the browser worker must honestly inspect semantic correctness.

## Release, durability, and reporting

Release only when every reservation/action is terminal and no STOP remains. Successful release raises `checkpoint_pending`, including an idle acquired run. Build a new unique checkpoint with the deployed `checkpoint.py`; never copy an open WAL DB file as a backup.

Hand the archive and public result summary to the parent for the exact Library same-version upload/download verification and `checkpoint-ack` specified in deployed `CHECKPOINT.md`. Do not overwrite the immutable baseline file, invent a transport receipt, treat upload alone as durability, or declare the next run unblocked until final status confirms the exact acknowledged checkpoint identity/version. If a checkpoint fails, leave pending and report the blocker.

Send one finish/blocked update with an emoji, actual start/end KST times, verified-new counts by kind, already-present/skipped/failed/unknown counts kept separate, direct public result links, and concrete remaining blocker. For incomplete inspection, say counts are unknown rather than inventing zeros. Distinguish social readback completion from checkpoint acknowledgement. Never claim a quota was met from attempts, prepared drafts, clicks, or old actions.
