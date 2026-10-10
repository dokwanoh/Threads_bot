# Bounded publisher draft preparation

This source extension records **draft preparation only**. It has no browser driver, network calls, social submission, retry, cancellation, reset, resumption or permission-granting mechanism. It preserves the existing publisher-owned reservation and canonical publish key, and leaves `actions.state = reserved` until the separate final publish intent. Preparation never creates receipts or verified/already-present success.

## Fixed payload and retained evidence

`create_preparation(ledger, owner, token, action, payload_path, payload_sha256, browser_session, tab_id, image_path=None)` accepts the exact canonical UTF-8 JSON payload bound by the existing reservation. Its keys are `account`, `kind: publish`, `target` (verified numeric URL on the explicitly configured BLOG_HOST), exactly four `parts`, `image: {path, sha256, attach_part_index: 0}`, and `preview: {part_index: 1, url: target, required: true}`. First reply must contain that exact URL. Image-path provenance stays in the canonical payload. Any optional alternate image file must have exactly the approved SHA-256.

The immutable manifest binds account, database ID, original action, owner, ledger session, run start, browser instance and tab, payload hash, exact texts, original image hash and the fixed five-operation order. Canonical payload bytes, original image bytes, manifest and every subsequent proof/source are retained in immutable `blobs`; append-only `audit` events contain `proof_hash`. No schema migration is used. Source closure validates directly from database blobs after restoration, without consulting any original file path.

## Exactly five one-use preparation permits

Call `begin_step(ledger, owner, token, action, step_id)` in this order:

1. `open_root_fill`: open composer and fill the exact root text.
2. `upload_original_image`: choose the approved original image file exactly once, on root index 0.
3. `add_fill_reply_1`: add one continuation and fill exact first reply.
4. `add_fill_reply_2`: add one continuation and fill exact second reply.
5. `add_fill_reply_3`: add one continuation and fill exact third reply.

Each call commits a fresh, distinct nonce before returning permission for **exactly one browser-tool invocation** containing only that fixed operation. The permit includes the exact operation, binding, `issued_at`, `expires_at = issued_at + 300`, `browser_invocations: 1`, and `final_submission: false`. The caller must check actual time is within `[issued_at, expires_at)` and match the browser/tab before invoking. Outer lower/upper call-time bounds must fall inside the permit window. Neither batching future steps nor adding Publish, hidden requests or other changing actions is allowed. Returned `may_prepare: true` is not social `may_dispatch`; `external_publication_allowed` is false.

For media, the returned `media_source` is the immutable ledger blob and its exact SHA-256, not the original path. The caller must extract these already-retained bytes into a bounded regular file, hash the extracted file immediately before `filechooser.setFiles`, and use it only for root index 0. A modified original pathname cannot silently replace the media. This is a caller contract, not a filesystem/browser sandbox.

If permit delivery is lost or ambiguous, do not invoke the browser. A durable pending permit blocks all new writes. If a browser result is lost, unknown, failed or not conclusively completed, do not replay. Read-only inspection is allowed while pending; it cannot turn an unknown tool result into successful completion.

## Completion attestations and read-only checks

`complete_step(ledger, owner, token, action, record_path, sha256)` requires a `publisher-draft-step-completion-v1` JSON record with exactly:

- `binding`, `manifest_sha256`, `step_id`, `nonce`, and `operation`, matching the pending permit
- `call`: `reference`, `tool_name: mcp__cua_repl__js`, `started_at`, `completed_at`, `outcome: completed`, `browser_invocations: 1`, `final_submission: not_invoked`, `request_source`, `result_source`, `operator_review_source`, `operator_reviewed_at`, `operation_matches_permit: true`, `other_mutations: none`, `timestamp_basis: observed_outer_bounds`, `timestamp_provenance`
- `readback`, `sources`, and `social_success: false`

`started_at` and `completed_at` are honest outer bounds from clocks captured immediately before invocation and after its terminal result, never invented native timestamps. The retained request/result/operator review must identify one authentic completed browser invocation, exactly matching the permitted operation, without hidden submission or other mutations. Call references and nonces cannot be reused.

For each completion, `readback` has exactly `mode: read_only`, `observed_at`, `reference`, `parts`, `original_image_sha256`, `image_present`, `first_reply_preview`, `dom_source`. It contains the expected exact current prefix of the four texts. The image is absent before upload and present with the original hash thereafter. Once first reply exists, preview must be `{part_index: 1, url: exact_numeric_target, visible: true}`. It is null before that point. Readback follows the completed call; review follows readback. This attestation completes only the nonce, leaving the action reserved.

`sources` maps bounded source IDs to `{media_type, sha256, size, data_base64}`. Actual original source bytes must be embedded, distinct source IDs used for each role, and no unreferenced sources added. Every source is also stored separately in blobs. Sources are bounded to 2 MB each and 4 MB per record. Source hashes establish integrity, not authenticity. The operator must actually review the original browser request/result and observed DOM; these tools do not execute code, analyze screenshots, authenticate a caller, or independently prove that a browser obeyed a permit.

## Final read-only seal and separate Publish

After all five completions, `seal_preparation(ledger, owner, token, action, record_path, sha256)` requires a `publisher-draft-final-inspection-v1` record with exactly `binding`, `manifest_sha256`, `readback`, `sources`, `final_submission: not_invoked`, `social_success: false`.

This fresh final readback is read-only, includes all four exact texts, root original-image SHA-256/presence and the exact visible first-reply numeric URL preview. Beyond normal readback fields it contains `screenshot_source`, `visual_review_source`, `visual_inspected_at`, `visual_matches_exact_payload: true`. Retain distinct actual DOM, PNG/JPEG screenshot and operator visual-inspection sources. The operator must inspect that screenshot against the exact texts, image and preview. The final inspection cannot predate the fifth completed step and must be fresh within 300 seconds, including final precommit and postcommit checks.

The seal is one-time. It never clicks Publish. Every new `publish` action must then use the normal `ledger.begin_write` with its fresh absent preflight. `ensure_publish_prepared` requires exact same owner/action, a fresh sealed preparation and no outstanding draft step. It returns the exact browser/tab/payload/manifest/seal binding and `expires_at = prepared_read_at + 300` for **one separate final Publish call only**. Immediately before that browser invocation, the native caller must check its current clock is at least `checked_at` and strictly before `expires_at`; an expired, lost or ambiguous final permit must never be replayed. `check_prepared_fresh(ledger, returned_binding)` rechecks freshness and non-rollback, updating its `checked_at`; the ledger calls it immediately before intent mutation, before commit and after commit before returning dispatch permission. A failed postcommit check leaves the already-durable final intent pending and returns no permission, without replay.

## Fail-closed unknown handling and integration

`stop_unknown_step(ledger, owner, token, action, nonce, reason)` is the sole pending-step resolution helper. It requires the exact pending nonce, appends an unknown event, puts that same original publish action in `unknown` with no final intent ID, and inserts account STOP. It grants no retry, resumption, cancellation, verification, success or clearing of STOP. There is no automatic recovery path.

The existing, separately authorized pre-execution-denial workflow remains compatible after a sealed draft and its separate final Publish intent. `denial_extension.record_denied` may produce `cancelled` only for its exact retained proof of authorization rejection before tool execution, with no submission or subsequent browser call. This extension revalidates the immutable denial event, exact original action/owner/intent/payload/target, original request/result, no-submission/no-retry flags, and absence of submitted/readback/receipt history directly from blobs. Before explicit finalization, the original STOP and writer remain. After `finalize_denied_run`, exact retained finalization approval and the matching released-run audit/checkpoint sequence are validated too. Historical denial evidence does not expire. Arbitrary cancellation, missing/corrupt proof, or malformed denial/release metadata remains blocked. This compatibility grants no retry or permission to bypass a rejection.

Registration, step-permit and unknown-STOP records use one captured operation timestamp consistently in their audit event. Normal processing across a second boundary is accepted; final checks still reject backwards clocks and expired dispatch permits.

Ledger integration gates must call:

- `ensure_no_preparation_pending` in global `no_pending`; replay validates complete evidence before any dispatch
- `ensure_preparation_action(ledger, action)` before claim/begin-write, preventing unrelated changing work while this publisher draft remains reserved
- `ensure_preparation_transition` before standard transitions; any started preparation forbids cancellation and pending steps forbid ordinary transitions
- `ensure_preparation_verify` before verify; draft reservation cannot become fake already-present, unknown draft STOP cannot be cleared with social verification, and subsequent prepared-publish verification requires exactly four distinct owned receipts
- `ensure_publish_prepared` plus `check_prepared_fresh` in final begin-write as above
- `preparation_records` in status and checkpoint safe-state validation; `preparation_evidence_hashes` in checkpoint evidence closure

Archives must include this module, this document, all referenced blobs, and existing ledger sources. Pure reads do not consume a permit. Historical completed publisher preparations do not block future legitimate runs. No active incomplete draft may be silently dropped, moved to a new key or interleaved with unrelated changing work.

Synthetic fixture constructors and negative tests are in `test_publisher_preparation.py`; no operational database, browser or account is touched by them.

## Source-version compatibility

This portable repository includes source and synthetic fixtures only. It does not
install a browser transport, issue real approval, or deploy the helper. Configuration
comes from the separately reviewed `settings.py`; synthetic defaults never identify
an actual account. Native observations and retained private proof must be supplied
and authenticated through the separately authorized operational workflow.

The runtime safe-state manifest now includes `publisher_preparations` even when
empty. This changes its hash without changing the SQL schema/version. A pending
checkpoint created by older source must be acknowledged with its original bundled
verifier before a separately reviewed source transition. Preserve old immutable
archives and Library version identities; never rewrite their hashes or mix source.
New archives require `publisher_preparation.py`, `PREPARATION.md`, the existing
quarantine/denial dependencies, and `settings.py`. Tests and source publication are
not deployment or resumption approval.
