# Uncertain-attempt quarantine contract

This repository contains the portable, reviewed source and synthetic tests for a narrowly scoped recovery helper. Source publication does not perform live finalization, invoke a browser, authorize a social change, or upload operational evidence. The helper accepts an unresolved outcome only under the specific independent approval and evidence boundaries below; it never proves absence.

## Honest outcome

The workflow row becomes `cancelled` solely to terminate the attempt. The immutable incident bundle, three new action audit events, writer-release audit, result, quarantine record, status, and checkpoint manifest must retain this disposition:

- `external_outcome: unknown`
- `termination: operator_accepted_uncertainty`
- `new_verified_count: 0`
- `retry_allowed: false`

The mandatory subtype is `operator_closed_uncertain_target_quarantined_v1`. No new verified observation or receipt is inserted. The current partial readbacks must never be classified absent. The original pre-intent absence evidence remains unchanged as historical evidence; it does not prove the later outcome.

## Authorization and trust boundary

Execution requires a new, specific user approval accepting the unresolved external outcome, permanently excluding the entire canonical post from all automated post-write kinds, and releasing the account-wide stop only subject to a verified checkpoint before other-post work. Prior no-execution approval, role approval, repository/upload approval, generic continuation, and authorization for the original repost do not authorize this disposition.

The narrow approval decision string is `accept_unknown_quarantine_post_release_writer_require_checkpoint_no_retry`. Its independent review must also bind `accepted_external_outcome: unknown`, `quarantine_scope: entire_canonical_post_all_post_write_kinds`, `resume_scope: other_posts_after_verified_checkpoint`, zero verified count, no retry, and no new social dispatch authorization.

`TrustedReviewPin` and `load_trusted_review(path, sha256)` provide an explicit operator trust boundary. The caller must independently review authentic conversation and tool sources and obtain the pin file and its SHA-256 out of band. Hashes, valid JSON, matching copied prose, a decision string, or a boolean do not authenticate the reviewer or the user. There is no automatic semantic authentication of approval text. A trusted reviewer must reject an old or unrelated question even if somebody can rehash and relabel it.

The pin binds the exact incident/approval bytes; distinct pending-question and affirmative-answer references and bytes; surrounding approval context; failed request/result/context; retained operator attestation; each limited readback source; reviewer; review context; and review time. The synthetic fixture intentionally produces synthetic pins; it does not supply a real approval.

## Supported incident and retained evidence

This helper supports only `legacy-current-ui-uncertainty-incident-v2`, protocol `legacy_current_ui_single_call_v1`: one authentic completed original `mcp__cua_repl__js` request that opened the menu, reached the exact `Unexpected repost menu; no repost selected` guard before final submit, and ended with that exception. The independent operator must verify that the guard's final-submit branch was not invoked and that no pending, outstanding, or later changing call exists. Both request and result retain the exact guard text. The tool-call ID is retained if available; otherwise an explicit missing-ID explanation is mandatory.

It does not support future native-v4 incidents. Such incidents need a separately reviewed extension retaining the complete private witness, native request, attempt/result, review sources, and closure. The protocol gate rejects them. Relabeling a native-v4 incident as legacy is not permissible operator review.

The incident contains two distinct, refreshed, read-only observations: target UI and limited account repost state. Both must remain `classification: unknown`, `coverage: partial`, with explicit limitations. The account and exact target must match the original incident; the two readback browser-instance and tab fields must both match the explicit replacement reconciliation provenance below. A virtualized/nonexhausted timeline and an aggregate count cannot become absence proof.

Exact request/result, operator attestation, limited read bytes, question, answer, and approval context are bounded embedded base64 sources with exact size/hash checks. Bundles reject undeclared/unreferenced sources and duplicate JSON keys. Incident, canonical incident bundle, approval, canonical approval bundle, and retained independent pin are saved as immutable blobs. Existing `source_sha256`/`proof_sha256` edges close the checkpoint evidence graph; no external source path is needed after finalization. Original intent, preflight record and raw proof, reservation/unknown audits, and STOP contents remain retained.

## Transaction

`finalize_uncertain_quarantine(ledger, owner, token, action, incident_path, incident_sha256, approval_path, approval_sha256, *, trusted_review)` checks:

1. Active original account/database, exact owner/token/session/run, exact repost action/canonical target/payload/intent/times, exact STOP identity, and expected checkpoint sequence.
2. Exactly the original reservation, one committed intent, and one unknown event; no submitted/readback/receipt or later attempt.
3. No other reserved/pending action or unreleased run, and no newly verified action anywhere in this run.
4. Fresh limited observations and operator/approval reviews, a monotonic checked clock, and review freshness after lock acquisition and at final pre-COMMIT boundary.

One `BEGIN IMMEDIATE` transaction saves proof, appends `target_quarantined_unresolved`, changes only the original action to workflow-cancelled, appends the mandatory subtype and approval, removes only the exact STOP/writer, releases the exact run, increments checkpoint sequence once, and marks checkpoint pending. It validates the completed quarantine graph before COMMIT. A crash before commit leaves the original unknown+STOP+writer; a crash after commit leaves terminal-uncertain+quarantine+pending checkpoint. Replay cannot increment the sequence or create another intent. The result never grants dispatch.

## Permanent target gate

`quarantine_records(db, account)` validates immutable audit, embedded proof/source closure, original preflight/history, disposition, account/action/target bindings, and original run/release/checkpoint relationships. Missing/corrupt subtype or proof fails closed. Old evidence is integrity-checked without expiring the permanent exclusion. Legitimate existing `denied_before_dispatch_recorded` cancelled intents remain recognized through their separate immutable denial subtype/proof, without becoming quarantines. A plain cancelled committed intent cannot hide missing quarantine metadata.

Records expose action ID, canonical target key, original target URL, proof hash, subtype, and the full unknown disposition.

`ensure_not_quarantined(ledger, kind, target)` rejects `repost`, `like`, `reply`, and `self_reply` for the canonical post ID across Threads domains, optional `www`, different handle spellings, and trailing slash aliases. It runs before claim reservation and write intent; global acquisition/status/checkpoint validation also fails closed if quarantine integrity is missing. A claim rejection creates no new reservation or social intent.

Preparation must exclude the entire quarantined candidate, including a conditional follow derived from that candidate. The ledger's independent profile-follow target and unrelated posts are not silently banned. No unquarantine, reset, retry flag, expiry, schema migration, or quota/role expansion is included. An independently prepared unrelated authorized batch may acquire only after the ordinary checkpoint ACK.


## v3 narrow replacement-tab and timestamp provenance

This revision supports only the reviewed replacement-tab path. The helper API and unknown-outcome semantics are unchanged from its earlier staging revision. The incident schema is `legacy-current-ui-uncertainty-incident-v2` and its retained bundle schema is `retained-uncertain-quarantine-sources-v2`.

The original `binding.tab_id` and original request/result/attestation bytes are retained. They must not be rewritten to the reconciliation tab. `binding.browser_session` is a legacy field name: v3 uses an explicitly labelled observed CUA browser instance such as the synthetic label `browser-instance:1`, not an unavailable native browser-session ID. The actual ledger session remains `binding.session`.

The required `bundle.reconciliation` object has exactly these fields:

- `schema: replacement-tab-readback-provenance-v1`
- `original_browser_session`, `original_tab_id`: match original incident binding
- `browser_session`: the same observed browser instance
- `tab_id`: distinct actual current replacement tab used by both limited readbacks
- `browser_identity_basis: observed_cua_browser_instance_not_native_session`
- `account`, `ledger_session`, `target`: match original binding account, session, and exact target URL
- `classification: original_tab_unavailable_replacement_read_only`
- `original_tab_state: not_listed_after_cleanup`
- `original_tab_unavailable_reason`: honest nonempty provenance explaining the old tab was unavailable; no assertion of an explicit close call unless separately observed
- `replacement_tab_state: current`
- `mode: read_only`
- `operator_source`: the distinct, retained current operator-provenance source ID

The independently reviewed current operator source must confirm the original call is terminal, there are no outstanding or subsequent changing calls, original tab unavailability, and actual current replacement tab/account/ledger-session/target identity. The original operator attestation remains a separate unchanged source. New required `TrustedReviewPin.reconciliation_provenance_sha256` binds the current source bytes independently; `operator_attestation_sha256` still binds the original source. Both sources are embedded in the existing proof/source closure. These fields and hashes do not authenticate themselves; authentic source review remains mandatory.

`failed_call.timestamp_basis` must be `observed_outer_bounds`; `timestamp_provenance` must honestly describe the observed reminders/result boundaries. In this subtype the legacy names `request_started_at` and `completed_at` mean a conservative observed lower bound before the request and upper bound after its terminal result. They are not exact native start/completion timestamps. The original order remains `intent_at <= lower_bound <= upper_bound <= unknown_audit_at`; invalid/reversed bounds or an asserted exact-native basis are rejected. The pinned current operator source retains this provenance. No unavailable precision is invented.

Both observations must use the exact replacement tab and browser instance. They remain partial/unknown. Missing provenance/current attestation, mismatched original/current browser or tabs, account/ledger-session/target mismatches, relabeling the original tab, mutating-call flags, wrong time basis, and invalid timestamp boundaries fail closed. None of these changes supplies an absence proof or authorizes live finalization.

## Synthetic validation

`python -m unittest discover -q` runs the staging-only helper, CLI/checkpoint, and archive-closure tests, including replacement-provenance regressions. They cover exact approval/pin/binding gates; native-v4 and multi-call rejection; partial/unknown evidence semantics; wrong/old approval decisions; source changes; other pending work; zero verified derivation; expiry/rollback/lock-wait behavior; process death before/after commit; storage/audit failure rollback; replay; source-deletion restore; missing/corrupt metadata; all cross-kind domain/handle aliases; profile/unrelated-target scope; and an existing normal denial through actual local checkpoint ACK followed by uncertainty closure, second local ACK, and unrelated-target claim. “Actual ACK” here invokes the real checkpoint acknowledgement function with a local synthetic receipt; there is no Library transfer.

CLI/checkpoint/plumbing tests and independent review are additional gates. Passing these tests does not authorize live recovery or prove an external post outcome.


## Source-version compatibility and deployment precondition

This extension adds a quarantine list to the runtime safe-state manifest and
requires the quarantine helper/document in newly produced restoration archives.
It cannot acknowledge an older pending checkpoint produced by the previous
source version: even an empty quarantine list changes the safe-state hash.
Deploy only after all earlier checkpoints are already acknowledged and the
matching source versions and stored Library version chain are verified. The
current uncertainty incident must then finalize and produce a new checkpoint
with this exact source set before unrelated writes resume.

Keep every old immutable baseline/checkpoint and its bundled code intact. Restore
an old archive using its own reviewed bundled ledger/checkpoint/verifier first,
not by mixing these new files into that archive. Any later source transition is
an independently reviewed deployment; never reinitialize the existing database,
rewrite old hashes, substitute Library identities, or bypass missing members.
The SQL schema/version remains unchanged. New recovery archives must include
`quarantine_extension.py`, `QUARANTINE.md`, and the portable `settings.py` as explicit required dependencies. Deployment-specific configuration must be supplied and reviewed separately; no operational configuration or approval producer is bundled.
