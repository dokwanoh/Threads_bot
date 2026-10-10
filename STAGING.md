# Staging and promotion checklist

## Implemented and covered by synthetic tests

- Pinned distinct role worker/browser/tab bindings and fresh observations
- Immutable payloads, same-role slot boundaries, duplicate schedule delivery gates
- One queue owner and one ledger writer for a prepared batch
- Complete command-result parsing and exact ledger/authorization binding
- One-use mutation permits, deadline checks, lost-response and denial blocking
- Immutable audit and evidence, no implicit database creation or owner takeover
- Paired archive identity/hash/version checks before queue completion
- Restricted source-pinned staging ledger adapters and offline queue snapshots
- Exact role/action grants with final-boundary expiry and clock-rollback checks
- Self-contained four-part publisher proof with retained image/observation bytes
- Goal-aware repost planning and observe-only native handoff contracts

## Required before any production claim

1. Review the final deployed source hashes and configuration. This public packaging
   revision changes portable paths and adds `settings.py`; earlier source pins must
   not be reused silently. State schemas and action-key semantics remain unchanged.
2. Resolve any live STOP only through its separate exact-evidence approval workflow.
3. Observe real worker, browser-instance, tab, and logged-in account identities.
4. Validate each actual schedule/time zone. The staged fixed-interval model cannot
   silently substitute for active-hours or irregular scheduling.
5. Implement and review the actual native mutation handler, production ledger
   selection, durable authorization/replay service, and supported browser evidence
   collection. Staging adapters and synthetic mutation contracts grant no permission.
   Keep tokens out of shell arguments/logs and use the supported browser route.
6. Validate the staged companion snapshot through an actual exact Library round
   trip and paired restore, plus orphaned-writer/crash reconciliation.
7. Verify a no-social-write end-to-end rehearsal and exact checkpoint round trip.
8. Obtain deployment authorization and quiesce old writers before promotion.

Publication is source control only. It does not change automation schedules, create
live role separation, prove browser/profile isolation, clear STOP, or deploy adapters.
