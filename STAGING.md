# Staging and promotion checklist

## Implemented and covered by synthetic tests

- Pinned distinct role worker/browser/tab bindings and fresh observations
- Immutable payloads, same-role slot boundaries, duplicate schedule delivery gates
- One queue owner and one ledger writer for a prepared batch
- Complete command-result parsing and exact ledger/authorization binding
- One-use mutation permits, deadline checks, lost-response and denial blocking
- Immutable audit and evidence, no implicit database creation or owner takeover
- Paired archive identity/hash/version checks before queue completion

## Required before any production claim

1. Review the final deployed source hashes and configuration. This public packaging
   revision changes portable paths and adds `settings.py`; earlier source pins must
   not be reused silently. State schemas and action-key semantics remain unchanged.
2. Resolve any live STOP only through its separate exact-evidence approval workflow.
3. Observe real worker, browser-instance, tab, and logged-in account identities.
4. Validate each actual schedule/time zone. The staged fixed-interval model cannot
   silently substitute for active-hours or irregular scheduling.
5. Implement independently reviewed browser, ledger, authorization, and tool-result
   adapters. Defaults must stay unavailable until an explicit integration selection.
   Keep tokens out of shell arguments/logs and use the supported browser route.
6. Implement a consistent token-free companion snapshot, exact Library round trip,
   paired restore review, and orphaned-writer/crash reconciliation.
7. Verify a no-social-write end-to-end rehearsal and exact checkpoint round trip.
8. Obtain deployment authorization and quiesce old writers before promotion.

Publication is source control only. It does not change automation schedules, create
live role separation, prove browser/profile isolation, clear STOP, or deploy adapters.
