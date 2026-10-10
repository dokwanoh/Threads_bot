# Recovery contract

This source is a local coordination prototype. It neither restores production state
automatically nor initiates browser/network actions. Missing or changed storage must
stop processing; never create a replacement empty database to satisfy a guard.

`Ledger.init_recovery` explicitly creates a new inactive candidate only. It refuses
existing paths, symlinked directories, the name `live.sqlite`, and all paths inside
the configured protected production root. Initializing an unrelated candidate does
not establish that an original ledger was recovered.

Recovery observations must be explicit, hash-bound public evidence. Sealing requires
an exact reviewed manifest and identified gaps. Activation requires the actual
downloaded sealed archive, exact account/database/baseline binding, a verified
round-trip receipt, no writer or STOP, and no unresolved action. File hashes prove
byte integrity; a trusted operator must establish evidence and receipt provenance.

The backup builder copies a fixed allowlist of ledger source, documentation, and
synthetic tests. It never walks arbitrary workspace directories. `settings.py` is
required in archives from this revision. The actual environment configuration is
not archived; pin it separately without exposing secrets. Older packages lacking
this dependency require an explicit compatibility review, not automatic acceptance.

A consistent SQLite backup is packaged in DELETE journal mode. A separately
authorized restore must first validate the package, reconcile subsequent actions,
and deliberately enable WAL on a new working copy. Do not copy an open WAL-mode
database without its consistent backup procedure.

The denial extension has an additional trust boundary: an operator must authenticate
the original pre-execution rejection, correlate the exact request/result with the
sole intent, and obtain separate approval for the exact bookkeeping closure. Generic
errors, timeouts, missing readback, and post-dispatch failures remain unknown. The
extension grants no retry or new external action. Queue ownership is not cleared by
ledger-only denial closure.

Source updates, valid archives, and successful synthetic tests do not authorize
deployment, activation, STOP clearance, or resumption of social actions.

## Uncertain-attempt quarantine

The separate [quarantine contract](QUARANTINE.md) permits a narrowly reviewed
legacy UI attempt to become workflow-terminal while its external outcome remains
unknown. It requires exact, independently authenticated approval accepting that
uncertainty. The canonical post remains permanently blocked across repost, like,
reply, and self-reply aliases; verified count stays zero and retries remain forbidden.
This does not extend ordinary denial closure or infer permission from a repository
upload, role grant, or earlier unrelated approval.

New baseline archives require `quarantine_extension.py` and `QUARANTINE.md` alongside
`settings.py`. Keep old archives and their reviewed bundled verifiers intact.
An older pending checkpoint must be acknowledged using its matching code before
any separately reviewed source transition; the new quarantine-list manifest field
changes safe-state hashes even for an empty list. Never rewrite old archive hashes,
replace Library identities, reinitialize a ledger, or silently mix source versions.

## Publisher preparation dependencies

Every new publication now needs the exact bounded preparation contract in
[PREPARATION.md](PREPARATION.md): five ordered one-use draft permits, retained
original media and readbacks, and a separate fresh final visual seal before the
ordinary final publish intent. Unknown draft work blocks the account; source
publication does not authorize a permit or any actual browser operation.

New baseline archives require `publisher_preparation.py` and `PREPARATION.md` in
addition to the existing portable dependencies. The runtime manifest now includes
`publisher_preparations`. An older pending checkpoint still requires its original
bundled verifier and prior ACK before any reviewed source transition.
