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
