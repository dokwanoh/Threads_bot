# Checkpoint contract

Successful ledger release increments the checkpoint sequence and sets a pending
gate. The next writer remains blocked until the exact round trip is acknowledged.
Unresolved writers, reservations, intents, submissions, unknown actions, or STOP
prevent packaging. No manual clear or automatic takeover is implemented.

Checkpoint creation is local only. A separately authorized transport must upload to
the pinned runtime Library identity, materialize the exact new version, and verify
the actual returned bytes. Keep the reconstruction baseline identity distinct from
runtime checkpoints. Later versions must link exactly to the prior recorded version.

The JSON acknowledgement binds account, database, baseline, sequence, safe-state
hash, archive hash, Library identity/version chain, downloaded path, transport
reference, and fresh verification time. The verifier checks each archived member,
embedded SQLite schema, action state, evidence, and exact live pre-ACK metadata.
`settings.py` is a required code dependency in this revision's archives.

The archive snapshot retains `checkpoint_pending=1`; the later ACK is bookkeeping.
A lost ACK response requires a separate status read and exact expected-state check.
Never repeat a social action or assume completion based on elapsed time.

The companion queue additionally requires an exact paired checkpoint proof with
queue identity, snapshot hash, Library version chain, registry revision, and result
digest. Pair verification alone does not prove receipt provenance or restorable
queue archive semantics. The repository does not ship a production queue snapshot
transport or restore procedure.

Runtime archives contain operational state and evidence. They are private artifacts
and must never be committed to this source repository.

## Quarantine-aware source version

This revision includes validated quarantine records in the runtime safe-state
manifest and requires `quarantine_extension.py`, `QUARANTINE.md`, and `settings.py`
in new archives. Proof/source closure is embedded, including the independently
reviewed uncertainty approval; those operational bytes must remain private.
Workflow cancellation cannot erase the retained unknown external disposition.

An older pending checkpoint needs its original matching verifier, because adding
an empty quarantine list still changes the manifest hash. A separately reviewed
source transition must follow that ACK and exact version-chain verification.
Restore old immutable archives with their own bundled code first. After a properly
authorized quarantine closure, a new exact-version checkpoint must pass its normal
round trip before an unrelated writer can acquire. No SQL schema/version change,
automatic migration, or direct gate-clear operation is included.

## Preparation-aware evidence closure

New snapshots include validated `publisher_preparations` and all retained payload,
image, draft permit/completion, final visual-inspection, and source blobs. Both
`publisher_preparation.py` and `PREPARATION.md` are required archive members.
Missing evidence or dependencies fails closed; original filesystem paths are not
needed for restored validation. Final-call denial remains subject to the existing
exact pre-execution proof and separately approved finalization contract.

Even an empty preparation list changes the safe-state hash. Preserve old immutable
archives and verify them with their own source version; acknowledge prior pending
checkpoints before a separately reviewed upgrade. This changes no SQL schema.
