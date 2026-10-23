# Recovery: probes, shutdown, backup and restore

## Probes (three jobs, not one)

| Probe | Question | How | Effect of failing |
|---|---|---|---|
| startup | Is it still starting? | `health-check` (readiness), every 5 s, up to 150 s | Holds off the other two; a slow start or a crash recovery is not mistaken for a failure |
| readiness | Can this process give a valid decision? | `health-check`: the decision store answers **through the read connection** | Removed from service; the gateway fails closed. Never restarts the pod |
| liveness | Is the process answering? | `health-check --service=liveness`: the process alone, **no database access** | Restart after six misses at 20 s (two minutes of not answering at all) |

Why it was changed: the old probes checked the database through the single writer connection. A long write, or a slow disk under it, would queue the probe behind the write, miss its deadline,
and get the pod killed, which would then replay recovery under load. Now a busy writer can make the pod unready, never dead. Tests: `readiness_does_not_wait_for_the_writer` (the probe answers
while the writer is held), and `tls_plus_gateway_jwt_is_required_on_every_supervisor_call` (the `liveness` service answers, an unknown name is refused).

**Shutdown.** On SIGTERM the gRPC server stops accepting and drains requests in flight (the listener's graceful shutdown), within the pod's 8 s grace period. Anything that arrives after is refused
at the connection, which the gateway's fail-closed binding turns into a denial: there is no path where termination allows a call that would have been refused. **Not measured under load:**
termination during sustained traffic has not been tested; the claim rests on the fail-closed behaviour measured in `conformance/failure-containment.json`, not on a termination run.

## Backup and restore

* `openshell-risk-guard backup --db … --out …`: a consistent snapshot through a separate read-only connection (`VACUUM INTO`), **while Risk Guard keeps deciding**. It runs `PRAGMA integrity_check` on the
  copy, counts the tables that matter, and writes a SHA-256 file beside it. A backup is never overwritten.
* `backup-verify --file …`: re-checks a backup against its checksum and integrity, touching no database.
* `restore --from … --db … [--force]`: refuses a backup that fails verification or has no checksum, refuses to replace a database without `--force`, keeps what it replaces as `<db>.before-restore`
  (a verified snapshot), removes the old write-ahead log, swaps the file in atomically, and opens it once so any newer migration is applied.
* On AKS: `scripts/aks/26-backup-risk-guard.ps1 -Backup | -DiskSnapshot | -Restore NAME`.

### Measured on the demo cluster (one run, 2026-10-23)

| | Result |
|---|---|
| Database | 78 MB; 15,401 decisions, 1,044 runs, 26 agent restrictions, 70 quarantine audit rows |
| Backup | **2.4 s**, no downtime, integrity `ok`, checksum written and re-verified from disk |
| Restore | **56 s** of Risk Guard being down (scale to zero, restore pod, scale to one, ready) |
| After the restore | Row counts identical to the backup. The workload that was restricted before is **still restricted** (`DELETE /customers/{id}`, tier `strict_epoch`). The demo ran again: routine calls allowed, the destructive call refused, a quarantine held, and 262 of 262 decisions replayed |

Also covered by tests (`tests/backup.rs`): a snapshot taken while the database is open restores a restricted workload and a quarantine, and the restored database refuses the same destructive call
with the carried restriction; a damaged, unchecksummed or existing target is refused; restoring an older snapshot over a newer database loses the newer decisions and keeps the replaced database.

The first run on the cluster failed (the backup directory did not exist on the volume); it now creates its directory, and a test covers it.

### What this does and does not give you

* **RTO (time to recover):** about a minute for this size, restoring from the same volume. It grows with the database.
* **RPO (data lost):** everything decided since the last backup. **Backups are not scheduled**; today they happen when someone runs the script. A schedule is not built.
* **Same volume.** A file backup on the same disk protects against a corrupt database, a bad migration or an operator mistake. It does **not** protect against losing the volume. `-DiskSnapshot` takes an Azure
  snapshot of the managed disk for that; it was **not exercised** in this run, and a restore from it has not been drilled.
* **Restoring an older snapshot is data loss.** A workload restricted after the snapshot is no longer restricted; one whose restriction has since been cleared is restricted again; quarantines,
  signals, policy revisions and decisions after it are gone. The replaced database is kept as `risk-guard.db.before-restore` so the choice can be undone.
* **No disk-capacity alert and no corruption-handling drill yet.** An integrity check runs on every backup and restore; nothing watches free space.
* Stop Risk Guard before restoring (one writer per file). The script does.
