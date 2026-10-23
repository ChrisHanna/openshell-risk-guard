// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Verified backup and restore of the decision database.
//!
//! * **Backup** takes a consistent snapshot of the live database through a separate read-only connection (`VACUUM INTO`), so decisions keep being made while it
//!   runs. It checks the copy (`PRAGMA integrity_check`), counts the tables that matter, and writes a SHA-256 file beside it.
//! * **Verify** re-checks a backup file without touching any database.
//! * **Restore** refuses a backup that fails verification or has no checksum, refuses to overwrite a database unless told to, removes the old database's write-ahead
//!   log (a stale one would be replayed into the restored file), swaps the file in atomically, and opens it once so the schema is brought up to date.
//!
//! Restoring an **older** snapshot is real data loss: decisions, restrictions, quarantines and policy revisions made after it are gone. A workload that was
//! restricted after the snapshot is no longer restricted; one whose restriction has since been cleared is restricted again. Stop Risk Guard before restoring
//! (one writer per file); the database it replaces is kept beside it as `<db>.before-restore`. See docs/recovery.md.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{Result, RiskGuardError};

/// Tables whose row counts are reported, so an operator can see what a backup holds.
const COUNTED: &[&str] = &[
    "epochs",
    "decisions",
    "restrictions",
    "agents",
    "agent_runs",
    "agent_restrictions",
    "agent_guardrail_revisions",
    "workload_quarantine",
    "workload_quarantine_audit",
    "siem_signals",
    "adaptive_models",
];

#[derive(Debug, Clone, Serialize)]
pub struct BackupReport {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub integrity: String,
    pub rows: BTreeMap<String, i64>,
}

fn storage(error: impl std::fmt::Display) -> RiskGuardError {
    RiskGuardError::Storage(error.to_string())
}

fn sidecar(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".sha256");
    PathBuf::from(name)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path).map_err(storage)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(storage)?;
    Ok(hex::encode(hasher.finalize()))
}

fn inspect(path: &Path) -> Result<BackupReport> {
    let conn =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(storage)?;
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(storage)?;
    let mut rows = BTreeMap::new();
    for table in COUNTED {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if exists {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .map_err(storage)?;
            rows.insert((*table).to_string(), count);
        }
    }
    Ok(BackupReport {
        path: path.display().to_string(),
        bytes: std::fs::metadata(path).map_err(storage)?.len(),
        sha256: sha256_file(path)?,
        integrity,
        rows,
    })
}

/// Snapshot `db` into the new file `out` (which must not exist), with a `<out>.sha256` beside it.
pub fn backup(db: &Path, out: &Path) -> Result<BackupReport> {
    if out.exists() || sidecar(out).exists() {
        return Err(RiskGuardError::InvalidArgument(format!(
            "{} already exists; a backup is never overwritten",
            out.display()
        )));
    }
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let partial = {
        let mut name = out.as_os_str().to_os_string();
        name.push(".partial");
        PathBuf::from(name)
    };
    let _ = std::fs::remove_file(&partial);
    {
        let source =
            Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(storage)?;
        source
            .busy_timeout(std::time::Duration::from_secs(30))
            .map_err(storage)?;
        source
            .execute("VACUUM INTO ?1", [partial.to_string_lossy().as_ref()])
            .map_err(storage)?;
    }
    let report = inspect(&partial)?;
    if report.integrity != "ok" {
        let _ = std::fs::remove_file(&partial);
        return Err(RiskGuardError::Storage(format!(
            "the snapshot failed its integrity check: {}",
            report.integrity
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::File::open(&partial)
        .and_then(|file| file.sync_all())
        .map_err(storage)?;
    std::fs::rename(&partial, out).map_err(storage)?;
    let name = out
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let mut line = std::fs::File::create(sidecar(out)).map_err(storage)?;
    writeln!(line, "{}  {name}", report.sha256).map_err(storage)?;
    Ok(BackupReport {
        path: out.display().to_string(),
        ..report
    })
}

/// Check a backup file: it opens, passes the integrity check, and matches its checksum file.
pub fn verify(file: &Path) -> Result<BackupReport> {
    let expected = std::fs::read_to_string(sidecar(file)).map_err(|_| {
        RiskGuardError::InvalidArgument(format!(
            "{} has no checksum file; this is not a backup this tool made",
            file.display()
        ))
    })?;
    let expected = expected
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    let report = inspect(file)?;
    if report.sha256 != expected {
        return Err(RiskGuardError::Storage(
            "the backup does not match its checksum: it was changed or damaged".into(),
        ));
    }
    if report.integrity != "ok" {
        return Err(RiskGuardError::Storage(format!(
            "the backup fails its integrity check: {}",
            report.integrity
        )));
    }
    Ok(report)
}

/// Put a verified backup in place of `db`. Risk Guard must not be running against `db`.
pub fn restore(from: &Path, db: &Path, force: bool) -> Result<BackupReport> {
    verify(from)?;
    if db.exists() && !force {
        return Err(RiskGuardError::InvalidArgument(format!(
            "{} exists; pass --force to replace it (its decisions made since the backup are lost)",
            db.display()
        )));
    }
    // What is being replaced is kept beside it as a verified snapshot, so a restore of the wrong file can be undone. If the old database is too
    // damaged to snapshot, that is no reason to refuse the restore that is meant to replace it.
    if db.exists() {
        let mut name = db.as_os_str().to_os_string();
        name.push(".before-restore");
        let kept = PathBuf::from(name);
        let _ = std::fs::remove_file(&kept);
        let _ = std::fs::remove_file(sidecar(&kept));
        let _ = backup(db, &kept);
    }
    let staged = {
        let mut name = db.as_os_str().to_os_string();
        name.push(".restore-partial");
        PathBuf::from(name)
    };
    std::fs::copy(from, &staged).map_err(storage)?;
    std::fs::File::open(&staged)
        .and_then(|file| file.sync_all())
        .map_err(storage)?;
    // The old database's write-ahead log and shared-memory file belong to it, not to the restored file.
    for suffix in ["-wal", "-shm"] {
        let mut name = db.as_os_str().to_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
    std::fs::rename(&staged, db).map_err(storage)?;
    // Opening applies any migration the snapshot predates and recreates the write-ahead log.
    drop(crate::store::SqliteRiskStore::open(db)?);
    let mut report = inspect(db)?;
    report.path = db.display().to_string();
    Ok(report)
}
