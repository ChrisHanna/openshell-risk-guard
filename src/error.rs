// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Shared error types for `openshell-risk-guard`.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, RiskGuardError>;

#[derive(Debug, Error)]
pub enum RiskGuardError {
    #[error("authentication failed: {0}")]
    Unauthenticated(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("conflicting duplicate request_id '{request_id}' in epoch '{epoch_id}'")]
    ConflictingDuplicateRequestId {
        epoch_id: String,
        request_id: String,
    },

    #[error("admission capacity exhausted: {0}")]
    AdmissionExhausted(String),

    #[error("storage failure: {0}")]
    Storage(String),

    #[error("policy validation or containment error: {0}")]
    Policy(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<rusqlite::Error> for RiskGuardError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<serde_json::Error> for RiskGuardError {
    fn from(err: serde_json::Error) -> Self {
        Self::InvalidArgument(err.to_string())
    }
}
