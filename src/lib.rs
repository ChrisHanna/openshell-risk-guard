// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-risk-guard`: Behavioral risk-based conditional access and
//! monotonic policy guard for OpenShell sandboxes.

pub mod adaptive;
pub mod adaptive_controls;
pub mod auth;
pub mod cli;
pub mod dashboard;
pub mod detector;
pub mod entra_auth;
pub mod error;
pub mod fixture;
pub mod guardrails;
pub mod hardening;
pub mod interceptor_service;
pub mod middleware_service;
pub mod normalizer;
pub mod sidecar;
pub mod operator_dashboard;
mod operator_controls;
pub mod store;
pub mod types;
pub mod workload_identity;

pub use error::{Result, RiskGuardError};
pub use types::*;
