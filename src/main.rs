// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Unified `openshell-risk-guard` server and CLI binary (Wave 3 - `t09-server-cli-bin`).

use clap::Parser;
use openshell_risk_guard::cli::{Cli, execute_cli};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();

    let cli = Cli::parse();
    match execute_cli(cli).await {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}

