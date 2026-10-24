// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Run the offline adaptive-learner evaluation and print it as Markdown.
//!
//!     cargo run --release --example adaptive_eval -- --suite headline --seeds 101-110
//!     cargo run --release --example adaptive_eval -- --suite ablation --seeds 1-6 --json out.json
//!     cargo run --release --example adaptive_eval -- --suite real --real data/real/summaries.jsonl
//!
//! Suites: `headline` (v1 against v2, warm start, closed and open world), `cold` (few training hours, with and without a pooled
//! prior), `ablation` (v2 with one component off at a time), `context` (synthetic SIEM context), `real` (exported activity
//! summaries), `all`. No cluster is touched. Seeds `a-b` is a range, `a,b,c` a list.

use openshell_risk_guard::adaptive::FitOptions;
use openshell_risk_guard::adaptive_eval::{
    ContextMode, Method, Plan, PriorMode, Report, evaluate, evaluate_summaries, parse_summaries,
};

fn main() {
    let mut seeds = (101..=110).collect::<Vec<u64>>();
    let mut suite = "headline".to_string();
    let mut real = None;
    let mut json = None;
    let mut open_world = 10u32;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().unwrap_or_default();
        match flag.as_str() {
            "--seeds" => {
                seeds = match value.split_once('-') {
                    Some((a, b)) => (a.parse().unwrap()..=b.parse().unwrap()).collect(),
                    None => value.split(',').map(|s| s.parse().unwrap()).collect(),
                }
            }
            "--suite" => suite = value,
            "--real" => real = Some(value),
            "--json" => json = Some(value),
            "--open-world" => open_world = value.parse().unwrap(),
            other => panic!("unknown flag {other}"),
        }
    }
    let wants = |name: &str| suite == name || suite == "all";
    let closed = Plan::standard(seeds.clone());
    let mut open = Plan::standard(seeds.clone());
    open.novelty_permille = open_world;
    let open_label =
        format!("open world ({open_world} in 1000 benign calls touch a never-seen resource)");
    let mut reports: Vec<Report> = Vec::new();
    let mut run = |method: &Method, plan: &Plan, label: &str, hours: i64| {
        eprintln!("running {} / {label}", method.name);
        let report = evaluate(method, plan, label, hours).unwrap();
        println!("{}", report.markdown());
        reports.push(report);
    };
    let v2_all = Method::current();
    if wants("headline") {
        for method in [Method::v1(), v2_all.clone()] {
            run(
                &method,
                &closed,
                "closed world, 40 training hours",
                closed.train_hours,
            );
            run(
                &method,
                &open,
                &format!("{open_label}, 40 training hours"),
                open.train_hours,
            );
        }
    }
    if wants("cold") {
        for hours in [2, 4, 8] {
            for method in [
                Method::v1(),
                v2_all.clone(),
                Method::v2(
                    "v2 + task-profile prior",
                    FitOptions::default(),
                    PriorMode::TaskProfile,
                ),
                Method::v2("v2 + fleet prior", FitOptions::default(), PriorMode::Fleet),
            ] {
                run(
                    &method,
                    &closed,
                    &format!("closed world, {hours} training hours"),
                    hours,
                );
                run(
                    &method,
                    &open,
                    &format!("{open_label}, {hours} training hours"),
                    hours,
                );
            }
        }
    }
    if wants("ablation") {
        let off = |name: &str, tweak: fn(&mut FitOptions)| {
            let mut options = FitOptions::default();
            tweak(&mut options);
            Method::v2(name, options, PriorMode::None)
        };
        for method in [
            v2_all.clone(),
            off("v2 without method mix", |o| o.method_mix = false),
            off("v2 without shape features", |o| o.shape = false),
            off("v2 without novelty", |o| o.novelty = false),
        ] {
            run(
                &method,
                &closed,
                "closed world, 40 training hours",
                closed.train_hours,
            );
            run(
                &method,
                &open,
                &format!("{open_label}, 40 training hours"),
                open.train_hours,
            );
        }
    }
    if wants("context") {
        for mode in [
            ContextMode::Off,
            ContextMode::Noise,
            ContextMode::Correlated,
        ] {
            let mut plan = open.clone();
            plan.context = mode;
            run(
                &v2_all,
                &plan,
                &format!("{open_label}, synthetic context {mode:?}"),
                plan.train_hours,
            );
        }
    }
    let real_rows = if wants("real") {
        real.map(|path| {
            let text = std::fs::read_to_string(&path).expect("read --real file");
            evaluate_summaries(&parse_summaries(&text).unwrap())
        })
    } else {
        None
    };
    match &real_rows {
        Some(rows) => {
            println!("**Real activity summaries** (rate and fan-out limits only)\n");
            println!(
                "| workload | active minutes | status | quiet test minutes alerted | refusal minutes alerted (unlabelled) |\n|---|---|---|---|---|"
            );
            for row in rows {
                println!(
                    "| {} | {} | {} | {}/{} | {}/{} |",
                    row.label,
                    row.active_minutes,
                    row.status,
                    row.false_alerts.k,
                    row.false_alerts.n,
                    row.refusal_minutes_alerted,
                    row.refusal_minutes
                );
            }
        }
        None if wants("real") => println!("Real activity summaries: none supplied (--real)."),
        None => {}
    }
    if let Some(path) = json {
        let value = serde_json::json!({"synthetic": reports, "real": real_rows});
        std::fs::write(path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
    }
}
