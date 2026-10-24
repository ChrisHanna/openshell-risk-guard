// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! Regression gate on the offline adaptive evaluation (see docs/adaptive-v2.md). It runs the same harness the example does, on a few
//! seeds, with no cluster. The floors are set well below what the current learner scores, so they catch a real regression and not noise;
//! they are not claims about unseen attackers.

use openshell_risk_guard::adaptive_eval::{
    Method, Plan, evaluate, evaluate_summaries, parse_summaries,
};

#[test]
fn the_evaluation_is_deterministic_and_v2_does_not_lose_to_v1_on_the_scripted_fleet() {
    let plan = Plan::standard(vec![101, 102, 103]);
    let v2 = evaluate(&Method::current(), &plan, "warm", plan.train_hours).unwrap();
    let again = evaluate(&Method::current(), &plan, "warm", plan.train_hours).unwrap();
    assert_eq!(
        serde_json::to_string(&v2).unwrap(),
        serde_json::to_string(&again).unwrap()
    );
    let v1 = evaluate(&Method::v1(), &plan, "warm", plan.train_hours).unwrap();
    assert!(v2.overall.benign_events > 3_000);
    // Benign traffic is not blocked, and false alerts stay rare.
    assert_eq!(v2.overall.false_blocks.k, 0);
    assert!(
        v2.overall.false_alerts.point < 0.005,
        "{:?}",
        v2.overall.false_alerts
    );
    // Every injected episode is counted, and v2 catches at least as many as v1 at both lines.
    assert_eq!(v2.overall.alert_overall.n, 12 * 4 * 3);
    assert!(v2.overall.alert_overall.k >= v1.overall.alert_overall.k);
    assert!(v2.overall.block_overall.k >= v1.overall.block_overall.k);
    assert!(
        v2.overall.alert_overall.point > 0.6,
        "{:?}",
        v2.overall.alert_overall
    );
    assert!(v1.overall.false_blocks.k == 0);
}

#[test]
fn real_summaries_are_only_evaluated_for_workloads_with_enough_history() {
    let mut text = String::new();
    // One workload with 200 quiet minutes and one spike, one with 10 minutes, one row nobody can attribute.
    for minute in 0..200 {
        let total = if minute == 190 { 90 } else { 2 + minute % 3 };
        text.push_str(&format!(
            "{{\"ts\":{},\"workload\":\"w-long\",\"total\":{total},\"refused_calls\":0,\"distinct_routes\":2}}\n",
            minute * 60_000
        ));
    }
    for minute in 0..10 {
        text.push_str(&format!(
            "{{\"ts\":{},\"workload\":\"w-short\",\"total\":1,\"refused_calls\":1,\"distinct_routes\":1}}\n",
            minute * 60_000
        ));
    }
    text.push_str("{\"ts\":1,\"workload\":null,\"total\":5}\n");
    let rows = evaluate_summaries(&parse_summaries(&text).unwrap());
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].active_minutes, 200);
    assert_eq!(rows[0].tested, 60);
    assert_eq!(rows[0].false_alerts.n, 60);
    assert_eq!(rows[0].false_alerts.k, 1, "the one spike is the only alert");
    assert!(rows[1].status.starts_with("not evaluated"));
    assert_eq!(rows[1].tested, 0);
}
