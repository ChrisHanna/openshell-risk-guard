// SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
// SPDX-License-Identifier: Apache-2.0

//! The `siem_context` rule: what OpenSearch-derived features add to a score. Pure: the features arrive in the detector's context, already
//! fresh and bounded, and the answer depends on nothing else. It can only add points, never remove them. See docs/design-siem-features.md.
//!
//! | Rule | Adds | Condition |
//! |---|---|---|
//! | R1 probing the policy | +4, or +8 | the sandbox's `openshell_denials_5m` is 3 or more, or 10 or more |
//! | R2 unlike the fleet | +3 | the workload's `refusal_ratio_15m_permille` is 300 or more while the fleet's is 100 or less |
//! | R3 unusual routes | +3 | `new_routes_1h` is 3 or more and `routes_unique_to_workload_permille` is 500 or more |
//! | R4 a campaign | +4 | `fleet_workloads_with_denials_5m` is 3 or more and this sandbox has at least one denial |
//!
//! The total is capped at the profile's maximum (default 15, never more than 30). A feature that is missing adds nothing.

use crate::types::{
    ContextFeatures, FeatureScope, SIEM_CONTEXT_DEFAULT_MAX_POINTS, SIEM_CONTEXT_HARD_CAP_POINTS,
};

pub const OPENSHELL_DENIALS_5M: &str = "openshell_denials_5m";
pub const OPENSHELL_DENIALS_1H: &str = "openshell_denials_1h";
pub const OPENSHELL_WOULD_BLOCK_5M: &str = "openshell_would_block_5m";
pub const REFUSAL_RATIO_15M_PERMILLE: &str = "refusal_ratio_15m_permille";
pub const NEW_ROUTES_1H: &str = "new_routes_1h";
pub const ROUTES_UNIQUE_PERMILLE: &str = "routes_unique_to_workload_permille";
pub const FLEET_OPENSHELL_DENIALS_5M: &str = "fleet_openshell_denials_5m";
pub const FLEET_WORKLOADS_WITH_DENIALS_5M: &str = "fleet_workloads_with_denials_5m";
pub const FLEET_REFUSAL_RATIO_15M_PERMILLE: &str = "fleet_refusal_ratio_15m_permille";
pub const FLEET_ACTIVE_WORKLOADS_15M: &str = "fleet_active_workloads_15m";

/// How a feature's value is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    /// An integer count, 0 to 100,000.
    Count,
    /// A ratio times 1,000, 0 to 1,000.
    Permille,
}

impl Range {
    #[must_use]
    pub const fn max(self) -> u32 {
        match self {
            Self::Count => 100_000,
            Self::Permille => 1_000,
        }
    }
}

/// The whole vocabulary: name, the scope it is published for (`sandbox` covers `sandbox` and `spiffe` subjects), and its range. Anything else is refused.
pub const VOCABULARY: [(&str, FeatureScope, Range); 10] = [
    (OPENSHELL_DENIALS_5M, FeatureScope::Sandbox, Range::Count),
    (OPENSHELL_DENIALS_1H, FeatureScope::Sandbox, Range::Count),
    (
        OPENSHELL_WOULD_BLOCK_5M,
        FeatureScope::Sandbox,
        Range::Count,
    ),
    (
        REFUSAL_RATIO_15M_PERMILLE,
        FeatureScope::Workload,
        Range::Permille,
    ),
    (NEW_ROUTES_1H, FeatureScope::Workload, Range::Count),
    (
        ROUTES_UNIQUE_PERMILLE,
        FeatureScope::Workload,
        Range::Permille,
    ),
    (
        FLEET_OPENSHELL_DENIALS_5M,
        FeatureScope::Fleet,
        Range::Count,
    ),
    (
        FLEET_WORKLOADS_WITH_DENIALS_5M,
        FeatureScope::Fleet,
        Range::Count,
    ),
    (
        FLEET_REFUSAL_RATIO_15M_PERMILLE,
        FeatureScope::Fleet,
        Range::Permille,
    ),
    (
        FLEET_ACTIVE_WORKLOADS_15M,
        FeatureScope::Fleet,
        Range::Count,
    ),
];

/// The scope and range a feature name is allowed for, or `None` when the name is not in the vocabulary.
#[must_use]
pub fn lookup(name: &str) -> Option<(FeatureScope, Range)> {
    VOCABULARY
        .iter()
        .find(|(known, _, _)| *known == name)
        .map(|(_, scope, range)| (*scope, *range))
}

/// One rule that fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: &'static str,
    pub points: u32,
    pub detail: String,
}

/// What the features add to a score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjustment {
    /// The points after the cap.
    pub points: u32,
    /// The points before the cap.
    pub uncapped: u32,
    /// The cap in force.
    pub max: u32,
    pub hits: Vec<Hit>,
}

/// The cap a profile asks for, held to the hard cap.
#[must_use]
pub fn effective_max(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(SIEM_CONTEXT_DEFAULT_MAX_POINTS)
        .min(SIEM_CONTEXT_HARD_CAP_POINTS)
}

/// Run R1 to R4 over `features`. `None` when nothing fires (so a decision with no useful features is exactly what it would be without them).
#[must_use]
pub fn adjustment(features: &ContextFeatures, requested_max: Option<u32>) -> Option<Adjustment> {
    let get = |scope, name| features.get(scope, name);
    let denials = get(FeatureScope::Sandbox, OPENSHELL_DENIALS_5M);
    let mut hits = Vec::new();

    if let Some(n) = denials {
        let points = if n >= 10 {
            8
        } else if n >= 3 {
            4
        } else {
            0
        };
        if points > 0 {
            hits.push(Hit {
                rule: "R1",
                points,
                detail: format!("{OPENSHELL_DENIALS_5M}={n}"),
            });
        }
    }
    if let (Some(own), Some(fleet)) = (
        get(FeatureScope::Workload, REFUSAL_RATIO_15M_PERMILLE),
        get(FeatureScope::Fleet, FLEET_REFUSAL_RATIO_15M_PERMILLE),
    ) && own >= 300
        && fleet <= 100
    {
        hits.push(Hit {
            rule: "R2",
            points: 3,
            detail: format!(
                "{REFUSAL_RATIO_15M_PERMILLE}={own}, {FLEET_REFUSAL_RATIO_15M_PERMILLE}={fleet}"
            ),
        });
    }
    if let (Some(new), Some(unique)) = (
        get(FeatureScope::Workload, NEW_ROUTES_1H),
        get(FeatureScope::Workload, ROUTES_UNIQUE_PERMILLE),
    ) && new >= 3
        && unique >= 500
    {
        hits.push(Hit {
            rule: "R3",
            points: 3,
            detail: format!("{NEW_ROUTES_1H}={new}, {ROUTES_UNIQUE_PERMILLE}={unique}"),
        });
    }
    if let (Some(campaign), Some(own)) = (
        get(FeatureScope::Fleet, FLEET_WORKLOADS_WITH_DENIALS_5M),
        denials,
    ) && campaign >= 3
        && own >= 1
    {
        hits.push(Hit {
            rule: "R4",
            points: 4,
            detail: format!(
                "{FLEET_WORKLOADS_WITH_DENIALS_5M}={campaign}, {OPENSHELL_DENIALS_5M}={own}"
            ),
        });
    }

    if hits.is_empty() {
        return None;
    }
    let uncapped: u32 = hits.iter().map(|h| h.points).sum();
    let max = effective_max(requested_max);
    Some(Adjustment {
        points: uncapped.min(max),
        uncapped,
        max,
        hits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ContextFeature;

    fn feature(scope: FeatureScope, name: &str, value: u32) -> ContextFeature {
        ContextFeature {
            scope,
            name: name.to_string(),
            value,
            subject: "x".into(),
            age_ms: 0,
        }
    }

    #[test]
    fn empty_features_add_nothing_and_the_cap_is_held_to_thirty() {
        assert!(adjustment(&ContextFeatures::default(), Some(30)).is_none());
        assert_eq!(effective_max(None), 15);
        assert_eq!(effective_max(Some(99)), 30);
        assert_eq!(effective_max(Some(0)), 0);
    }

    #[test]
    fn every_rule_fires_and_the_default_cap_trims_the_sum() {
        let features = ContextFeatures::new([
            feature(FeatureScope::Sandbox, OPENSHELL_DENIALS_5M, 12),
            feature(FeatureScope::Workload, REFUSAL_RATIO_15M_PERMILLE, 400),
            feature(FeatureScope::Fleet, FLEET_REFUSAL_RATIO_15M_PERMILLE, 50),
            feature(FeatureScope::Workload, NEW_ROUTES_1H, 5),
            feature(FeatureScope::Workload, ROUTES_UNIQUE_PERMILLE, 800),
            feature(FeatureScope::Fleet, FLEET_WORKLOADS_WITH_DENIALS_5M, 4),
        ]);
        let adjustment = adjustment(&features, None).unwrap();
        assert_eq!(adjustment.uncapped, 18);
        assert_eq!(adjustment.points, 15);
        assert_eq!(adjustment.hits.len(), 4);
    }
}
