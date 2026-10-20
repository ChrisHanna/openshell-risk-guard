//! Explicit operator inputs for curated, network-only adaptive detection.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningScope {
    LocalDemo,
    Verified,
}

impl LearningScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalDemo => "local_demo",
            Self::Verified => "verified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureReview {
    Finish,
    Approve,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelMode {
    Shadow,
    Enforce,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdaptiveOperation {
    StartCapture {
        run_id: String,
        scope: LearningScope,
        expected_guardrails_revision: u64,
    },
    ReviewCapture {
        session_id: String,
        action: CaptureReview,
        notes: String,
    },
    Train {
        context_id: String,
        scope: LearningScope,
        expected_guardrails_revision: u64,
    },
    SetModel {
        model_id: String,
        mode: ModelMode,
        expected_active_model_id: Option<String>,
        acknowledge_shadow_review: bool,
        /// Clean shadow would-blocks the operator saw; enforce is refused if it changed.
        #[serde(default)]
        reviewed_shadow_would_block: Option<u64>,
    },
    SetAutoLearning {
        enabled: bool,
    },
}

#[derive(Debug)]
pub enum AdaptiveUpdateResult {
    Applied(Value),
    Conflict(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn operation_documents_reject_unknown_fields_and_missing_review() {
        assert!(
            serde_json::from_value::<AdaptiveOperation>(json!({
                "operation":"start_capture","run_id":"run","scope":"local_demo",
                "expected_guardrails_revision":0,"trust_all_history":true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AdaptiveOperation>(json!({
                "operation":"set_model","model_id":"model","mode":"enforce",
                "expected_active_model_id":null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AdaptiveOperation>(json!({
                "operation":"start_capture","run_id":"run","scope":"production",
                "expected_guardrails_revision":0
            }))
            .is_err()
        );
        assert!(matches!(
            serde_json::from_value::<AdaptiveOperation>(json!({
                "operation":"set_auto_learning","enabled":false
            }))
            .unwrap(),
            AdaptiveOperation::SetAutoLearning { enabled: false }
        ));
        assert!(
            serde_json::from_value::<AdaptiveOperation>(json!({
                "operation":"set_auto_learning","enabled":true,"extra":1
            }))
            .is_err()
        );
    }
}
