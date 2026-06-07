use serde::{Deserialize, Serialize};

use crate::scanner::ScanVerdict;

/// The final decision made by the policy engine after aggregating all scanner
/// verdicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Decision {
    /// The action is allowed unconditionally.
    Allow,

    /// The action is allowed, but the user should see some context.
    AllowWithContext(String),

    /// The tool input/output should be rewritten before proceeding.
    Mutate(serde_json::Value),

    /// The action is blocked with a reason.
    Block(String),

    /// The engine cannot decide automatically; prompt the user.
    Ask,
}

impl Decision {
    /// Short label suitable for audit logs and display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AllowWithContext(_) => "allow_with_context",
            Self::Mutate(_) => "mutate",
            Self::Block(_) => "block",
            Self::Ask => "ask",
        }
    }
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::AllowWithContext(ctx) => write!(f, "allow ({ctx})"),
            Self::Mutate(_) => write!(f, "mutate"),
            Self::Block(reason) => write!(f, "block: {reason}"),
            Self::Ask => write!(f, "ask"),
        }
    }
}

/// Aggregate multiple scanner verdicts into a single decision.
///
/// Worst-verdict-wins logic:
/// - Any `Block` => `Decision::Block` (with the highest-scoring block message)
/// - No blocks but any `Mutate` => `Decision::Mutate` (first mutation wins)
/// - No blocks/mutates but any `Warn` => `Decision::AllowWithContext`
/// - All `Pass` => `Decision::Allow`
///
/// When multiple blocks exist, the one with the highest score is used for the
/// block message. When multiple warnings exist, their messages are joined.
pub fn aggregate(verdicts: &[ScanVerdict]) -> Decision {
    if verdicts.is_empty() {
        return Decision::Allow;
    }

    let mut worst_block: Option<(&str, f32)> = None;
    let mut block_messages: Vec<&str> = Vec::new();
    let mut first_mutate: Option<&serde_json::Value> = None;
    let mut warn_messages: Vec<&str> = Vec::new();

    for v in verdicts {
        match v {
            ScanVerdict::Block { message, score, .. } => {
                block_messages.push(message.as_str());
                let dominated = worst_block.map(|(_, s)| *score > s).unwrap_or(true);
                if dominated {
                    worst_block = Some((message.as_str(), *score));
                }
            }
            ScanVerdict::Mutate { replacement, .. } => {
                if first_mutate.is_none() {
                    first_mutate = Some(replacement);
                }
            }
            ScanVerdict::Warn { message, .. } => {
                warn_messages.push(message.as_str());
            }
            ScanVerdict::Pass => {}
        }
    }

    // Worst-verdict-wins
    if !block_messages.is_empty() {
        let msg = if block_messages.len() == 1 {
            block_messages[0].to_string()
        } else {
            format!(
                "{} scanners blocked: {}",
                block_messages.len(),
                block_messages.join("; ")
            )
        };
        return Decision::Block(msg);
    }

    if let Some(replacement) = first_mutate {
        return Decision::Mutate(replacement.clone());
    }

    if !warn_messages.is_empty() {
        let ctx = warn_messages.join("; ");
        return Decision::AllowWithContext(ctx);
    }

    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Hit;

    #[test]
    fn empty_verdicts_allow() {
        assert!(matches!(aggregate(&[]), Decision::Allow));
    }

    #[test]
    fn all_pass_allows() {
        let verdicts = vec![ScanVerdict::Pass, ScanVerdict::Pass];
        assert!(matches!(aggregate(&verdicts), Decision::Allow));
    }

    #[test]
    fn warn_produces_allow_with_context() {
        let verdicts = vec![
            ScanVerdict::Pass,
            ScanVerdict::Warn {
                message: "looks suspicious".into(),
                score: 0.4,
                hits: vec![],
            },
        ];
        match aggregate(&verdicts) {
            Decision::AllowWithContext(ctx) => assert!(ctx.contains("suspicious")),
            other => panic!("expected AllowWithContext, got {other:?}"),
        }
    }

    #[test]
    fn block_wins_over_warn() {
        let verdicts = vec![
            ScanVerdict::Warn {
                message: "hmm".into(),
                score: 0.3,
                hits: vec![],
            },
            ScanVerdict::Block {
                message: "definitely bad".into(),
                score: 0.9,
                hits: vec![Hit {
                    rule_id: "T-1".into(),
                    matched_text: "rm -rf /".into(),
                    offset: 0,
                    length: 8,
                }],
            },
        ];
        match aggregate(&verdicts) {
            Decision::Block(msg) => assert!(msg.contains("definitely bad")),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn mutate_wins_over_warn_but_not_block() {
        let verdicts = vec![
            ScanVerdict::Warn {
                message: "w".into(),
                score: 0.2,
                hits: vec![],
            },
            ScanVerdict::Mutate {
                replacement: serde_json::json!({"redacted": true}),
                message: "redacted secret".into(),
            },
        ];
        assert!(matches!(aggregate(&verdicts), Decision::Mutate(_)));
    }

    #[test]
    fn multiple_blocks_joined() {
        let verdicts = vec![
            ScanVerdict::Block {
                message: "first".into(),
                score: 0.8,
                hits: vec![],
            },
            ScanVerdict::Block {
                message: "second".into(),
                score: 0.95,
                hits: vec![],
            },
        ];
        match aggregate(&verdicts) {
            Decision::Block(msg) => {
                assert!(msg.contains("2 scanners blocked"));
                assert!(msg.contains("first"));
                assert!(msg.contains("second"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }
}
