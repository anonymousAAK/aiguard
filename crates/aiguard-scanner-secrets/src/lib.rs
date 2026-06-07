pub mod entropy;
pub mod rules;

use aiguard_core::{Hit, ScanContext, ScanVerdict, Scanner};
use async_trait::async_trait;

use crate::entropy::shannon_entropy;
use crate::rules::{load_rules_from_str, CompiledRuleSet};

const BUILTIN_RULES_TOML: &str = include_str!("../data/secrets-rules.toml");

pub struct SecretsScanner {
    ruleset: CompiledRuleSet,
    entropy_floor: f32,
    action: Action,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Action {
    Block,
    #[default]
    Redact,
    Warn,
}

pub struct SecretMatch {
    pub rule_id: String,
    pub matched_text: String,
    pub offset: usize,
    pub length: usize,
}

impl SecretsScanner {
    pub fn new(action: Action, entropy_floor: f32) -> anyhow::Result<Self> {
        let ruleset = load_rules_from_str(BUILTIN_RULES_TOML)?;
        Ok(Self {
            ruleset,
            entropy_floor,
            action,
        })
    }

    pub fn scan_text(&self, text: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();
        let candidates = self.ruleset.candidate_rules(text);

        for &rule_idx in &candidates {
            let rule = &self.ruleset.rules[rule_idx];
            for m in rule.regex.find_iter(text) {
                let matched_text = m.as_str();

                // Entropy gate
                let floor = rule.entropy.unwrap_or(self.entropy_floor);
                if floor > 0.0 {
                    let e = shannon_entropy(matched_text);
                    if e < floor {
                        continue;
                    }
                }

                matches.push(SecretMatch {
                    rule_id: rule.id.clone(),
                    matched_text: matched_text.to_string(),
                    offset: m.start(),
                    length: m.len(),
                });
            }
        }

        matches
    }

    fn to_verdict(&self, matches: Vec<SecretMatch>) -> ScanVerdict {
        if matches.is_empty() {
            return ScanVerdict::Pass;
        }

        let hits: Vec<Hit> = matches
            .iter()
            .map(|m| Hit {
                rule_id: m.rule_id.clone(),
                matched_text: m.matched_text.clone(),
                offset: m.offset,
                length: m.length,
            })
            .collect();

        let message = if matches.len() == 1 {
            format!("secret detected: {}", matches[0].rule_id)
        } else {
            format!(
                "{} secrets detected: {}",
                matches.len(),
                matches
                    .iter()
                    .map(|m| m.rule_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        match self.action {
            Action::Block | Action::Redact => ScanVerdict::Block {
                message,
                score: 1.0,
                hits,
            },
            Action::Warn => ScanVerdict::Warn {
                message,
                score: 0.9,
                hits,
            },
        }
    }
}

#[async_trait]
impl Scanner for SecretsScanner {
    fn name(&self) -> &'static str {
        "secrets"
    }

    async fn scan(&self, ctx: &ScanContext<'_>) -> aiguard_core::Result<ScanVerdict> {
        let text = if let Some(raw) = ctx.raw_text {
            raw.to_string()
        } else if let Some(response) = ctx.tool_response {
            serde_json::to_string(response).unwrap_or_default()
        } else if let Some(input) = ctx.tool_input {
            serde_json::to_string(input).unwrap_or_default()
        } else {
            return Ok(ScanVerdict::Pass);
        };

        if text.is_empty() {
            return Ok(ScanVerdict::Pass);
        }

        let matches = self.scan_text(&text);
        Ok(self.to_verdict(matches))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_scanner() -> SecretsScanner {
        SecretsScanner::new(Action::Block, 3.5).unwrap()
    }

    #[test]
    fn detects_aws_key() {
        let s = make_scanner();
        // Split to avoid triggering GitHub push protection on the test repo.
        // The scanner sees the concatenated string at runtime.
        let key = ["AKIA", "IOSF", "ODNN7XYZABCD"].concat();
        let matches = s.scan_text(&format!("key={key}"));
        assert!(!matches.is_empty());
        assert_eq!(matches[0].rule_id, "aws-access-key-id");
    }

    #[test]
    fn detects_github_pat() {
        let s = make_scanner();
        // Split across format! to avoid push-protection false-positive.
        let token = format!("ghp_{}{}", "A1b2C3d4E5f6", "G7h8I9j0K1l2M3n4O5p6Q7r8S9t0");
        let matches = s.scan_text(&format!("token={token}"));
        assert!(!matches.is_empty());
    }

    #[test]
    fn detects_private_key() {
        let s = make_scanner();
        let matches =
            s.scan_text("-----BEGIN RSA PRIVATE KEY-----\nblah\n-----END RSA PRIVATE KEY-----");
        assert!(!matches.is_empty());
    }

    #[test]
    fn clean_text_passes() {
        let s = make_scanner();
        let matches = s.scan_text("nothing secret here, just normal code");
        assert!(matches.is_empty());
    }
}
