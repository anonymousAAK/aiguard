use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::{Result, TetherError};
use crate::policy::RedactConfig;

/// A single redaction match found in the input text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactMatch {
    /// Name of the rule that triggered.
    pub rule: String,
    /// Byte offset in the original text.
    pub offset: usize,
    /// Length of the matched text in bytes.
    pub length: usize,
    /// The original text that was redacted.
    pub original: String,
}

/// A compiled, ready-to-use secret redactor.
///
/// Pre-compiles all regex patterns at construction time for fast repeated use.
#[derive(Debug, Clone)]
pub struct Redactor {
    rules: Vec<CompiledRule>,
    replacement_template: String,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    name: String,
    regex: Regex,
}

impl Redactor {
    /// Build a `Redactor` from the policy's redact configuration.
    pub fn from_config(config: &RedactConfig) -> Result<Self> {
        let mut rules = Vec::with_capacity(config.patterns.len());
        for pat in &config.patterns {
            let regex = Regex::new(&pat.regex).map_err(|e| TetherError::Regex(e))?;
            rules.push(CompiledRule {
                name: pat.name.clone(),
                regex,
            });
        }
        Ok(Self {
            rules,
            replacement_template: config.replacement_template.clone(),
        })
    }

    /// Build a `Redactor` with no rules (passes everything through).
    pub fn noop() -> Self {
        Self {
            rules: Vec::new(),
            replacement_template: String::new(),
        }
    }

    /// Redact all matching secrets in the input text.
    ///
    /// Returns the redacted text and a list of every match that was found.
    /// Matches are processed in rule order; overlapping matches from the same
    /// pass are handled by iterating through non-overlapping matches per rule.
    pub fn redact(&self, text: &str) -> (String, Vec<RedactMatch>) {
        if self.rules.is_empty() {
            return (text.to_string(), Vec::new());
        }

        let mut matches: Vec<RedactMatch> = Vec::new();
        let mut result = text.to_string();

        for rule in &self.rules {
            // We must re-scan after each rule because offsets shift.
            let mut new_result = String::with_capacity(result.len());
            let mut last_end = 0;

            for m in rule.regex.find_iter(&result) {
                let replacement = self.replacement_template.replace("{rule}", &rule.name);

                // Record the match relative to the *current* result string.
                // For the caller, we record against the evolving text.
                matches.push(RedactMatch {
                    rule: rule.name.clone(),
                    offset: m.start(),
                    length: m.len(),
                    original: m.as_str().to_string(),
                });

                new_result.push_str(&result[last_end..m.start()]);
                new_result.push_str(&replacement);
                last_end = m.end();
            }

            new_result.push_str(&result[last_end..]);
            result = new_result;
        }

        (result, matches)
    }

    /// Returns the number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{RedactConfig, RedactPattern};

    fn test_config() -> RedactConfig {
        RedactConfig {
            patterns: vec![
                RedactPattern {
                    name: "aws_key".into(),
                    regex: r"AKIA[0-9A-Z]{16}".into(),
                },
                RedactPattern {
                    name: "github_token".into(),
                    regex: r"ghp_[A-Za-z0-9]{36,}".into(),
                },
            ],
            replacement_template: "[REDACTED:{rule}]".into(),
        }
    }

    #[test]
    fn redacts_aws_key() {
        let r = Redactor::from_config(&test_config()).unwrap();
        let input = "my key is AKIAIOSFODNN7EXAMPLE ok";
        let (output, hits) = r.redact(input);
        assert_eq!(output, "my key is [REDACTED:aws_key] ok");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "aws_key");
        assert_eq!(hits[0].original, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn redacts_github_token() {
        let r = Redactor::from_config(&test_config()).unwrap();
        let token = format!("ghp_{}", "A".repeat(40));
        let input = format!("token={token}");
        let (output, hits) = r.redact(&input);
        assert!(output.contains("[REDACTED:github_token]"));
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn no_match_passes_through() {
        let r = Redactor::from_config(&test_config()).unwrap();
        let input = "nothing secret here";
        let (output, hits) = r.redact(input);
        assert_eq!(output, input);
        assert!(hits.is_empty());
    }

    #[test]
    fn noop_redactor_passes_through() {
        let r = Redactor::noop();
        let input = "AKIAIOSFODNN7EXAMPLE";
        let (output, hits) = r.redact(input);
        assert_eq!(output, input);
        assert!(hits.is_empty());
    }

    #[test]
    fn multiple_matches_in_one_input() {
        let r = Redactor::from_config(&test_config()).unwrap();
        let input = "key1=AKIAIOSFODNN7EXAMPLE key2=AKIAIOSFODNN7ABCDEFG";
        let (output, hits) = r.redact(input);
        assert_eq!(hits.len(), 2);
        assert!(!output.contains("AKIA"));
    }
}
