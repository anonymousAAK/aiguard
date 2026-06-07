use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

/// A single secret-detection rule as loaded from TOML.
#[derive(Debug, Clone)]
pub struct SecretRule {
    /// Unique identifier, e.g. "aws-access-key-id".
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Compiled regex pattern to match secrets.
    pub regex: Regex,
    /// Optional minimum Shannon entropy for the captured group (or full match).
    /// If set, matches below this threshold are discarded as false positives.
    pub entropy: Option<f32>,
    /// Keywords for Aho-Corasick pre-filtering. If non-empty, the rule is only
    /// tested against lines that contain at least one keyword.
    pub keywords: Vec<String>,
}

/// The raw TOML structure for a rule file.
#[derive(Debug, Deserialize)]
pub struct RuleFile {
    #[serde(rename = "rule", default)]
    pub rules: Vec<RawRule>,
}

/// A single rule entry as deserialized from TOML (before regex compilation).
#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub id: String,
    pub description: String,
    pub regex: String,
    #[serde(default)]
    pub entropy: Option<f32>,
    #[serde(default)]
    pub keywords: Vec<String>,
}

/// A compiled rule set ready for scanning, with an optional keyword automaton
/// for fast pre-filtering.
#[derive(Debug)]
pub struct CompiledRuleSet {
    /// All compiled rules.
    pub rules: Vec<SecretRule>,
    /// Aho-Corasick automaton built from all rules' keywords.
    /// Maps each pattern index back to a set of rule indices.
    pub keyword_automaton: Option<AhoCorasick>,
    /// For each pattern in the automaton, which rule indices it belongs to.
    pub keyword_to_rules: Vec<Vec<usize>>,
}

impl CompiledRuleSet {
    /// Returns the set of rule indices whose keywords appear in `text`.
    /// If a rule has no keywords, it is always included.
    pub fn candidate_rules(&self, text: &str) -> Vec<usize> {
        let mut candidates = Vec::new();
        let mut rule_hit = vec![false; self.rules.len()];

        // Rules with no keywords are always candidates.
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.keywords.is_empty() {
                rule_hit[i] = true;
            }
        }

        // Check keyword automaton.
        if let Some(ref ac) = self.keyword_automaton {
            for mat in ac.find_overlapping_iter(text) {
                let pattern_idx = mat.pattern().as_usize();
                if pattern_idx < self.keyword_to_rules.len() {
                    for &rule_idx in &self.keyword_to_rules[pattern_idx] {
                        rule_hit[rule_idx] = true;
                    }
                }
            }
        }

        for (i, hit) in rule_hit.iter().enumerate() {
            if *hit {
                candidates.push(i);
            }
        }

        candidates
    }
}

/// Load rules from a TOML string. Compiles regexes and builds the keyword
/// automaton.
pub fn load_rules_from_str(toml_str: &str) -> anyhow::Result<CompiledRuleSet> {
    let file: RuleFile = toml::from_str(toml_str)?;
    compile_rules(file.rules)
}

/// Load rules from a TOML file on disk.
pub fn load_rules_from_file(path: &Path) -> anyhow::Result<CompiledRuleSet> {
    let contents = std::fs::read_to_string(path)?;
    load_rules_from_str(&contents)
}

/// Compile a list of raw rules into a `CompiledRuleSet`.
pub fn compile_rules(raw_rules: Vec<RawRule>) -> anyhow::Result<CompiledRuleSet> {
    let mut rules = Vec::with_capacity(raw_rules.len());
    let mut all_keywords: Vec<String> = Vec::new();
    let mut keyword_to_rules: Vec<Vec<usize>> = Vec::new();

    for (rule_idx, raw) in raw_rules.into_iter().enumerate() {
        let regex = Regex::new(&raw.regex)
            .map_err(|e| anyhow::anyhow!("failed to compile regex for rule '{}': {}", raw.id, e))?;

        for kw in &raw.keywords {
            let kw_lower = kw.to_lowercase();
            // Check if this keyword already exists.
            if let Some(pos) = all_keywords.iter().position(|k| k == &kw_lower) {
                keyword_to_rules[pos].push(rule_idx);
            } else {
                all_keywords.push(kw_lower);
                keyword_to_rules.push(vec![rule_idx]);
            }
        }

        rules.push(SecretRule {
            id: raw.id,
            description: raw.description,
            regex,
            entropy: raw.entropy,
            keywords: raw.keywords,
        });
    }

    let keyword_automaton = if all_keywords.is_empty() {
        None
    } else {
        Some(
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&all_keywords)
                .map_err(|e| anyhow::anyhow!("failed to build keyword automaton: {}", e))?,
        )
    };

    Ok(CompiledRuleSet {
        rules,
        keyword_automaton,
        keyword_to_rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_single_rule() {
        let toml = r#"
[[rule]]
id = "test-rule"
description = "Test rule"
regex = 'AKIA[0-9A-Z]{16}'
entropy = 3.0
keywords = ["AKIA"]
"#;
        let ruleset = load_rules_from_str(toml).expect("should parse");
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].id, "test-rule");
        assert!(ruleset.keyword_automaton.is_some());
    }

    #[test]
    fn candidate_rules_filters_by_keyword() {
        let toml = r#"
[[rule]]
id = "rule-a"
description = "Rule A"
regex = 'AKIA[0-9A-Z]{16}'
keywords = ["AKIA"]

[[rule]]
id = "rule-b"
description = "Rule B"
regex = 'ghp_[A-Za-z0-9]{36}'
keywords = ["ghp_"]
"#;
        let ruleset = load_rules_from_str(toml).expect("should parse");
        let candidates = ruleset.candidate_rules("found AKIA1234567890123456 in text");
        assert!(candidates.contains(&0));
        assert!(!candidates.contains(&1));
    }

    #[test]
    fn rules_without_keywords_always_match() {
        let toml = r#"
[[rule]]
id = "no-kw"
description = "No keywords"
regex = 'secret_[a-z]+'
"#;
        let ruleset = load_rules_from_str(toml).expect("should parse");
        let candidates = ruleset.candidate_rules("anything");
        assert!(candidates.contains(&0));
    }
}
