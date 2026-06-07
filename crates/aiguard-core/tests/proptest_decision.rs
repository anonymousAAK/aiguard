use aiguard_core::scanner::{Hit, ScanVerdict};
use aiguard_core::{aggregate, Decision};
use proptest::prelude::*;

fn arb_hit() -> impl Strategy<Value = Hit> {
    (
        "[a-z]{1,8}",
        "[a-z ]{1,20}",
        0usize..100usize,
        1usize..20usize,
    )
        .prop_map(|(rule_id, matched_text, offset, length)| Hit {
            rule_id,
            matched_text,
            offset,
            length,
        })
}

fn arb_pass() -> impl Strategy<Value = ScanVerdict> {
    Just(ScanVerdict::Pass)
}

fn arb_warn() -> impl Strategy<Value = ScanVerdict> {
    (
        "[a-z ]{1,30}",
        0.0f32..1.0f32,
        prop::collection::vec(arb_hit(), 0..3),
    )
        .prop_map(|(message, score, hits)| ScanVerdict::Warn {
            message,
            score,
            hits,
        })
}

fn arb_block() -> impl Strategy<Value = ScanVerdict> {
    (
        "[a-z ]{1,30}",
        0.0f32..1.0f32,
        prop::collection::vec(arb_hit(), 0..3),
    )
        .prop_map(|(message, score, hits)| ScanVerdict::Block {
            message,
            score,
            hits,
        })
}

fn arb_mutate() -> impl Strategy<Value = ScanVerdict> {
    "[a-z]{1,10}".prop_map(|s| ScanVerdict::Mutate {
        replacement: serde_json::json!({"redacted": s}),
        message: "redacted".into(),
    })
}

fn arb_verdict() -> impl Strategy<Value = ScanVerdict> {
    prop_oneof![arb_pass(), arb_warn(), arb_block(), arb_mutate()]
}

proptest! {
    /// If any Block exists in the input, aggregate must return Block.
    #[test]
    fn block_dominates_all(
        before in prop::collection::vec(arb_verdict(), 0..10),
        block  in arb_block(),
        after  in prop::collection::vec(arb_verdict(), 0..10),
    ) {
        let mut verdicts = before;
        verdicts.push(block);
        verdicts.extend(after);

        let decision = aggregate(&verdicts);
        prop_assert!(
            matches!(decision, Decision::Block(_)),
            "expected Block, got {:?}", decision
        );
    }

    /// With only Mutates and Warns (no Blocks), aggregate must return Mutate.
    #[test]
    fn mutate_dominates_warn_and_pass(
        mutates in prop::collection::vec(arb_mutate(), 1..6),
        warns   in prop::collection::vec(arb_warn(),   0..6),
        passes  in prop::collection::vec(arb_pass(),   0..6),
    ) {
        let mut verdicts: Vec<ScanVerdict> = Vec::new();
        verdicts.extend(mutates);
        verdicts.extend(warns);
        verdicts.extend(passes);

        let decision = aggregate(&verdicts);
        prop_assert!(
            matches!(decision, Decision::Mutate(_)),
            "expected Mutate, got {:?}", decision
        );
    }

    /// With only Warns and Passes (no Block or Mutate), result is AllowWithContext.
    #[test]
    fn warn_dominates_pass(
        warns  in prop::collection::vec(arb_warn(), 1..8),
        passes in prop::collection::vec(arb_pass(), 0..8),
    ) {
        let mut verdicts: Vec<ScanVerdict> = Vec::new();
        verdicts.extend(warns);
        verdicts.extend(passes);

        let decision = aggregate(&verdicts);
        prop_assert!(
            matches!(decision, Decision::AllowWithContext(_)),
            "expected AllowWithContext, got {:?}", decision
        );
    }

    /// Any number of Pass verdicts always yields Allow.
    #[test]
    fn all_pass_is_allow(
        passes in prop::collection::vec(arb_pass(), 1..20),
    ) {
        let decision = aggregate(&passes);
        prop_assert!(
            matches!(decision, Decision::Allow),
            "expected Allow, got {:?}", decision
        );
    }

    /// Reordering the verdict slice does not change the decision variant.
    #[test]
    fn aggregate_is_idempotent_under_reorder(
        a in arb_verdict(),
        b in arb_verdict(),
    ) {
        let ab = aggregate(&[a.clone(), b.clone()]);
        let ba = aggregate(&[b, a]);
        prop_assert_eq!(
            ab.label(),
            ba.label(),
            "aggregate([a,b]) and aggregate([b,a]) should have the same variant"
        );
    }

    /// Empty input always yields Allow.
    #[test]
    fn empty_is_allow(len in 0usize..1usize) {
        prop_assume!(len == 0);
        let decision = aggregate(&[]);
        prop_assert!(matches!(decision, Decision::Allow));
    }
}
