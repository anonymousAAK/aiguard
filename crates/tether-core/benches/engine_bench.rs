use criterion::{black_box, criterion_group, criterion_main, Criterion};
use aiguard_core::{PolicyEngine, Policy, PolicyConfig, DefaultAction};
use aiguard_core::scanner::{AgentKind, ScanContext, Stage};

fn make_allow_engine() -> PolicyEngine {
    let mut policy = Policy::default();
    // Set default_action to Allow so a no-scanner engine always returns Allow.
    policy.policy = PolicyConfig {
        default_action: DefaultAction::Allow,
        strict: false,
        fail_open: false,
        ask_on_first_run: false,
    };
    PolicyEngine::noop(policy).expect("failed to build PolicyEngine")
}

fn bench_evaluate_allow(c: &mut Criterion) {
    let engine = make_allow_engine();
    let input = serde_json::json!({"command": "ls"});

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime");

    c.bench_function("evaluate_allow", |b| {
        b.iter(|| {
            let ctx = ScanContext {
                session_id: "bench-session",
                agent: AgentKind::ClaudeCode,
                stage: Stage::PreTool,
                tool_name: Some(black_box("Bash")),
                tool_input: Some(black_box(&input)),
                tool_response: None,
                raw_text: None,
            };
            rt.block_on(engine.evaluate(black_box(&ctx)))
                .expect("evaluate failed")
        })
    });
}

criterion_group!(benches, bench_evaluate_allow);
criterion_main!(benches);
