use aiguard_core::ScanVerdict;

/// Tier 2: ONNX model-based prompt injection detection.
///
/// Currently a placeholder that always returns Pass when disabled.
/// Future versions will load an ONNX runtime model for semantic detection.
pub struct ModelTierScanner {
    pub enabled: bool,
}

impl ModelTierScanner {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub async fn scan_text(&self, _text: &str) -> aiguard_core::Result<ScanVerdict> {
        if !self.enabled {
            return Ok(ScanVerdict::Pass);
        }

        // ONNX runtime not compiled in for this build (v0.x stub).
        // Run `aiguard models pull pi-v2` to download the model, then recompile
        // with the `onnx` feature once the runtime is wired up in a future release.
        // Until then, this tier is inert — Tier-1 regex scanning still runs.
        tracing::warn!(
            "prompt-injection model tier is enabled but the ONNX runtime is not \
             compiled in (v0.x stub). Falling back to Pass. Set `tier_model = false` \
             in [scanners.prompt_injection] to suppress this warning."
        );
        Ok(ScanVerdict::Pass)
    }
}
