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

        // ONNX integration placeholder - when enabled, would run inference
        // against a fine-tuned transformer model for prompt injection detection.
        Ok(ScanVerdict::Pass)
    }
}
