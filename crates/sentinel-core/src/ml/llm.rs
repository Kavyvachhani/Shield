use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMConfig {
    pub provider: String, // "ollama", "openai-compatible", "none"
    pub base_url: String, // e.g. "http://localhost:11434/v1"
    pub api_key: Option<String>,
    pub model_name: String, // e.g. "llama3", "mistral"
}

impl Default for LLMConfig {
    fn default() -> Self {
        Self {
            provider: "ollama".into(),
            base_url: "http://localhost:11434/v1".into(),
            api_key: None,
            model_name: "llama3".into(),
        }
    }
}

pub struct LLMEnrichmentService {
    config: LLMConfig,
}

impl LLMEnrichmentService {
    pub fn new(config: LLMConfig) -> Self {
        Self { config }
    }

    /// Generates an executive narrative summary for Report A
    pub async fn generate_executive_narrative(&self, company_name: &str, critical_count: usize, high_count: usize) -> Result<String> {
        if self.config.provider == "none" {
            return Ok(format!(
                "Assessment completed for {}. Identifed {} critical and {} high severity findings requiring immediate remediation.",
                company_name, critical_count, high_count
            ));
        }

        // Mock LLM call output for offline local integration
        Ok(format!(
            "[LLM Enriched Executive Summary for {}]\nSecurity evaluation indicates a key posture risk profile with {} critical issues and {} high issues requiring prioritized patching.",
            company_name, critical_count, high_count
        ))
    }

    /// Enriches remediation instructions for developers
    pub async fn enrich_remediation_guidance(&self, title: &str, cwe_id: Option<&str>) -> Result<String> {
        let cwe = cwe_id.unwrap_or("CWE-General");
        Ok(format!(
            "[LLM Guidance for {} - {}]\n1. Implement robust input validation at API boundary.\n2. Enforce strict parameterization.",
            title, cwe
        ))
    }
}
