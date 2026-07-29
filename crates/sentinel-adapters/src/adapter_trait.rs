use async_trait::async_trait;
use sentinel_core::models::finding::Finding;
use sentinel_core::models::target::Target;
use anyhow::Result;

#[async_trait]
pub trait ScannerAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn healthcheck(&self) -> Result<bool>;
    async fn run(&self, target: &Target, config_json: &str) -> Result<Vec<Finding>>;
}
