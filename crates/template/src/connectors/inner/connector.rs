//! Inner 认证、授权连接器

use crate::connectors::TemplateConnector;
use connector::Connector;
use data_transmission::error;

/// Inner 连接器
#[derive(Debug, Clone)]
pub struct InnerTemplateConnector {}

impl Connector for InnerTemplateConnector {}

impl TemplateConnector for InnerTemplateConnector {}

impl InnerTemplateConnector {
    /// 健康检查
    pub async fn health_check(&self) -> Result<(), error::Error> {
        Ok(())
    }
}
