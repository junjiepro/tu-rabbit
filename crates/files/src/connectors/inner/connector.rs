//! Inner 认证、授权连接器

use crate::connectors::FilesConnector;
use connector::Connector;
use data_transmission::error;

/// Inner 连接器
#[derive(Debug, Clone)]
pub struct InnerFilesConnector {}

impl Connector for InnerFilesConnector {}

impl FilesConnector for InnerFilesConnector {}

impl InnerFilesConnector {
    /// 健康检查
    pub async fn health_check(&self) -> Result<(), error::Error> {
        Ok(())
    }
}
