//! Inner 连接器构造器
//! 

use crate::api::configuration::Settings;
use crate::connectors::FilesConnectorBuilder;
use crate::connectors::inner::{InnerFilesConnector, InnerFilesConnectorServer};
use actix_web::web::Data;
use connector::ConnectorBuilder;

/// Inner 连接器构造器
pub struct InnerFilesConnectorBuilder {
    pub(crate) configuration: Settings,
}

impl ConnectorBuilder for InnerFilesConnectorBuilder {
    type Connector = InnerFilesConnector;
    type ConnectorServer = InnerFilesConnectorServer;

    fn build_connector(&self) -> Self::Connector {
        InnerFilesConnector {}
    }

    fn build_connector_server(&self) -> Self::ConnectorServer {
        let connector = self.build_connector();
        let files_root_directory = FilesRootDirectory(self.configuration.files_root_directory.clone());

        let connector = Data::new(connector);
        let files_root_directory = Data::new(files_root_directory);
        InnerFilesConnectorServer {
            connector,
            files_root_directory,
        }
    }
}

impl FilesConnectorBuilder for InnerFilesConnectorBuilder {}

impl InnerFilesConnectorBuilder {
    pub fn build(configuration: Settings) -> Self {
        Self { configuration }
    }
}

#[derive(Debug)]
pub struct FilesRootDirectory(pub String);
