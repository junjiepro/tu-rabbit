//! Inner 连接器构造器
//! 

use crate::api::configuration::Settings;
use crate::connectors::TemplateConnectorBuilder;
use crate::connectors::inner::{InnerTemplateConnector, InnerTemplateConnectorServer};
use actix_web::web::Data;
use connector::ConnectorBuilder;

/// Inner 连接器构造器
pub struct InnerTemplateConnectorBuilder {
    pub(crate) configuration: Settings,
}

impl ConnectorBuilder for InnerTemplateConnectorBuilder {
    type Connector = InnerTemplateConnector;
    type ConnectorServer = InnerTemplateConnectorServer;

    fn build_connector(&self) -> Self::Connector {
        InnerTemplateConnector {}
    }

    fn build_connector_server(&self) -> Self::ConnectorServer {
        let connector = self.build_connector();

        let connector = Data::new(connector);
        InnerTemplateConnectorServer {
            connector,
        }
    }
}

impl TemplateConnectorBuilder for InnerTemplateConnectorBuilder {}

impl InnerTemplateConnectorBuilder {
    pub fn build(configuration: Settings) -> Self {
        Self { configuration }
    }
}
