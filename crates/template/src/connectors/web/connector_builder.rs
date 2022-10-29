//! web 连接器构造器
//! 

use crate::connectors::TemplateConnectorBuilder;
use crate::connectors::web::{WebTemplateConnector, WebTemplateConnectorServer};
use actix_web::web::Data;
use connector::ConnectorBuilder;

/// web 连接器构造器
pub struct WebTemplateConnectorBuilder {
    pub(crate) address: String,
}

impl ConnectorBuilder for WebTemplateConnectorBuilder {
    type Connector = WebTemplateConnector;
    type ConnectorServer = WebTemplateConnectorServer;

    fn build_connector(&self) -> Self::Connector {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .build()
            .unwrap();
        
        WebTemplateConnector {
            address: self.address.clone(),
            client,
        }
    }

    fn build_connector_server(&self) -> Self::ConnectorServer {
        let connector = self.build_connector();
        let connector = Data::new(connector);
        
        WebTemplateConnectorServer {
            connector
        }
    }
}

impl TemplateConnectorBuilder for WebTemplateConnectorBuilder {}

impl WebTemplateConnectorBuilder {
    pub fn build(address: String) -> Self {
        Self { address }
    }
}