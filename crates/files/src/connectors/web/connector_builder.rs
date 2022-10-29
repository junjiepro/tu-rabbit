//! web 连接器构造器
//! 

use crate::connectors::FilesConnectorBuilder;
use crate::connectors::web::{WebFilesConnector, WebFilesConnectorServer};
use actix_web::web::Data;
use connector::ConnectorBuilder;

/// web 连接器构造器
pub struct WebFilesConnectorBuilder {
    pub(crate) address: String,
}

impl ConnectorBuilder for WebFilesConnectorBuilder {
    type Connector = WebFilesConnector;
    type ConnectorServer = WebFilesConnectorServer;

    fn build_connector(&self) -> Self::Connector {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .build()
            .unwrap();
        
        WebFilesConnector {
            address: self.address.clone(),
            client,
        }
    }

    fn build_connector_server(&self) -> Self::ConnectorServer {
        let connector = self.build_connector();
        let connector = Data::new(connector);
        
        WebFilesConnectorServer {
            connector
        }
    }
}

impl FilesConnectorBuilder for WebFilesConnectorBuilder {}

impl WebFilesConnectorBuilder {
    pub fn build(address: String) -> Self {
        Self { address }
    }
}