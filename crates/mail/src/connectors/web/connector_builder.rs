//! web 连接器构造器
//! 

use crate::connectors::MailConnectorBuilder;
use crate::connectors::web::{WebMailConnector, WebMailConnectorServer};
use actix_web::web::Data;
use connector::ConnectorBuilder;

/// web 连接器构造器
pub struct WebMailConnectorBuilder {
    pub(crate) address: String,
}

impl ConnectorBuilder for WebMailConnectorBuilder {
    type Connector = WebMailConnector;
    type ConnectorServer = WebMailConnectorServer;

    fn build_connector(&self) -> Self::Connector {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .build()
            .unwrap();
        
        WebMailConnector {
            address: self.address.clone(),
            client,
        }
    }

    fn build_connector_server(&self) -> Self::ConnectorServer {
        let connector = self.build_connector();
        let connector = Data::new(connector);
        
        WebMailConnectorServer {
            connector
        }
    }
}

impl MailConnectorBuilder for WebMailConnectorBuilder {}

impl WebMailConnectorBuilder {
    pub fn build(address: String) -> Self {
        Self { address }
    }
}