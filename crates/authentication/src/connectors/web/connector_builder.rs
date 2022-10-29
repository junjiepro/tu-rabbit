//! web 认证、授权连接器构造器
//! 

use crate::connectors::{AuthenticationConnectorBuilder, ApplicationToBind};
use crate::connectors::web::{WebAuthenticationConnector, WebAuthenticationConnectorServer};
use actix_web::web::Data;
use connector::ConnectorBuilder;

/// web 认证、授权连接器构造器
pub struct WebAuthenticationConnectorBuilder {
    pub(crate) address: String,
    pub(crate) application_to_bind: Option<ApplicationToBind>,
}

impl ConnectorBuilder for WebAuthenticationConnectorBuilder {
    type Connector = WebAuthenticationConnector;
    type ConnectorServer = WebAuthenticationConnectorServer;

    fn build_connector(&self) -> Self::Connector {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .build()
            .unwrap();
        
        WebAuthenticationConnector {
            address: self.address.clone(),
            client,
        }
    }

    fn build_connector_server(&self) -> Self::ConnectorServer {
        let connector = self.build_connector();
        let connector = Data::new(connector);

        let application_to_bind = match &self.application_to_bind {
            Some(application_to_bind) => Some(Data::new(application_to_bind.clone())),
            None => None,
        };
        
        WebAuthenticationConnectorServer {
            connector,
            application_to_bind,
        }
    }
}

impl AuthenticationConnectorBuilder for WebAuthenticationConnectorBuilder {
    fn bind_application(mut self, application_msg_id: &str) -> Self {
        self.application_to_bind = Some(ApplicationToBind {
            application_msg_id: application_msg_id.into(),
        });
        self
    }
}

impl WebAuthenticationConnectorBuilder {
    pub fn build(address: String) -> Self {
        Self {
            address,
            application_to_bind: None,
        }
    }
}