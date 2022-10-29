//! Inner 连接器构造器
//! 

use crate::api::configuration::Settings;
use crate::connectors::MailConnectorBuilder;
use crate::connectors::inner::{InnerMailConnector, InnerMailConnectorServer};
use actix_web::web::Data;
use connector::ConnectorBuilder;
use secrecy::Secret;

/// Inner 连接器构造器
pub struct InnerMailConnectorBuilder {
    pub(crate) configuration: Settings,
}

impl ConnectorBuilder for InnerMailConnectorBuilder {
    type Connector = InnerMailConnector;
    type ConnectorServer = InnerMailConnectorServer;

    fn build_connector(&self) -> Self::Connector {
        InnerMailConnector {}
    }

    fn build_connector_server(&self) -> Self::ConnectorServer {
        let connector = self.build_connector();
        let base_url = self.configuration.application.base_url.clone();
        let hmac_secret = self.configuration.application.hmac_secret.clone();
        let mail_settings = self.configuration.mail.clone();

        let connector = Data::new(connector);
        let base_url = Data::new(ApplicationBaseUrl(base_url));
        let hmac_secret = Data::new(HmacSecret(hmac_secret.clone()));
        let mail_settings = Data::new(mail_settings);
        InnerMailConnectorServer {
            connector,
            base_url,
            hmac_secret,
            mail_settings,
        }
    }
}

impl MailConnectorBuilder for InnerMailConnectorBuilder {}

impl InnerMailConnectorBuilder {
    pub fn build(configuration: Settings) -> Self {
        Self { configuration }
    }
}

#[derive(Debug)]
pub struct ApplicationBaseUrl(pub String);

#[derive(Debug, Clone)]
pub struct HmacSecret(pub Secret<String>);
