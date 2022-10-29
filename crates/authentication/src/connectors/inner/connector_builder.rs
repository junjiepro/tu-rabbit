//! Inner 认证、授权连接器构造器
//! 

use crate::api::configuration::{Settings, DatabaseSettings};
use crate::connectors::{AuthenticationConnectorBuilder, ApplicationToBind};
use crate::connectors::inner::{InnerAuthenticationConnector, InnerAuthenticationConnectorServer};
use actix_web::web::Data;
use connector::ConnectorBuilder;
use secrecy::Secret;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Inner 认证、授权连接器构造器
pub struct InnerAuthenticationConnectorBuilder {
    pub(crate) configuration: Settings,
    pub(crate) application_to_bind: Option<ApplicationToBind>,
}

impl ConnectorBuilder for InnerAuthenticationConnectorBuilder {
    type Connector = InnerAuthenticationConnector;
    type ConnectorServer = InnerAuthenticationConnectorServer;

    fn build_connector(&self) -> Self::Connector {
        InnerAuthenticationConnector {}
    }

    fn build_connector_server(&self) -> Self::ConnectorServer {
        let connector = self.build_connector();
        let db_pool = get_connection_pool(&self.configuration.database);
        let base_url = self.configuration.application.base_url.clone();
        let hmac_secret = self.configuration.application.hmac_secret.clone();
        let forbidden_admin_application_msg_id = self.configuration.application.forbidden_admin_application_msg_id;

        let connector = Data::new(connector);
        let db_pool = Data::new(ApplicationPgPool(db_pool));
        let base_url = Data::new(ApplicationBaseUrl(base_url));
        let hmac_secret = Data::new(HmacSecret(hmac_secret.clone()));
        let forbidden_admin_application_msg_id = Data::new(ForbiddenAdminApplicationMsgId(forbidden_admin_application_msg_id));
        let application_to_bind = match &self.application_to_bind {
            Some(application_to_bind) => Some(Data::new(application_to_bind.clone())),
            None => None,
        };

        InnerAuthenticationConnectorServer {
            connector,
            db_pool,
            base_url,
            hmac_secret,
            forbidden_admin_application_msg_id,
            application_to_bind,
        }
    }
}

impl AuthenticationConnectorBuilder for InnerAuthenticationConnectorBuilder {
    fn bind_application(mut self, application_msg_id: &str) -> Self {
        if application_msg_id == "admin" && self.configuration.application.forbidden_admin_application_msg_id {
            panic!("Forbidden admin application msg id!");
        }
        self.application_to_bind = Some(ApplicationToBind {
            application_msg_id: application_msg_id.into(),
        });
        self
    }
}

impl InnerAuthenticationConnectorBuilder {
    pub fn build(configuration: Settings) -> Self {
        Self {
            configuration,
            application_to_bind: None,
        }
    }
}

pub fn get_connection_pool(
    configuration: &DatabaseSettings
) -> PgPool {
    PgPoolOptions::new()
        .connect_timeout(std::time::Duration::from_secs(2))
        .connect_lazy_with(configuration.with_db())
}

// We need to define a wrapper type in order to retrieve the URL
// in the `subscribe` handler.
// Retrieval from the context, in actix-web, is type-based: using
// a raw `String` would expose us to conflicts.
#[derive(Debug)]
pub struct ApplicationBaseUrl(pub String);

#[derive(Debug, Clone)]
pub struct HmacSecret(pub Secret<String>);

#[derive(Debug)]
pub struct ApplicationPgPool(pub PgPool);

#[derive(Debug)]
pub struct ForbiddenAdminApplicationMsgId(pub bool);
