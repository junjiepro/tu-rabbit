//! Inner 连接器服务

use crate::api::configuration::MailSettings;
use crate::api::health_check::health_check;
use crate::connectors::inner::{InnerMailConnector, ApplicationBaseUrl, HmacSecret};
use actix_web::Error;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{web::{self, Data}, Scope};
use connector::ConnectorServer;

#[derive(Debug, Clone)]
pub struct InnerMailConnectorServer {
    pub(crate) connector: Data<InnerMailConnector>,
    pub(crate) base_url: Data<ApplicationBaseUrl>,
    pub(crate) hmac_secret: Data<HmacSecret>,
    pub(crate) mail_settings: Data<MailSettings>,
}

impl ConnectorServer for InnerMailConnectorServer {
    fn service_factory<
        T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = Error,
            InitError = (),
        >
    >(&self, path: Option<&str>, scope: Scope<T>) -> Scope<T> {
        match path {
            Some(path) =>
                scope
                    .service(
                        web::scope(path)
                            .route("/health-check", web::get().to(health_check))
                    ),
            None => scope,
        }
    }

    fn service_app_data<
        T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = Error,
            InitError = (),
        >
    >(&self, scope: Scope<T>) -> Scope<T> {
        scope
            .app_data(self.connector.clone())
            .app_data(self.base_url.clone())
            .app_data(self.hmac_secret.clone())
            .app_data(self.mail_settings.clone())
    }
}