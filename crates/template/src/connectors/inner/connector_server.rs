//! Inner 连接器服务

use crate::api::health_check::health_check;
use crate::connectors::inner::InnerTemplateConnector;
use actix_web::Error;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{web::{self, Data}, Scope};
use connector::ConnectorServer;

#[derive(Debug, Clone)]
pub struct InnerTemplateConnectorServer {
    pub(crate) connector: Data<InnerTemplateConnector>,
}

impl ConnectorServer for InnerTemplateConnectorServer {
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
    }
}