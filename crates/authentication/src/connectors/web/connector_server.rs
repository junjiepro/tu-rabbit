//! Web 连接器服务


use crate::connectors::{web::WebAuthenticationConnector, ApplicationToBind};
use actix_web::{Scope, web::Data, dev::{ServiceFactory, ServiceRequest, ServiceResponse}, Error};
use connector::ConnectorServer;

#[derive(Debug, Clone)]
pub struct WebAuthenticationConnectorServer {
    pub(crate) connector: Data<WebAuthenticationConnector>,
    pub(crate) application_to_bind: Option<Data<ApplicationToBind>>,
}

impl ConnectorServer for WebAuthenticationConnectorServer {
    fn service_factory<
        T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = Error,
            InitError = (),
        >
    >(&self, _path: Option<&str>, scope: Scope<T>) -> Scope<T> {
        scope
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
        let scope = scope
            .app_data(self.connector.clone());
        if let Some(application_to_bind) = &self.application_to_bind {
            scope
                .app_data(application_to_bind.clone())
        } else {
            scope
        }
    }
}