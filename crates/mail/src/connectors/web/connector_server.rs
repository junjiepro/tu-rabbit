//! Web 连接器服务


use crate::connectors::web::WebMailConnector;
use actix_web::{Scope, web::Data, dev::{ServiceFactory, ServiceRequest, ServiceResponse}, Error};
use connector::ConnectorServer;

#[derive(Debug, Clone)]
pub struct WebMailConnectorServer {
    pub(crate) connector: Data<WebMailConnector>,
}

impl ConnectorServer for WebMailConnectorServer {
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
        scope
            .app_data(self.connector.clone())
    }
}