//! Inner 连接器服务

use crate::api::files::{save_files, save_files_without_timestamp, download_file};
use crate::api::health_check::health_check;
use crate::connectors::inner::{InnerFilesConnector, FilesRootDirectory};
use actix_web::Error;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{web::{self, Data}, Scope};
use connector::ConnectorServer;

#[derive(Debug, Clone)]
pub struct InnerFilesConnectorServer {
    pub(crate) connector: Data<InnerFilesConnector>,
    pub(crate) files_root_directory: Data<FilesRootDirectory>,
}

impl ConnectorServer for InnerFilesConnectorServer {
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
                            .route("", web::post().to(save_files))
                            .route("", web::get().to(download_file))
                            .route("/no-timestamp", web::post().to(save_files_without_timestamp))
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
            .app_data(self.files_root_directory.clone())
    }
}