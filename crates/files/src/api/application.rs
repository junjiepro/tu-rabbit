//! Application
//! 
//! 运行服务

use crate::api::configuration::Settings;
use crate::connectors::inner::{InnerFilesConnectorBuilder, inner_middleware_fn};
use actix_web::dev::Server;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer};
use actix_web_lab::middleware::from_fn;
use connector::{ConnectorBuilder, ConnectorServiceExt};
use std::net::TcpListener;
use tracing_actix_web::TracingLogger;

pub struct Application {
    port: u16,
    server: Server,
}

impl Application {
    pub async fn build(configuration: Settings) -> Result<Self, anyhow::Error> {
        let address = format!(
            "{}:{}",
            configuration.application.host, configuration.application.port
        );
        let listener = TcpListener::bind(address)?;
        let port = listener.local_addr().unwrap().port();
        let connector_builder = InnerFilesConnectorBuilder::build(configuration.clone());
        let server = run(
            listener,
            connector_builder,
        ).await?;

        Ok(Self{ port, server })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server.await
    }
}

async fn run(
    listener: TcpListener,
    connector_builder: InnerFilesConnectorBuilder,
) -> Result<Server, anyhow::Error> {
    let connector_server = connector_builder.build_connector_server();
    let connector_server = Data::new(connector_server);
    
    // Capture `connection` from the surrounding environment
    let server = HttpServer::new(move || {
            App::new()
                .wrap(TracingLogger::default())
                .service(
                    web::scope("")
                        .wrap(from_fn(inner_middleware_fn))
                        .connector_service(Some("/files"), connector_server.get_ref())
                )
        })
        .workers(1)
        .listen(listener)?
        .run();
    Ok(server)
}
