//! Application
//! 
//! 运行认证、授权服务

use crate::api::configuration::Settings;
use crate::connectors::inner::{InnerAuthenticationConnectorBuilder, inner_middleware_fn};
use actix_web::dev::Server;
use actix_web::web::Data;
use actix_web::{web, App, HttpServer, middleware};
use actix_web::cookie::Key;
use actix_web_flash_messages::FlashMessagesFramework;
use actix_web_flash_messages::storage::CookieMessageStore;
use actix_web_lab::middleware::from_fn;
use connector::{ConnectorBuilder, ConnectorServiceExt};
use mail::api::configuration::Settings as MailSettings;
use mail::connectors::inner::{InnerMailConnectorBuilder, inner_middleware_fn as mail_inner_middleware_fn};
use typed_redis::TypedRedisBuilder;
use typed_session::TypedSessionMiddleware;
use std::net::TcpListener;
use tracing_actix_web::TracingLogger;
use secrecy::{Secret, ExposeSecret};

pub struct Application {
    port: u16,
    server: Server,
}

impl Application {
    pub async fn build(
        configuration: Settings,
        mail_configuration: MailSettings,
    ) -> Result<Self, anyhow::Error> {
        let address = format!(
            "{}:{}",
            configuration.application.host, configuration.application.port
        );
        let listener = TcpListener::bind(address)?;
        let port = listener.local_addr().unwrap().port();
        let connector_builder = InnerAuthenticationConnectorBuilder::build(configuration.clone());
        let mail_connector_builder = InnerMailConnectorBuilder::build(mail_configuration.clone());
        let server = run(
            listener,
            connector_builder,
            mail_connector_builder,
            configuration.application.hmac_secret,
            configuration.redis_uri,
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
    connector_builder: InnerAuthenticationConnectorBuilder,
    mail_connector_builder: InnerMailConnectorBuilder,
    hmac_secret: Secret<String>,
    redis_uri: Secret<String>,
) -> Result<Server, anyhow::Error> {
    let connector_server = connector_builder.build_connector_server();
    let connector_server = Data::new(connector_server);
    
    let mail_connector_server = mail_connector_builder.build_connector_server();
    let mail_connector_server = Data::new(mail_connector_server);
    
    let secret_key = Key::from(hmac_secret.expose_secret().as_bytes());
    let message_store = CookieMessageStore::builder(secret_key.clone()).build();
    let message_framework = FlashMessagesFramework::builder(message_store).build();
    let redis_store = TypedSessionMiddleware::store(redis_uri.expose_secret()).await?;
    let typed_redis = TypedRedisBuilder::build(redis_uri.expose_secret());
    // Capture `connection` from the surrounding environment
    let server = HttpServer::new(move || {
            App::new()
                .wrap(message_framework.clone())
                .wrap(
                    TypedSessionMiddleware::builder(redis_store.clone(), secret_key.clone()).build()
                )
                .wrap(TracingLogger::default())
                .wrap(middleware::NormalizePath::trim())
                .service(
                    web::scope("")
                        .wrap(from_fn(inner_middleware_fn))
                        .wrap(from_fn(mail_inner_middleware_fn))
                        .connector_service(None, mail_connector_server.get_ref())
                        .connector_service(Some("/authentication"), connector_server.get_ref())
                )
                .app_data(typed_redis.clone())
        })
        .workers(1)
        .listen(listener)?
        .run();
    Ok(server)
}
