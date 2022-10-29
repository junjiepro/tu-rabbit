use std::path::Path;

use actix_web::web::{Data, self};
use actix_web::{HttpServer, App, HttpResponse};
use actix_web_lab::middleware::from_fn;
use connector::{ConnectorBuilder, ConnectorServiceExt};
use data_transmission::web::{build_http_response_error_data, build_http_response_empty_data};
use tracing_actix_web::TracingLogger;
use crate::api::configuration::{Settings, get_mail_configuration, MailSettings};
use crate::api::application::Application;
use crate::connectors::MailConnectorType;
use crate::connectors::inner::{InnerMailConnector, inner_middleware_fn};
use crate::connectors::web::{WebMailConnector, web_middleware_fn};
use crate::domain::mail_builder::MailBuilder;
use telemetry::tracing;
use std::net::TcpListener;

pub struct TestApp {
    pub port: u16,
    pub address: String,
    pub api_client: reqwest::Client,
}

impl TestApp {
    
}

pub async fn spawn_configuration() -> Settings {
    // Randomise configuration to ensure test isolation
    let configuration = {
        let mut c = get_mail_configuration(
            Some(
                Path::new("../../").to_path_buf()
            )
        ).expect("Failed to read configuration.");
        // Use a random OS port
        c.application.port = 0;
        c
    };

    configuration
}

// Launch our application in the background ~somehow~
pub async fn spawn_app() -> TestApp {
    tracing();
    
    let configuration = spawn_configuration().await;
    
    let application = Application::build(configuration.clone()).await.expect("Failed to build application.");
    let application_port = application.port();
    let address = format!("http://localhost:{}", application_port);
    // Launch the server as a background task
    // tokio::spawn returns a handle to the spawned future,
    // but we have no use for it here, hence the non-binding let
    let _ = tokio::spawn(application.run_until_stopped());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    
    let test_app = TestApp {
        address,
        port: application_port,
        api_client: client,
    };
    test_app
}


pub struct ConnectorTestApp {
    pub port: u16,
    pub address: String,
    pub api_client: reqwest::Client,
}

pub async fn spawn_connector_app(
    connector_builder: impl ConnectorBuilder + Send + 'static,
    connector_type: MailConnectorType,
) -> ConnectorTestApp {
    tracing();

    let address = format!("127.0.0.1:{}", 0);
    let listener = TcpListener::bind(address).unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("http://localhost:{}", port);

    let _ = tokio::spawn(build_application(
        connector_builder,
        connector_type,
        listener,
    ));

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    ConnectorTestApp {
        port,
        address,
        api_client: client,
    }
}

async fn build_application(
    connector_builder: impl ConnectorBuilder,
    connector_type: MailConnectorType,
    listener: TcpListener,
) -> Result<(), std::io::Error> {
    let connector_server = connector_builder.build_connector_server();
    let connector_server = Data::new(connector_server);

    let server = match connector_type {
        MailConnectorType::Web => {
            HttpServer::new(move || {
                App::new()
                    .wrap(TracingLogger::default())
                    .service(
                        web::scope("")
                        .wrap(from_fn(web_middleware_fn))
                        .connector_service(None, connector_server.get_ref())
                        .route("/test-web/health-check", web::get().to(web_health_check))
                    )
            })
            .workers(1)
            .listen(listener)
            .unwrap()
            .run()
        },
        MailConnectorType::Inner => {
            HttpServer::new(move || {
                App::new()
                    .wrap(TracingLogger::default())
                    .service(
                        web::scope("")
                        .wrap(from_fn(inner_middleware_fn))
                        .connector_service(None, connector_server.get_ref())
                        .route("/test-inner/health-check", web::get().to(inner_health_check))
                        .route("/test-inner/send-mail", web::post().to(inner_send_mail))
                    )
            })
            .workers(1)
            .listen(listener)
            .unwrap()
            .run()
        },
    };
    server.await
}

async fn inner_health_check(connector: Data<InnerMailConnector>) -> HttpResponse {
    match connector.health_check().await {
        Ok(_) => build_http_response_empty_data(),
        Err(e) => build_http_response_error_data(e),
    }
}

async fn inner_send_mail(connector: Data<InnerMailConnector>, mail_settings: Data<MailSettings>) -> HttpResponse {
    match connector.send_mail(
        mail_settings.get_ref(),
        MailBuilder::new()
            .to("test@mytest.com")
            .subject("Test")
            .text("Test content"),
    ) {
        Ok(_) => build_http_response_empty_data(),
        Err(e) => build_http_response_error_data(e),
    }
}

async fn web_health_check(connector: Data<WebMailConnector>) -> HttpResponse {
    match connector.health_check().await {
        Ok(_) => build_http_response_empty_data(),
        Err(e) => build_http_response_error_data(e),
    }
}
