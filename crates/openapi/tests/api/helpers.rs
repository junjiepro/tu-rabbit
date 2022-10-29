use std::path::Path;

use openapi::api::configuration::get_openapi_configuration;
use openapi::api::application::Application;
use telemetry::tracing;

pub struct TestApp {
    pub port: u16,
    pub address: String,
    pub api_client: reqwest::Client,
}

impl TestApp {
    pub async fn get_api_docs(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/openapi/api-docs", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

// Launch our application in the background ~somehow~
pub async fn spawn_app() -> TestApp {
    tracing();

    // Randomise configuration to ensure test isolation
    let configuration = {
        let mut c = get_openapi_configuration(
            Some(
                Path::new("../../").to_path_buf()
            )
        ).expect("Failed to read configuration.");
        // Use a random OS port
        c.application.port = 0;
        c
    };

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

