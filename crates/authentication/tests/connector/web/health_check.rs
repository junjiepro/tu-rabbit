use authentication::connectors::AuthenticationConnectorType;
use authentication::test_helpers::{spawn_app, spawn_connector_app, spawn_configuration};
use authentication::connectors::web::WebAuthenticationConnectorBuilder;
use data_transmission::web::get_empty_http_data_wraper_from_str;

#[tokio::test]
async fn health_check_works() {
    // Arrange
    let app = spawn_app().await;
    let configuration = spawn_configuration(false).await;
    let connector_app = spawn_connector_app(
        WebAuthenticationConnectorBuilder::build(
            format!("{}/authentication", &app.address)
        ),
        AuthenticationConnectorType::Web,
        configuration.redis_uri,
    ).await;

    // Act
    let response = app.api_client
        .get(&format!("{}/test-web/health-check", connector_app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());
}

