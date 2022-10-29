use authentication::connectors::AuthenticationConnectorType;
use authentication::connectors::inner::InnerAuthenticationConnectorBuilder;
use authentication::test_helpers::{spawn_connector_app, spawn_configuration};
use data_transmission::web::get_empty_http_data_wraper_from_str;

#[tokio::test]
async fn health_check_works() {
    // Arrange
    let configuration = spawn_configuration(true).await;
    let connector_app = spawn_connector_app(
        InnerAuthenticationConnectorBuilder::build(configuration.clone()),
        AuthenticationConnectorType::Inner,
        configuration.redis_uri,
    ).await;

    // Act
    let response = connector_app.api_client
        .get(&format!("{}/test-inner/health-check", connector_app.address))
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

