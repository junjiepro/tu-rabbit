use data_transmission::web::get_empty_http_data_wraper_from_str;
use template::connectors::TemplateConnectorType;
use template::connectors::inner::InnerTemplateConnectorBuilder;
use template::test::helpers::{spawn_connector_app, spawn_configuration};

#[tokio::test]
async fn health_check_works() {
    // Arrange
    let configuration = spawn_configuration().await;
    let connector_app = spawn_connector_app(
        InnerTemplateConnectorBuilder::build(configuration.clone()),
        TemplateConnectorType::Inner,
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

