use data_transmission::web::get_empty_http_data_wraper_from_str;
use files::connectors::FilesConnectorType;
use files::test::helpers::{spawn_app, spawn_connector_app};
use files::connectors::web::WebFilesConnectorBuilder;

#[tokio::test]
async fn health_check_works() {
    // Arrange
    let app = spawn_app().await;
    let connector_app = spawn_connector_app(
        WebFilesConnectorBuilder::build(
            format!("{}/files", &app.address)
        ),
        FilesConnectorType::Web,
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

