use authentication::connectors::AuthenticationConnectorType;
use authentication::connectors::inner::InnerAuthenticationConnectorBuilder;
use authentication::test_helpers::{spawn_connector_app, spawn_configuration};
use data_transmission::web::get_empty_http_data_wraper_from_str;

#[tokio::test]
async fn service_with_permission_routes_access_denied_without_logged_in() {
    // Arrange
    let configuration = spawn_configuration(true).await;
    let connector_app = spawn_connector_app(
        InnerAuthenticationConnectorBuilder::build(configuration.clone()),
        AuthenticationConnectorType::Inner,
        configuration.redis_uri,
    ).await;

    // Act - 1
    let response = connector_app.api_client
        .get(&format!("{}/test-inner/permission-routes/", connector_app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(!context_data.is_success());

    // Act - 2
    let response = connector_app.api_client
        .post(&format!("{}/test-inner/permission-routes/", connector_app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(!context_data.is_success());

    // Act - 3
    let response = connector_app.api_client
        .get(&format!("{}/test-inner/permission-routes/three", connector_app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(!context_data.is_success());

    // Act - 4
    let response = connector_app.api_client
        .get(&format!("{}/test-inner/permission-routes/four", connector_app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(!context_data.is_success());
}

#[tokio::test]
async fn service_with_permission_routes_access_with_admin() {
    // Arrange
    let configuration = spawn_configuration(true).await;
    let connector_app = spawn_connector_app(
        InnerAuthenticationConnectorBuilder::build(configuration.clone()),
        AuthenticationConnectorType::Inner,
        configuration.redis_uri.clone(),
    ).await;
    let app = connector_app.to_test_app(&configuration).await;

    // Act 0 - login
    app.test_user.login(&app).await;

    // Act - 1
    let response = app.api_client
        .get(&format!("{}/test-inner/permission-routes/", app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act - 2
    let response = app.api_client
        .post(&format!("{}/test-inner/permission-routes/", app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act - 3
    let response = app.api_client
        .get(&format!("{}/test-inner/permission-routes/three", app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act - 4
    let response = app.api_client
        .get(&format!("{}/test-inner/permission-routes/four", app.address))
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
