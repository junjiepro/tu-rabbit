use authentication::connectors::{AuthenticationConnectorType, AuthenticationConnectorBuilder};
use authentication::domain::user::User;
use authentication::test_helpers::{spawn_app, spawn_connector_app, spawn_configuration};
use authentication::connectors::web::WebAuthenticationConnectorBuilder;
use data_transmission::error::Error;
use data_transmission::error::authentication::ValidateError;
use data_transmission::web::{get_data_from_str, get_error_from_str};
use reqwest::StatusCode;

#[tokio::test]
async fn get_current_user_with_login_returns_valid_user() {
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

    // Act 1 - login
    app.test_user.login(&app).await;

    // Act 2 - get current user
    let response = app.api_client
        .get(&format!("{}/test-web/current-user", connector_app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context - User
    let context = response.text().await.unwrap().clone();
    let user = get_data_from_str::<User>(context.as_str()).unwrap();
    assert_eq!(app.test_user.user_id, user.get_user_id());

    // Assert - permissions
    let permissions_string_array = user.permissions_string_array();
    assert_eq!(Vec::<String>::new(), permissions_string_array);
}

#[tokio::test]
async fn get_current_user_without_login_returns_unauthenticated_error_response() {
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

    // Act - get current user
    let response = app.api_client
        .get(&format!("{}/test-web/current-user", connector_app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    
    // Assert - status code
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context - Error
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = ValidateError::AuthError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::UNAUTHORIZED.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn get_current_user_with_login_from_admin_binding_connector_builder_returns_valid_user() {
    // Arrange
    let app = spawn_app().await;
    let configuration = spawn_configuration(false).await;
    let connector_app = spawn_connector_app(
        WebAuthenticationConnectorBuilder::build(
            format!("{}/authentication", &app.address)
        ).bind_application("admin"),
        AuthenticationConnectorType::Web,
        configuration.redis_uri,
    ).await;

    // Act 1 - login
    app.test_user.login(&app).await;

    // Act 2 - get current user
    let response = app.api_client
        .get(&format!("{}/test-web/current-user", connector_app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context - User
    let context = response.text().await.unwrap().clone();
    let user = get_data_from_str::<User>(context.as_str()).unwrap();
    assert_eq!(app.test_user.user_id, user.get_user_id());

    // Assert - permissions
    let permissions_string_array = user.permissions_string_array();
    assert_eq!(vec!["admin".to_string(), "".to_string()], permissions_string_array);
}