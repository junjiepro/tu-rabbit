use authentication::test_helpers::spawn_app;
use data_transmission::{error::{Error, authentication::RegisterUserError}, web::{get_error_from_str, get_empty_http_data_wraper_from_str}};
use reqwest::StatusCode;
use uuid::Uuid;

#[tokio::test]
async fn check_username_with_existed_username_return_exist_error_response() {
    // Arrange
    let app = spawn_app().await;
    
    // Act
    let response = app.api_client
        .post(&format!("{}/authentication/check-username", app.address))
        .json(&serde_json::json!({
            "username": &app.test_user.username,
        }))
        .send()
        .await
        .expect("Failed to execute request.");
    
    // Assert
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = RegisterUserError::UsernameAlreadyExistError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::BAD_REQUEST.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn check_username_with_not_existed_username_return_success() {
    // Arrange
    let app = spawn_app().await;
    let username = Uuid::new_v4().to_string();
    
    // Act
    let response = app.api_client
        .post(&format!("{}/authentication/check-username", app.address))
        .json(&serde_json::json!({
            "username": &username,
        }))
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