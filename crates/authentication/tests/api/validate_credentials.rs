use authentication::domain::credentials::ValidateCredentialsResult;
use data_transmission::{error::{Error, authentication::ValidateError}, web::{get_data_from_str, get_error_from_str}};
use reqwest::{StatusCode, cookie::Cookie};
use uuid::Uuid;
use authentication::test_helpers::spawn_app;

#[tokio::test]
async fn validate_credentials_with_valid_user_and_auto_login_return_success_result() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.test_user.login_with_auto_login(&app).await;

    // Assert - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let result = get_data_from_str::<ValidateCredentialsResult>(context.as_str()).unwrap();
    assert_eq!("success", result.status);
    assert_eq!(0, result.status_code);
}

#[tokio::test]
async fn validate_credentials_with_valid_user_and_auto_login_return_valid_credentials_cookie() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.test_user.login_with_auto_login(&app).await;

    // Assert - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - cookies
    let mut cookies = response.cookies();
    let rememberme = cookies.find(|c| c.name() == "rememberme");
    assert_cookie(rememberme);
}

#[tokio::test]
async fn validate_credentials_with_valid_user_and_without_auto_login_return_success_result() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.test_user.login(&app).await;

    // Assert - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let result = get_data_from_str::<ValidateCredentialsResult>(context.as_str()).unwrap();
    assert_eq!("success", result.status);
    assert_eq!(0, result.status_code);
}

#[tokio::test]
async fn validate_credentials_with_valid_user_and_without_auto_login_return_valid_credentials_cookie() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.test_user.login(&app).await;

    // Assert - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - cookies
    let mut cookies = response.cookies();
    let rememberme = cookies.find(|c| c.name() == "rememberme");
    assert!(rememberme.is_none());
}

#[tokio::test]
async fn validate_credentials_with_invalid_user_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let username = Uuid::new_v4().to_string();
    let password = Uuid::new_v4().to_string();

    // Act
    let response = app.validate_credentials(&serde_json::json!({
        "username": &username,
        "password": &password,
        "autoLogin": false,
        "userType": "",
    }))
    .await;

    // Assert
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = ValidateError::AuthError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::UNAUTHORIZED.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn validate_credentials_with_invalid_user_return_empty_credentials_cookie() {
    // Arrange
    let app = spawn_app().await;
    let username = Uuid::new_v4().to_string();
    let password = Uuid::new_v4().to_string();

    // Act
    let response = app.validate_credentials(&serde_json::json!({
        "username": &username,
        "password": &password,
        "autoLogin": false,
        "userType": "",
    }))
    .await;

    // Assert
    assert_eq!(200, response.status().as_u16());
    
    // Assert - cookies
    let mut cookies = response.cookies();
    let session_id = cookies.find(|c| c.name() == "id");
    let rememberme = cookies.find(|c| c.name() == "rememberme");
    assert!(session_id.is_none());
    assert!(rememberme.is_none());
}

#[tokio::test]
async fn validate_credentials_with_invalid_password_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let password = Uuid::new_v4().to_string();

    // Act
    let response = app.validate_credentials(&serde_json::json!({
        "username": &app.test_user.username,
        "password": &password,
        "autoLogin": false,
        "userType": "",
    }))
    .await;

    // Assert
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = ValidateError::AuthError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::UNAUTHORIZED.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn validate_credentials_with_invalid_password_return_empty_credentials_cookie() {
    // Arrange
    let app = spawn_app().await;
    let password = Uuid::new_v4().to_string();

    // Act
    let response = app.validate_credentials(&serde_json::json!({
        "username": &app.test_user.username,
        "password": &password,
        "autoLogin": false,
        "userType": "",
    }))
    .await;

    // Assert
    assert_eq!(200, response.status().as_u16());
    
    // Assert - cookies
    let mut cookies = response.cookies();
    let session_id = cookies.find(|c| c.name() == "id");
    let rememberme = cookies.find(|c| c.name() == "rememberme");
    assert!(session_id.is_none());
    assert!(rememberme.is_none());
}

fn assert_cookie(cookie: Option<Cookie>) {
    assert!(cookie.is_some());
    let cookie = cookie.unwrap();
    assert_eq!("/", cookie.path().unwrap());
    assert!(cookie.http_only());
}