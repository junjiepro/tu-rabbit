use authentication::domain::user::User;
use data_transmission::{error::{Error, authentication::ValidateError}, web::{get_error_from_str, get_data_from_str}};
use reqwest::{StatusCode, header::HeaderMap, header::SET_COOKIE, header::HeaderValue};
use uuid::Uuid;

use authentication::test_helpers::spawn_app;

#[tokio::test]
async fn get_current_user_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.get_current_user().await;

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
async fn get_current_user_with_login_return_valid_user() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - get current user
    let response = app.get_current_user().await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context - User
    let context = response.text().await.unwrap().clone();
    let user = get_data_from_str::<User>(context.as_str()).unwrap();
    assert_eq!(app.test_user.user_id, user.get_user_id());
}

#[tokio::test]
async fn get_current_user_with_login_overtime_and_auto_login_return_valid_user() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    let response = app.test_user.login_with_auto_login(&app).await;

    // Act 2 - take rememberme cookie and ignore token
    let mut headers = HeaderMap::new();
    let cookie = response.cookies()
        .find(|cookie| cookie.name() == "rememberme").unwrap();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!("{}={}", cookie.name(), cookie.value())).unwrap(),
    );

    // Act 3 - get current user
    let response = app.get_current_user_with_headers(headers).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context - User
    let context = response.text().await.unwrap().clone();
    let user = get_data_from_str::<User>(context.as_str()).unwrap();
    assert_eq!(app.test_user.user_id, user.get_user_id());
}

#[tokio::test]
async fn get_current_user_with_invalid_token_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let invalid_token = Uuid::new_v4().to_string();

    // Act 1 - set cookie
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!("token={}", invalid_token)).unwrap(),
    );

    // Act 2 - get current user
    let response = app.get_current_user_with_headers(headers).await;

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
async fn get_current_user_with_invalid_rememberme_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let invalid_rememberme = Uuid::new_v4().to_string();

    // Act 1 - set cookie
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!("rememberme={}", invalid_rememberme)).unwrap(),
    );

    // Act 2 - get current user
    let response = app.get_current_user_with_headers(headers).await;

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
async fn get_current_user_return_valid_user_without_admin_permission() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - get current user
    let response = app.get_current_user().await;

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
async fn bind_current_user_with_admin_return_valid_user_with_admin_permission() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind current user with admin role
    app.bind_current_user_with_admin_role().await;

    // Act 3 - get current user
    let response = app.get_current_user().await;

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