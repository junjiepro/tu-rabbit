use authentication::test_helpers::spawn_app;
use data_transmission::{error::{Error, authentication::ValidateError}, web::{get_error_from_str, get_empty_http_data_wraper_from_str}};
use reqwest::StatusCode;

#[tokio::test]
async fn out_login_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    
    // Act
    let response = app.api_client
        .post(&format!("{}/authentication/out-login", app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    
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
async fn out_login_with_login_return_success() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - out login
    let response = app.api_client
        .post(&format!("{}/authentication/out-login", app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());
}

#[tokio::test]
async fn get_current_user_after_out_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - out login
    let response = app.api_client
        .post(&format!("{}/authentication/out-login", app.address))
        .send()
        .await
        .expect("Failed to execute request.");
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 3 - get current user
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
