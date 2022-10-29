use authentication::test_helpers::spawn_app;
use data_transmission::{error::{Error, authentication::{SendVerificationCodeError, GenerateVerificationCodeError}}, web::{get_error_from_str, get_empty_http_data_wraper_from_str}};
use reqwest::StatusCode;
use uuid::Uuid;

#[tokio::test]
async fn generate_verification_code_and_send_with_invalid_data_return_not_supported_error_response() {
    // Arrange
    let app = spawn_app().await;
    let key = Uuid::new_v4().to_string();
    let value = Uuid::new_v4().to_string();

    // Act
    let response = app.generate_verification_code_and_send(&serde_json::json!({
        key: value,
    })).await;
    
    // Assert - code
    assert_eq!(StatusCode::BAD_REQUEST.as_u16(), response.status().as_u16());
}

#[tokio::test]
async fn generate_verification_code_and_send_with_email_type_return_success() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.generate_verification_code_and_send(&serde_json::json!({
        "key": "someone@some.COM.CN",
        "keyType": 1,
    })).await;
    
    // Assert
    assert!(response.status().is_success());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());
}

#[tokio::test]
async fn generate_verification_code_and_send_with_phone_type_return_not_supported_error_response() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.generate_verification_code_and_send(&serde_json::json!({
        "key": "12345678910",
        "keyType": 2,
    })).await;
    
    // Assert - context - Error
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = SendVerificationCodeError::NotSupportedYetError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::NOT_IMPLEMENTED.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn generate_verification_code_and_send_with_empty_key_return_empty_error_response() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.generate_verification_code_and_send(&serde_json::json!({
        "key": "",
        "keyType": 1,
    })).await;
    
    // Assert - context - Error
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = GenerateVerificationCodeError::EmptyValueError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::BAD_REQUEST.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}