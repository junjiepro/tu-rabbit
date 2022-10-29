use authentication::{test_helpers::spawn_app, domain::application::Application};
use data_transmission::{error::{Error, authentication::ValidateError, CommonError}, web::{get_error_from_str, get_data_from_str, get_empty_http_data_wraper_from_str}};
use reqwest::StatusCode;

////////////////////////////////
///                          ///
///     GET APPLICATIONS      ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_applications_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    
    // Act
    let response = app.get_applications().await;
    
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
async fn get_applications_with_login_but_without_permission_return_no_application_error_response() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - get
    let response = app.get_applications().await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::NoPermissionError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::FORBIDDEN.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn get_applications_with_login_and_bind_admin_role_return_application_array() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - get
    let response = app.get_applications().await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Application>>(context.as_str()).unwrap();
    // admin application
    assert_eq!(1, context_data.len());
}


////////////////////////////////
///                          ///
///      ADD APPLICATION      ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn add_application_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();
    
    // Act
    let response = app.add_application(&serde_json::json!({
        "applicationeId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
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
async fn add_application_with_login_but_without_permission_return_no_application_error_response() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - add
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::NoPermissionError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::FORBIDDEN.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn add_valid_application_with_login_and_bind_admin_role_return_valid_application() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Application>(context.as_str()).unwrap();
    // application
    assert_ne!(application_id, context_data.get_application_id().to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());
}

#[tokio::test]
async fn add_invalid_msg_id_application_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = uuid::Uuid::new_v4().to_string();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::InvalidInputError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::BAD_REQUEST.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn add_stored_application_with_login_and_bind_admin_role_return_error_response() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;

    // Act 4 - add again
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::UnexpectedError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::INTERNAL_SERVER_ERROR.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

////////////////////////////////
///                          ///
///    UPDATE APPLICATION     ///
///                          ///
////////////////////////////////

    
#[tokio::test]
async fn update_application_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();
    
    // Act
    let response = app.update_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
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
async fn update_application_with_login_but_without_permission_return_no_application_error_response() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - add
    let response = app.update_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::NoPermissionError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::FORBIDDEN.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn update_valid_application_with_login_and_bind_admin_role_return_success() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Application>(context.as_str()).unwrap();
    let stored_application_id = context_data.get_application_id().to_string();
    // application
    assert_ne!(&application_id, &stored_application_id);
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = app.spawn_msg_id();

    // Act 4 - update
    let response = app.update_application(&serde_json::json!({
        "applicationId": &stored_application_id,
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 5 - get
    let response = app.get_application_by_id(&stored_application_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Option<Application>>(context.as_str()).unwrap();
    // application
    assert!(context_data.is_some());
    let context_data = context_data.unwrap();
    assert_eq!(stored_application_id, context_data.get_application_id().to_string().as_str());
    assert_eq!(&new_msg_id, context_data.get_msg_id());
}

#[tokio::test]
async fn update_invalid_msg_id_application_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Application>(context.as_str()).unwrap();
    let stored_application_id = context_data.get_application_id().to_string();
    // application
    assert_ne!(&application_id, &stored_application_id);
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = uuid::Uuid::new_v4().to_string();

    // Act 4 - update
    let response = app.update_application(&serde_json::json!({
        "applicationId": &stored_application_id,
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::InvalidInputError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::BAD_REQUEST.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn update_not_stored_application_with_login_and_bind_admin_role_return_error_response() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - update
    let response = app.update_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::NoPermissionError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::FORBIDDEN.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

////////////////////////////////
///                          ///
///   GET APPLICATION BY ID   ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_application_by_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.get_application_by_id(&id).await;
    
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
async fn get_application_by_id_with_login_but_without_permission_return_no_application_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - get
    let response = app.get_application_by_id(&id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::NoPermissionError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::FORBIDDEN.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn get_application_by_invalid_id_with_login_and_bind_admin_role_return_none() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - get
    let response = app.get_application_by_id(&id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Application>(context.as_str());
    // application
    assert!(context_data.is_none());
}

#[tokio::test]
async fn get_application_by_valid_id_with_login_and_bind_admin_role_return_valid_application() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Application>(context.as_str()).unwrap();
    let stored_application_id = context_data.get_application_id().to_string();
    // application
    assert_ne!(&application_id, &stored_application_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - get
    let response = app.get_application_by_id(&stored_application_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Option<Application>>(context.as_str()).unwrap();
    // application
    assert!(context_data.is_some());
    let context_data = context_data.unwrap();
    assert_eq!(stored_application_id, context_data.get_application_id().to_string().as_str());
    assert_eq!(&msg_id, context_data.get_msg_id());
}

////////////////////////////////
///                          ///
///  DELETE APPLICATION BY ID ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn delete_application_by_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.delete_application_by_id(&id).await;
    
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
async fn delete_application_by_id_with_login_but_without_permission_return_no_application_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - delete
    let response = app.delete_application_by_id(&id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::NoPermissionError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::FORBIDDEN.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn delete_application_by_invalid_id_with_login_and_bind_admin_role_return_empty_success() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - delete
    let response = app.delete_application_by_id(&id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // application
    assert!(context_data.is_success());
}

#[tokio::test]
async fn delete_application_by_valid_id_with_login_and_bind_admin_role_return_empty_success_and_get_target_application_return_none() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Application>(context.as_str()).unwrap();
    let stored_application_id = context_data.get_application_id().to_string();
    // application
    assert_ne!(&application_id, &stored_application_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - delete
    let response = app.delete_application_by_id(&stored_application_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // application
    assert!(context_data.is_success());

    // Act 5 - get
    let response = app.get_application_by_id(&stored_application_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Application>(context.as_str());
    // application
    assert!(context_data.is_none());
}

////////////////////////////////
///                          ///
///  CHECK APPLICATION MSG ID ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn check_application_msg_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act
    let response = app.check_application_msg_id(&msg_id).await;
    
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
async fn check_application_msg_id_with_login_but_without_permission_return_no_application_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - check
    let response = app.check_application_msg_id(&msg_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::NoPermissionError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::FORBIDDEN.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn check_application_invalid_msg_id_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_application_msg_id(&msg_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let current_error = get_error_from_str(context.as_str()).unwrap();
    let target_error: Error = CommonError::InvalidInputError(anyhow::anyhow!("")).into();
    assert_eq!(StatusCode::BAD_REQUEST.as_u16(), current_error.status_code().as_u16());
    assert_eq!(target_error.msg_code, current_error.msg_code);
}

#[tokio::test]
async fn check_application_valid_msg_id_with_login_and_bind_admin_role_return_empty_success() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_application_msg_id(&msg_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // application
    assert!(context_data.is_success());
}

#[tokio::test]
async fn check_application_stored_msg_id_with_login_and_bind_admin_role_return_stored_application_id() {
    // Arrange
    let app = spawn_app().await;
    let application_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let role_msg_id = app.spawn_msg_id();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_application(&serde_json::json!({
        "applicationId": &application_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "roleMsgId": &role_msg_id,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Application>(context.as_str()).unwrap();
    let stored_application_id = context_data.get_application_id().to_string();
    // application
    assert_ne!(&application_id, &stored_application_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - check
    let response = app.check_application_msg_id(&msg_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<String>(context.as_str()).unwrap();
    // application
    assert_eq!(&stored_application_id, context_data.as_str());
}