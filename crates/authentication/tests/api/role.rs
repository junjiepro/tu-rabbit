use authentication::{test_helpers::spawn_app, domain::{role::Role, permission::Permission}};
use data_transmission::{error::{Error, authentication::ValidateError, CommonError}, web::{get_error_from_str, get_data_from_str, get_empty_http_data_wraper_from_str}};
use reqwest::StatusCode;

////////////////////////////////
///                          ///
///        GET ROLES         ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_roles_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    
    // Act
    let response = app.get_roles().await;
    
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
async fn get_roles_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - get
    let response = app.get_roles().await;
    
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
async fn get_roles_with_login_and_bind_admin_role_return_role_array() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - get
    let response = app.get_roles().await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    // Administrator role
    assert_eq!(1, context_data.len());
}

////////////////////////////////
///                          ///
///         ADD ROLE         ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn add_role_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();
    
    // Act
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
async fn add_role_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
async fn add_valid_role_with_login_and_bind_admin_role_return_valid_role() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    // role
    assert_ne!(role_id, context_data.get_role_id().to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());
}

#[tokio::test]
async fn add_invalid_msg_id_role_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = uuid::Uuid::new_v4().to_string();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
async fn add_invalid_namespace_role_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = uuid::Uuid::new_v4().to_string();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
async fn add_stored_role_with_login_and_bind_admin_role_return_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;

    // Act 4 - add again
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
///       UPDATE ROLE        ///
///                          ///
////////////////////////////////

    
#[tokio::test]
async fn update_role_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();
    
    // Act
    let response = app.update_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
async fn update_role_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - add
    let response = app.update_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
async fn update_valid_role_with_login_and_bind_admin_role_return_success() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id().to_string();
    // role
    assert_ne!(&role_id, &stored_role_id);
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = app.spawn_msg_id();

    // Act 4 - update
    let response = app.update_role(&serde_json::json!({
        "roleId": &stored_role_id,
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 5 - get
    let response = app.get_role_by_id(&stored_role_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Option<Role>>(context.as_str()).unwrap();
    // role
    assert!(context_data.is_some());
    let context_data = context_data.unwrap();
    assert_eq!(&new_msg_id, context_data.get_msg_id());
}

#[tokio::test]
async fn update_invalid_msg_id_role_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id().to_string();
    // role
    assert_ne!(&role_id, &stored_role_id);
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = uuid::Uuid::new_v4().to_string();

    // Act 4 - update
    let response = app.update_role(&serde_json::json!({
        "roleId": &stored_role_id,
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
async fn update_invalid_namespace_role_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id().to_string();
    // role
    assert_ne!(&role_id, &stored_role_id);
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_namespace = uuid::Uuid::new_v4().to_string();

    // Act 4 - update
    let response = app.update_role(&serde_json::json!({
        "roleId": &stored_role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &new_namespace,
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
async fn update_not_stored_role_with_login_and_bind_admin_role_return_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - update
    let response = app.update_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
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
async fn update_valid_role_add_user_add_permission_with_login_and_bind_admin_role_return_success() {
    // Arrange
    let app = spawn_app().await;

    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    let permission_id = uuid::Uuid::nil().to_string();
    let permission_msg_id = app.spawn_msg_id();
    let permission_default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let permission_remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id();
    // role
    assert_ne!(&role_id, &stored_role_id.to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = app.spawn_msg_id();

    // Act 4 - add permission
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &permission_msg_id,
        "defaultMsg": &permission_default_msg,
        "permission": &permission,
        "remarks": &permission_remarks,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&permission_msg_id, context_data.get_msg_id());

    // Act 5 - update
    let response = app.update_role(&serde_json::json!({
        "roleId": &stored_role_id.to_string(),
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
        "userIds": &vec![app.test_user.user_id.clone()],
        "permissionIds": &vec![&stored_permission_id],
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 6 - get role by user id
    let response = app.get_roles_by_user_id(&app.test_user.user_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|r| &r.get_role_id() == &stored_role_id && &r.get_msg_id() == &new_msg_id));

    // Act 7 - get role by permission id
    let response = app.get_roles_by_permission_id(&stored_permission_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|r| &r.get_role_id() == &stored_role_id && &r.get_msg_id() == &new_msg_id));
}

#[tokio::test]
async fn update_valid_role_delete_user_delete_permission_with_login_and_bind_admin_role_return_success() {
    // Arrange
    let app = spawn_app().await;

    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    let permission_id = uuid::Uuid::nil().to_string();
    let permission_msg_id = app.spawn_msg_id();
    let permission_default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let permission_remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id();
    // role
    assert_ne!(&role_id, &stored_role_id.to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = app.spawn_msg_id();

    // Act 4 - add permission
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &permission_msg_id,
        "defaultMsg": &permission_default_msg,
        "permission": &permission,
        "remarks": &permission_remarks,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&permission_msg_id, context_data.get_msg_id());

    // Act 5 - update
    let response = app.update_role(&serde_json::json!({
        "roleId": &stored_role_id.to_string(),
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
        "userIds": &vec![app.test_user.user_id.clone()],
        "permissionIds": &vec![&stored_permission_id],
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 6 - get role by user id
    let response = app.get_roles_by_user_id(&app.test_user.user_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|r| &r.get_role_id() == &stored_role_id && &r.get_msg_id() == &new_msg_id));

    // Act 7 - get role by permission id
    let response = app.get_roles_by_permission_id(&stored_permission_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|r| &r.get_role_id() == &stored_role_id && &r.get_msg_id() == &new_msg_id));

    // Act 8 - update to reduce user and permission
    let response = app.update_role(&serde_json::json!({
        "roleId": &stored_role_id.to_string(),
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
        "userIds": &Vec::<String>::new(),
        "permissionIds": &Vec::<String>::new(),
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 9 - get role by user id
    let response = app.get_roles_by_user_id(&app.test_user.user_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(!context_data.iter().any(|r| &r.get_role_id() == &stored_role_id && &r.get_msg_id() == &new_msg_id));

    // Act 10 - get role by permission id
    let response = app.get_roles_by_permission_id(&stored_permission_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(!context_data.iter().any(|r| &r.get_role_id() == &stored_role_id && &r.get_msg_id() == &new_msg_id));
}

////////////////////////////////
///                          ///
///      GET ROLE BY ID      ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_role_by_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.get_role_by_id(&id).await;
    
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
async fn get_role_by_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - get
    let response = app.get_role_by_id(&id).await;
    
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
async fn get_role_by_invalid_id_with_login_and_bind_admin_role_return_none() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - get
    let response = app.get_role_by_id(&id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str());
    // role
    assert!(context_data.is_none());
}

#[tokio::test]
async fn get_role_by_valid_id_with_login_and_bind_admin_role_return_valid_role() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id().to_string();
    // role
    assert_ne!(&role_id, &stored_role_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - get
    let response = app.get_role_by_id(&stored_role_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Option<Role>>(context.as_str()).unwrap();
    // role
    assert!(context_data.is_some());
    let context_data = context_data.unwrap();
    assert_eq!(stored_role_id, context_data.get_role_id().to_string().as_str());
    assert_eq!(&msg_id, context_data.get_msg_id());
}

////////////////////////////////
///                          ///
///    DELETE ROLE BY ID     ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn delete_role_by_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.delete_role_by_id(&id).await;
    
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
async fn delete_role_by_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - delete
    let response = app.delete_role_by_id(&id).await;
    
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
async fn delete_role_by_invalid_id_with_login_and_bind_admin_role_return_empty_success() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - delete
    let response = app.delete_role_by_id(&id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // role
    assert!(context_data.is_success());
}

#[tokio::test]
async fn delete_role_by_valid_id_with_login_and_bind_admin_role_return_empty_success_and_get_target_role_return_none() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id().to_string();
    // role
    assert_ne!(&role_id, &stored_role_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - delete
    let response = app.delete_role_by_id(&stored_role_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // role
    assert!(context_data.is_success());

    // Act 5 - get
    let response = app.get_role_by_id(&stored_role_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str());
    // role
    assert!(context_data.is_none());
}

////////////////////////////////
///                          ///
///    CHECK ROLE MSG ID     ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn check_role_msg_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act
    let response = app.check_role_msg_id(&msg_id).await;
    
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
async fn check_role_msg_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - check
    let response = app.check_role_msg_id(&msg_id).await;
    
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
async fn check_role_invalid_msg_id_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_role_msg_id(&msg_id).await;
    
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
async fn check_role_valid_msg_id_with_login_and_bind_admin_role_return_empty_success() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_role_msg_id(&msg_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // role
    assert!(context_data.is_success());
}

#[tokio::test]
async fn check_role_stored_msg_id_with_login_and_bind_admin_role_return_stored_role_id() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id().to_string();
    // role
    assert_ne!(&role_id, &stored_role_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - check
    let response = app.check_role_msg_id(&msg_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<String>(context.as_str()).unwrap();
    // role
    assert_eq!(&stored_role_id, context_data.as_str());
}

////////////////////////////////
///                          ///
///   CHECK ROLE NAMESPACE   ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn check_role_namespace_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let namespace = app.spawn_namespace();

    // Act
    let response = app.check_role_namespace(&namespace).await;
    
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
async fn check_role_namespace_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let namespace = app.spawn_namespace();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - check
    let response = app.check_role_namespace(&namespace).await;
    
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
async fn check_role_invalid_namespace_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let namespace = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_role_namespace(&namespace).await;
    
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
async fn check_role_valid_namespace_with_login_and_bind_admin_role_return_empty_success() {
    // Arrange
    let app = spawn_app().await;
    let namespace = app.spawn_namespace();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_role_namespace(&namespace).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // role
    assert!(context_data.is_success());
}

////////////////////////////////
///                          ///
///   GET ROLES BY USER ID   ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_roles_by_user_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let user_id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.get_roles_by_user_id(&user_id).await;
    
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
async fn get_roles_by_user_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let user_id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - check
    let response = app.get_roles_by_user_id(&user_id).await;
    
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
async fn get_roles_by_user_id_with_login_and_bind_admin_role_return_roles() {
    // Arrange
    let app = spawn_app().await;

    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    let permission_id = uuid::Uuid::nil().to_string();
    let permission_msg_id = app.spawn_msg_id();
    let permission_default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let permission_remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id();
    // role
    assert_ne!(&role_id, &stored_role_id.to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = app.spawn_msg_id();

    // Act 4 - add permission
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &permission_msg_id,
        "defaultMsg": &permission_default_msg,
        "permission": &permission,
        "remarks": &permission_remarks,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&permission_msg_id, context_data.get_msg_id());

    // Act 5 - update
    let response = app.update_role(&serde_json::json!({
        "roleId": &stored_role_id.to_string(),
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
        "userIds": &vec![app.test_user.user_id.clone()],
        "permissionIds": &vec![&stored_permission_id],
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 6 - get role by user id
    let response = app.get_roles_by_user_id(&app.test_user.user_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|r| &r.get_role_id() == &stored_role_id && &r.get_msg_id() == &new_msg_id));
}

////////////////////////////////
///                          ///
///GET ROLES BY PERMISSION ID///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_roles_by_permission_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.get_roles_by_permission_id(&permission_id).await;
    
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
async fn get_roles_by_permission_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - check
    let response = app.get_roles_by_permission_id(&permission_id).await;
    
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
async fn get_roles_by_permission_id_with_login_and_bind_admin_role_return_roles() {
    // Arrange
    let app = spawn_app().await;

    let role_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let namespace = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    let permission_id = uuid::Uuid::nil().to_string();
    let permission_msg_id = app.spawn_msg_id();
    let permission_default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let permission_remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_role(&serde_json::json!({
        "roleId": &role_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Role>(context.as_str()).unwrap();
    let stored_role_id = context_data.get_role_id();
    // role
    assert_ne!(&role_id, &stored_role_id.to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = app.spawn_msg_id();

    // Act 4 - add permission
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &permission_msg_id,
        "defaultMsg": &permission_default_msg,
        "permission": &permission,
        "remarks": &permission_remarks,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&permission_msg_id, context_data.get_msg_id());

    // Act 5 - update
    let response = app.update_role(&serde_json::json!({
        "roleId": &stored_role_id.to_string(),
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "namespace": &namespace,
        "remarks": &remarks,
        "userIds": &vec![app.test_user.user_id.clone()],
        "permissionIds": &vec![&stored_permission_id],
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 6 - get role by permission id
    let response = app.get_roles_by_permission_id(&stored_permission_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|r| &r.get_role_id() == &stored_role_id && &r.get_msg_id() == &new_msg_id));
}