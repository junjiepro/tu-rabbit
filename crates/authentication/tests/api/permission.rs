use authentication::{test_helpers::spawn_app, domain::{permission::Permission, role::Role}};
use data_transmission::{error::{Error, authentication::ValidateError, CommonError}, web::{get_error_from_str, get_data_from_str, get_empty_http_data_wraper_from_str}};
use reqwest::StatusCode;

////////////////////////////////
///                          ///
///     GET PERMISSIONS      ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_permissions_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    
    // Act
    let response = app.get_permissions().await;
    
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
async fn get_permissions_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - get
    let response = app.get_permissions().await;
    
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
async fn get_permissions_with_login_and_bind_admin_role_return_permission_array() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - get
    let response = app.get_permissions().await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Permission>>(context.as_str()).unwrap();
    // admin permission
    assert_eq!(1, context_data.len());
}


////////////////////////////////
///                          ///
///      ADD PERMISSION      ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn add_permission_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();
    
    // Act
    let response = app.add_permission(&serde_json::json!({
        "permissioneId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
async fn add_permission_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
async fn add_valid_permission_with_login_and_bind_admin_role_return_valid_permission() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    // permission
    assert_ne!(permission_id, context_data.get_permission_id().to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());
}

#[tokio::test]
async fn add_invalid_msg_id_permission_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = uuid::Uuid::new_v4().to_string();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
async fn add_invalid_inner_value_permission_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = uuid::Uuid::new_v4().to_string();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
async fn add_stored_permission_with_login_and_bind_admin_role_return_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;

    // Act 4 - add again
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
///    UPDATE PERMISSION     ///
///                          ///
////////////////////////////////

    
#[tokio::test]
async fn update_permission_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();
    
    // Act
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
async fn update_permission_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - add
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
async fn update_valid_permission_with_login_and_bind_admin_role_return_success() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = app.spawn_msg_id();

    // Act 4 - update
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &stored_permission_id,
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 5 - get
    let response = app.get_permission_by_id(&stored_permission_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Option<Permission>>(context.as_str()).unwrap();
    // permission
    assert!(context_data.is_some());
    let context_data = context_data.unwrap();
    assert_eq!(stored_permission_id, context_data.get_permission_id().to_string().as_str());
    assert_eq!(&new_msg_id, context_data.get_msg_id());
}

#[tokio::test]
async fn update_invalid_msg_id_permission_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_msg_id = uuid::Uuid::new_v4().to_string();

    // Act 4 - update
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &stored_permission_id,
        "msgId": &new_msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
async fn update_invalid_value_permission_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Arrange
    let new_permission = uuid::Uuid::new_v4().to_string();

    // Act 4 - update
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &stored_permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &new_permission,
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
async fn update_not_stored_permission_with_login_and_bind_admin_role_return_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - update
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
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
async fn update_valid_permission_add_role_with_login_and_bind_admin_role_return_success() {
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
    let new_permission_msg_id = app.spawn_msg_id();

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
    let stored_permission_id = context_data.get_permission_id();
    // permission
    assert_ne!(&permission_id, &stored_permission_id.to_string());
    assert_eq!(&permission_msg_id, context_data.get_msg_id());

    // Act 5 - update
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &stored_permission_id.to_string(),
        "msgId": &new_permission_msg_id,
        "defaultMsg": &permission_default_msg,
        "permission": &permission,
        "remarks": &permission_remarks,
        "roleIds": &vec![&stored_role_id.to_string()],
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 6 - get permissions by role id
    let response = app.get_permissions_by_role_id(&stored_role_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Permission>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|p| &p.get_permission_id() == &stored_permission_id && &p.get_msg_id() == &new_permission_msg_id));
}

#[tokio::test]
async fn update_valid_permission_delete_role_with_login_and_bind_admin_role_return_success() {
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
    let new_permission_msg_id = app.spawn_msg_id();

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
    let stored_permission_id = context_data.get_permission_id();
    // permission
    assert_ne!(&permission_id, &stored_permission_id.to_string());
    assert_eq!(&permission_msg_id, context_data.get_msg_id());

    // Act 5 - update
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &stored_permission_id.to_string(),
        "msgId": &new_permission_msg_id,
        "defaultMsg": &permission_default_msg,
        "permission": &permission,
        "remarks": &permission_remarks,
        "roleIds": &vec![&stored_role_id.to_string()],
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 6 - get permissions by role id
    let response = app.get_permissions_by_role_id(&stored_role_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Permission>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|p| &p.get_permission_id() == &stored_permission_id && &p.get_msg_id() == &new_permission_msg_id));

    // Act 7 - update to reduce role
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &stored_permission_id.to_string(),
        "msgId": &new_permission_msg_id,
        "defaultMsg": &permission_default_msg,
        "permission": &permission,
        "remarks": &permission_remarks,
        "roleIds": &Vec::<String>::new(),
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 8 - get permissions by role id
    let response = app.get_permissions_by_role_id(&stored_role_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Permission>>(context.as_str()).unwrap();
    assert!(!context_data.iter().any(|p| &p.get_permission_id() == &stored_permission_id && &p.get_msg_id() == &new_permission_msg_id));
}

////////////////////////////////
///                          ///
///   GET PERMISSION BY ID   ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_permission_by_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.get_permission_by_id(&id).await;
    
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
async fn get_permission_by_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - get
    let response = app.get_permission_by_id(&id).await;
    
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
async fn get_permission_by_invalid_id_with_login_and_bind_admin_role_return_none() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - get
    let response = app.get_permission_by_id(&id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str());
    // permission
    assert!(context_data.is_none());
}

#[tokio::test]
async fn get_permission_by_valid_id_with_login_and_bind_admin_role_return_valid_permission() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - get
    let response = app.get_permission_by_id(&stored_permission_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Option<Permission>>(context.as_str()).unwrap();
    // permission
    assert!(context_data.is_some());
    let context_data = context_data.unwrap();
    assert_eq!(stored_permission_id, context_data.get_permission_id().to_string().as_str());
    assert_eq!(&msg_id, context_data.get_msg_id());
}

////////////////////////////////
///                          ///
///  DELETE PERMISSION BY ID ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn delete_permission_by_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.delete_permission_by_id(&id).await;
    
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
async fn delete_permission_by_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - delete
    let response = app.delete_permission_by_id(&id).await;
    
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
async fn delete_permission_by_invalid_id_with_login_and_bind_admin_role_return_empty_success() {
    // Arrange
    let app = spawn_app().await;
    let id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - delete
    let response = app.delete_permission_by_id(&id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // permission
    assert!(context_data.is_success());
}

#[tokio::test]
async fn delete_permission_by_valid_id_with_login_and_bind_admin_role_return_empty_success_and_get_target_permission_return_none() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - delete
    let response = app.delete_permission_by_id(&stored_permission_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // permission
    assert!(context_data.is_success());

    // Act 5 - get
    let response = app.get_permission_by_id(&stored_permission_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str());
    // permission
    assert!(context_data.is_none());
}

////////////////////////////////
///                          ///
///  CHECK PERMISSION MSG ID ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn check_permission_msg_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act
    let response = app.check_permission_msg_id(&msg_id).await;
    
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
async fn check_permission_msg_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - check
    let response = app.check_permission_msg_id(&msg_id).await;
    
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
async fn check_permission_invalid_msg_id_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_permission_msg_id(&msg_id).await;
    
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
async fn check_permission_valid_msg_id_with_login_and_bind_admin_role_return_empty_success() {
    // Arrange
    let app = spawn_app().await;
    let msg_id = app.spawn_msg_id();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_permission_msg_id(&msg_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // permission
    assert!(context_data.is_success());
}

#[tokio::test]
async fn check_permission_stored_msg_id_with_login_and_bind_admin_role_return_stored_permission_id() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - check
    let response = app.check_permission_msg_id(&msg_id).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<String>(context.as_str()).unwrap();
    // permission
    assert_eq!(&stored_permission_id, context_data.as_str());
}

////////////////////////////////
///                          ///
///  CHECK PERMISSION VALUE  ///
///                          ///
////////////////////////////////

#[tokio::test]
async fn check_permission_value_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission = app.spawn_namespace();

    // Act
    let response = app.check_permission_value(&permission).await;
    
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
async fn check_permission_value_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission = app.spawn_namespace();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - check
    let response = app.check_permission_value(&permission).await;
    
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
async fn check_permission_invalid_value_with_login_and_bind_admin_role_return_invalid_error_response() {
    // Arrange
    let app = spawn_app().await;
    let permission = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_permission_value(&permission).await;
    
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
async fn check_permission_valid_value_with_login_and_bind_admin_role_return_empty_success() {
    // Arrange
    let app = spawn_app().await;
    let permission = app.spawn_namespace();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - check
    let response = app.check_permission_value(&permission).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    // permission
    assert!(context_data.is_success());
}

#[tokio::test]
async fn check_permission_stored_value_with_login_and_bind_admin_role_return_stored_permission_id() {
    // Arrange
    let app = spawn_app().await;
    let permission_id = uuid::Uuid::nil().to_string();
    let msg_id = app.spawn_msg_id();
    let default_msg = uuid::Uuid::new_v4().to_string();
    let permission = app.spawn_namespace();
    let remarks = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - add
    let response = app.add_permission(&serde_json::json!({
        "permissionId": &permission_id,
        "msgId": &msg_id,
        "defaultMsg": &default_msg,
        "permission": &permission,
        "remarks": &remarks,
    })).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Permission>(context.as_str()).unwrap();
    let stored_permission_id = context_data.get_permission_id().to_string();
    // permission
    assert_ne!(&permission_id, &stored_permission_id);
    assert_eq!(&msg_id, context_data.get_msg_id());
    
    // Act 4 - check
    let response = app.check_permission_value(&permission).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<String>(context.as_str()).unwrap();
    // permission
    assert_eq!(&stored_permission_id, context_data.as_str());
}


////////////////////////////////
///                          ///
///GET PERMISSIONS BY ROLE ID///
///                          ///
////////////////////////////////

#[tokio::test]
async fn get_permissions_by_role_id_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::new_v4().to_string();

    // Act
    let response = app.get_permissions_by_role_id(&role_id).await;
    
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
async fn get_permissions_by_role_id_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let role_id = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - check
    let response = app.get_permissions_by_role_id(&role_id).await;
    
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
async fn get_permissions_by_role_id_with_login_and_bind_admin_role_return_permissions() {
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
    let new_permission_msg_id = app.spawn_msg_id();

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
    let stored_permission_id = context_data.get_permission_id();
    // permission
    assert_ne!(&permission_id, &stored_permission_id.to_string());
    assert_eq!(&permission_msg_id, context_data.get_msg_id());

    // Act 5 - update
    let response = app.update_permission(&serde_json::json!({
        "permissionId": &stored_permission_id.to_string(),
        "msgId": &new_permission_msg_id,
        "defaultMsg": &permission_default_msg,
        "permission": &permission,
        "remarks": &permission_remarks,
        "roleIds": &vec![&stored_role_id.to_string()],
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 6 - get permissions by role id
    let response = app.get_permissions_by_role_id(&stored_role_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Permission>>(context.as_str()).unwrap();
    assert!(context_data.iter().any(|p| &p.get_permission_id() == &stored_permission_id && &p.get_msg_id() == &new_permission_msg_id));
}