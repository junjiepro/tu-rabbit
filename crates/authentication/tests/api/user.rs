use authentication::{test_helpers::spawn_app, domain::{user::UserListItem, role::Role}};
use data_transmission::{error::{Error, authentication::ValidateError, CommonError}, web::{get_error_from_str, get_data_from_str, get_empty_http_data_wraper_from_str}};
use reqwest::StatusCode;

#[tokio::test]
async fn get_users_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    
    // Act
    let response = app.get_users().await;
    
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
async fn get_users_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - get
    let response = app.get_users().await;
    
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
async fn get_users_with_login_and_bind_admin_role_return_user_array() {
    // Arrange
    let app = spawn_app().await;

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - get
    let response = app.get_users().await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<UserListItem>>(context.as_str()).unwrap();
    // admin user and test user
    assert_eq!(2, context_data.len());
}

////////////////////////////////
///                          ///
///       UPDATE USER        ///
///                          ///
////////////////////////////////

/**
 * user::update_valid_user_add_role_with_login_and_bind_admin_role_return_success
    user::update_valid_user_delete_role_with_login_and_bind_admin_role_return_success
    user::update_valid_user_with_login_and_bind_admin_role_return_success
 */
#[tokio::test]
async fn update_user_without_login_return_unauthorized_error_response() {
    // Arrange
    let app = spawn_app().await;
    let name = uuid::Uuid::new_v4().to_string();
    
    // Act
    let response = app.update_user(&serde_json::json!({
        "userId": &app.test_user.user_id,
        "name": &name,
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
async fn update_user_with_login_but_without_permission_return_no_permission_error_response() {
    // Arrange
    let app = spawn_app().await;
    let name = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;
    
    // Act 2 - add
    let response = app.update_user(&serde_json::json!({
        "userId": &app.test_user.user_id,
        "name": &name,
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
async fn update_valid_user_with_login_and_bind_admin_role_return_success() {
    // Arrange
    let app = spawn_app().await;
    let name = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;

    // Act 3 - update
    let response = app.update_user(&serde_json::json!({
        "userId": &app.test_user.user_id,
        "name": &name,
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 4 - get
    let response = app.get_users().await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<UserListItem>>(context.as_str()).unwrap();
    // users
    assert!(context_data.iter().any(|r| &r.get_user_id() == &app.test_user.user_id && r.get_name().unwrap() == &name));
}

#[tokio::test]
async fn update_not_stored_user_with_login_and_bind_admin_role_return_error_response() {
    // Arrange
    let app = spawn_app().await;
    let user_id = uuid::Uuid::new_v4().to_string();
    let name = uuid::Uuid::new_v4().to_string();

    // Act 1 - login (validte credentials)
    app.test_user.login(&app).await;

    // Act 2 - bind admin role
    app.bind_current_user_with_admin_role().await;
    
    // Act 3 - update
    let response = app.update_user(&serde_json::json!({
        "userId": &user_id,
        "name": &name,
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
async fn update_valid_user_add_role_with_login_and_bind_admin_role_return_success() {
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
    let stored_role_id = context_data.get_role_id();
    // role
    assert_ne!(&role_id, &stored_role_id.to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Act 4 - get role by user id
    let response = app.get_roles_by_user_id(&app.test_user.user_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    // admin role
    let mut role_ids: Vec<uuid::Uuid> = context_data
        .iter()
        .map(|role| role.get_role_id())
        .collect();

    // Arrange
    let name = uuid::Uuid::new_v4().to_string();
    role_ids.push(stored_role_id.clone());

    // Act 5 - update
    let response = app.update_user(&serde_json::json!({
        "userId": &app.test_user.user_id,
        "name": &name,
        "roleIds": &role_ids,
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
    assert!(context_data.iter().any(|r| &r.get_role_id() == &stored_role_id));
}

#[tokio::test]
async fn update_valid_user_delete_role_with_login_and_bind_admin_role_return_success() {
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
    let stored_role_id = context_data.get_role_id();
    // role
    assert_ne!(&role_id, &stored_role_id.to_string());
    assert_eq!(&msg_id, context_data.get_msg_id());

    // Act 4 - get role by user id
    let response = app.get_roles_by_user_id(&app.test_user.user_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    // admin role
    let mut role_ids: Vec<uuid::Uuid> = context_data
        .iter()
        .map(|role| role.get_role_id())
        .collect();

    // Arrange
    let name = uuid::Uuid::new_v4().to_string();
    role_ids.push(stored_role_id.clone());

    // Act 5 - update
    let response = app.update_user(&serde_json::json!({
        "userId": &app.test_user.user_id,
        "name": &name,
        "roleIds": &role_ids,
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
    assert!(context_data.iter().any(|r| &r.get_role_id() == &stored_role_id));

    // Act 7 - update to reduce role
    let response = app.update_user(&serde_json::json!({
        "userId": &app.test_user.user_id,
        "name": &name,
        "roleIds": &role_ids[..1],
    })).await;

    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_empty_http_data_wraper_from_str(context.as_str()).unwrap();
    assert!(context_data.is_success());

    // Act 8 - get role by user id
    let response = app.get_roles_by_user_id(&app.test_user.user_id.to_string()).await;
    
    // Assert - status code - ok
    assert_eq!(200, response.status().as_u16());
    
    // Assert - context
    let context = response.text().await.unwrap().clone();
    let context_data = get_data_from_str::<Vec<Role>>(context.as_str()).unwrap();
    assert!(!context_data.iter().any(|r| &r.get_role_id() == &stored_role_id));
}