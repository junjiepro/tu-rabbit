//! user
//! 
//! 用户

use crate::{domain::{user::{service, UserExt}, permission::CurrentUserPermissions, role::{UserAndRole, service as RoleService}}, connectors::inner::ApplicationPgPool};
use actix_web::{web, HttpResponse};
use data_transmission::{web::{build_http_response_data, build_http_response_error_data, build_http_response_empty_data}, error::CommonError};
use typed_session::TypedSession;

#[tracing::instrument(
    name = "Get users API",
    skip(session, pool)
)]
pub async fn get_users(
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            return match service::get_users(permission.get_permissions(), &pool.0).await {
                Ok(roles) => build_http_response_data(roles),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get users."))
    )
}

#[tracing::instrument(
    name = "Get users by role_id API",
    skip(role_id, session, pool)
)]
pub async fn get_users_by_role_id(
    role_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            return match service::get_users_by_role_id(&role_id, permission.get_permissions(), &pool.0).await {
                Ok(roles) => build_http_response_data(roles),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get users by role_id: {}.", &role_id))
    )
}

#[tracing::instrument(
    name = "update user API",
    skip(user_ext, session, pool)
)]
pub async fn update_user(
    user_ext: web::Json<UserExt>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            // 获取数据库里的用户
            let stored_user = service::get_user_by_id(&user_ext.user_id, current_permission.get_permissions(), &pool.get_ref().0).await;
            // 权限存在且有权限更新
            if let Ok(Some(_)) = stored_user {
                // 准备
                let user = user_ext.get_user();
                let user_and_role_array = user_ext.get_user_and_role_array();
                // 用户更新
                if user.is_some() {
                    let mut user = user.unwrap();
                    match service::update_user(&mut user, &pool.0).await {
                        Ok(_) => {},
                        Err(e) => {
                            return build_http_response_error_data(e);
                        },
                    };
                }
                // 用户角色更新
                if user_and_role_array.is_some() {
                    // 获取当前用户有权限编辑的角色
                    let stored_roles = RoleService::get_roles(current_permission.get_permissions(), &pool.0).await;
                    let stored_roles_under_user = RoleService::get_roles_by_user_id(&user_ext.user_id, current_permission.get_permissions(), &pool.0).await;
                    if let (Ok(stored_roles), Ok(stored_roles_under_user)) = (stored_roles, stored_roles_under_user) {
                        let stored_roles_under_user_len = stored_roles_under_user.len();
                        // 保存目标
                        let user_and_role_array = user_and_role_array.unwrap();
                        // 有权限的可保存目标
                        let user_and_role_array: Vec<UserAndRole> = user_and_role_array
                            .into_iter()
                            .filter(|user_and_role| 
                                stored_roles
                                    .iter()
                                    .any(|role| role.role_id == user_and_role.role_id)
                            )
                            .collect();
                        // 有权限的待插入目标
                        let insert_user_and_role_array = if stored_roles_under_user_len > 0 {
                            user_and_role_array.clone()
                                .into_iter()
                                .filter(|user_and_role|
                                    !stored_roles_under_user
                                        .iter()
                                        .any(|role| role.role_id == user_and_role.role_id)
                                )
                                .collect()
                        } else {
                            user_and_role_array.clone()
                        };
                        // 有权限的待删除目标
                        let delete_user_and_role_array = if stored_roles_under_user_len > 0 {
                            stored_roles_under_user
                                .into_iter()
                                .filter(|role| 
                                    !user_and_role_array
                                        .iter()
                                        .any(|user_and_role| role.role_id == user_and_role.role_id)
                                )
                                .map(|role| UserAndRole { role_id: role.role_id, user_id: user_ext.user_id.clone() })
                                .collect()
                        } else {
                            vec![]
                        };
                        match RoleService::save_user_and_role_array(&insert_user_and_role_array, &delete_user_and_role_array,  &pool.0).await {
                            Ok(_) => {},
                            Err(e) => {
                                return build_http_response_error_data(e);
                            },
                        };
                    }
                }
                
                return build_http_response_empty_data();
            }
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to update user."))
    )
}