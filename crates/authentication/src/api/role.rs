//! role
//! 
//! 角色

use crate::{domain::{role::{service, Role, RoleExt, UserAndRole}, permission::{service as PermissionService, CurrentUserPermissions, RoleAndPermission}, user::service as UserService, namespace::Namespace}, connectors::inner::ApplicationPgPool};
use actix_web::{web, HttpResponse};
use data_transmission::{web::{build_http_response_data, build_http_response_error_data, build_http_response_empty_data}, error::CommonError};
use typed_session::TypedSession;

#[tracing::instrument(
    name = "Get roles API",
    skip(session, pool)
)]
pub async fn get_roles(
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            return match service::get_roles(permission.get_permissions(), &pool.0).await {
                Ok(roles) => build_http_response_data(roles),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get roles."))
    )
}

#[tracing::instrument(
    name = "Add role API",
    skip(role, session, pool)
)]
pub async fn add_role(
    mut role: web::Json<Role>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            return match service::insert_role(&mut role, permission.get_permissions(), &pool.0).await {
                Ok(_) => build_http_response_data(role.into_inner()),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to add role."))
    )
}

#[tracing::instrument(
    name = "update role API",
    skip(role_ext, session, pool)
)]
pub async fn update_role(
    role_ext: web::Json<RoleExt>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            // 获取数据库里的角色
            let stored_role = service::get_role_by_id(&role_ext.role_id, permission.get_permissions(), &pool.get_ref().0).await;
            // 角色存在且有权限更新
            if let Ok(Some(_)) = stored_role {
                // 准备
                let role = role_ext.get_role();
                let user_and_role_array = role_ext.get_user_and_role_array();
                let role_and_permission_array = role_ext.get_role_and_permission_array();
                // 角色更新
                if role.is_some() {
                    let mut role = role.unwrap();
                    match service::update_role(&mut role, permission.get_permissions(), &pool.0).await {
                        Ok(_) => {},
                        Err(e) => {
                            return build_http_response_error_data(e);
                        },
                    };
                }
                // 角色用户更新
                if user_and_role_array.is_some() {
                    // 获取当前用户有权限编辑的用户
                    let stored_users = UserService::get_users(permission.get_permissions(), &pool.0).await;
                    let stored_users_under_role = UserService::get_users_by_role_id(&role_ext.role_id, permission.get_permissions(), &pool.0).await;
                    if let (Ok(stored_users), Ok(stored_users_under_role)) = (stored_users, stored_users_under_role) {
                        let stored_users_under_role_len = stored_users_under_role.len();
                        // 保存目标
                        let user_and_role_array = user_and_role_array.unwrap();
                        // 有权限的可保存目标
                        let user_and_role_array: Vec<UserAndRole> = user_and_role_array
                            .into_iter()
                            .filter(|user_and_role| 
                                stored_users
                                    .iter()
                                    .any(|user| user.user_id == user_and_role.user_id)
                            )
                            .collect();
                        // 有权限的待插入目标
                        let insert_user_and_role_array = if stored_users_under_role_len > 0 {
                            user_and_role_array.clone()
                                .into_iter()
                                .filter(|user_and_role| 
                                    !stored_users_under_role
                                        .iter()
                                        .any(|user| user.user_id == user_and_role.user_id)
                                )
                                .collect()
                        } else {
                            user_and_role_array.clone()
                        };
                        // 有权限的待删除目标
                        let delete_user_and_role_array = if stored_users_under_role_len > 0 {
                            stored_users_under_role
                                .into_iter()
                                .filter(|user| 
                                    !user_and_role_array
                                        .iter()
                                        .any(|user_and_role| user.user_id == user_and_role.user_id)
                                )
                                .map(|user| UserAndRole { user_id: user.user_id, role_id: role_ext.role_id.clone() })
                                .collect()
                        } else {
                            vec![]
                        };
                        match service::save_user_and_role_array(&insert_user_and_role_array, &delete_user_and_role_array,  &pool.0).await {
                            Ok(_) => {},
                            Err(e) => {
                                return build_http_response_error_data(e);
                            },
                        };
                    }
                }
                // 角色权限更新
                if role_and_permission_array.is_some() {
                    // 获取当前用户有权限编辑的权限
                    let stored_permissions = PermissionService::get_permissions(permission.get_permissions(), &pool.0).await;
                    let stored_permissions_under_role = PermissionService::get_permissions_by_role_id(&role_ext.role_id, permission.get_permissions(), &pool.0).await;
                    if let (Ok(stored_permissions), Ok(stored_permissions_under_role)) = (stored_permissions, stored_permissions_under_role) {
                        let stored_permissions_under_role_len = stored_permissions_under_role.len();
                        // 保存目标
                        let role_and_permission_array = role_and_permission_array.unwrap();
                        // 有权限的可保存目标
                        let role_and_permission_array: Vec<RoleAndPermission> = role_and_permission_array
                            .into_iter()
                            .filter(|role_and_permission| 
                                stored_permissions
                                    .iter()
                                    .any(|permission| permission.permission_id == role_and_permission.permission_id)
                            )
                            .collect();
                        // 有权限的待插入目标
                        let insert_role_and_permission_array = if stored_permissions_under_role_len > 0 {
                            role_and_permission_array.clone()
                                .into_iter()
                                .filter(|role_and_permission| 
                                    !stored_permissions_under_role
                                        .iter()
                                        .any(|permission| permission.permission_id == role_and_permission.permission_id)
                                )
                                .collect()
                        } else {
                            role_and_permission_array.clone()
                        };
                        // 有权限的待删除目标
                        let delete_role_and_permission_array = if stored_permissions_under_role_len > 0 {
                            stored_permissions_under_role
                                .into_iter()
                                .filter(|permission| 
                                    !role_and_permission_array
                                        .iter()
                                        .any(|role_and_permission| permission.permission_id == role_and_permission.permission_id)
                                )
                                .map(|permission| RoleAndPermission { permission_id: permission.permission_id, role_id: role_ext.role_id.clone() })
                                .collect()
                        } else {
                            vec![]
                        };
                        match PermissionService::save_role_and_permission_array(&insert_role_and_permission_array, &delete_role_and_permission_array,  &pool.0).await {
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
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to update role."))
    )
}

#[tracing::instrument(
    name = "get role by id API",
    skip(role_id, session, pool)
)]
pub async fn get_role_by_id(
    role_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            return match service::get_role_by_id(&role_id, permission.get_permissions(), &pool.get_ref().0).await {
                Ok(role) => build_http_response_data(role),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get role."))
    )
}

#[tracing::instrument(
    name = "get roles by user_id API",
    skip(user_id, session, pool)
)]
pub async fn get_roles_by_user_id(
    user_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            return match service::get_roles_by_user_id(&user_id, permission.get_permissions(), &pool.get_ref().0).await {
                Ok(roles) => build_http_response_data(roles),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get roles by user_id: {}.", &user_id))
    )
}

#[tracing::instrument(
    name = "get roles by permission_id API",
    skip(permission_id, session, pool)
)]
pub async fn get_roles_by_permission_id(
    permission_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            return match service::get_roles_by_permission_id(&permission_id, permission.get_permissions(), &pool.get_ref().0).await {
                Ok(roles) => build_http_response_data(roles),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get roles by permission_id: {}.", &permission_id))
    )
}

#[tracing::instrument(
    name = "delete role by id API",
    skip(role_id, session, pool)
)]
pub async fn delete_role_by_id(
    role_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            return match service::delete_role_by_id(&role_id, permission.get_permissions(), &pool.get_ref().0).await {
                Ok(_) => build_http_response_empty_data(),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to delete role."))
    )
}

#[tracing::instrument(
    name = "check role msg id API",
    skip(msg_id, session, pool)
)]
pub async fn check_role_msg_id(
    msg_id: web::Path<String>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        // 管理员
        if permission.is_admin() {
            // 校验 msg_id
            match Namespace::validate_msg(&msg_id) {
                Ok(_) => {},
                Err(e) => {
                    return build_http_response_error_data(
                        CommonError::InvalidInputError(e.into())
                    );
                },
            }
            // 创建可见所有命名空间值的命名空间
            let namespace = match Namespace::has("") {
                Ok(namespace) => namespace,
                Err(e) => {
                    return build_http_response_error_data(
                        CommonError::UnexpectedError(e.into())
                    );
                }
            };
            let namespaces = vec![namespace];
            return match service::get_role_by_msg_id(&msg_id, &namespaces, &pool.get_ref().0).await {
                Ok(Some(role)) => build_http_response_data(role.get_role_id().to_string()),
                Ok(None) => build_http_response_empty_data(),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to check role msg id."))
    )
}

#[tracing::instrument(
    name = "check role namespace API",
    skip(namespace, session)
)]
pub async fn check_role_namespace(
    namespace: web::Path<String>,
    session: TypedSession,
) -> HttpResponse {
    if let Ok(Some(permission)) = session.get::<CurrentUserPermissions>() {
        if permission.get_permissions().len() > 0 {
            // 校验权限
            match Namespace::validate_required_namespace(permission.get_permissions(), &namespace) {
                Ok(has) => {
                    if has {
                        return build_http_response_empty_data();
                    }
                },
                Err(e) => {
                    return build_http_response_error_data(
                        CommonError::InvalidInputError(e.into())
                    );
                },
            }
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to check role namespace."))
    )
}