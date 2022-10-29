//! permission
//! 
//! 权限

use crate::{domain::{permission::{service, Permission, PermissionExt, RoleAndPermission, CurrentUserPermissions}, role::{service as RoleService}, namespace::Namespace}, connectors::inner::ApplicationPgPool};
use actix_web::{web, HttpResponse};
use data_transmission::{web::{build_http_response_data, build_http_response_error_data, build_http_response_empty_data}, error::CommonError};
use typed_session::TypedSession;

#[tracing::instrument(
    name = "Get permissions API",
    skip(session, pool)
)]
pub async fn get_permissions(
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::get_permissions(current_permission.get_permissions(), &pool.0).await {
                Ok(permissions) => build_http_response_data(permissions),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get permissions."))
    )
}

#[tracing::instrument(
    name = "Add permission API",
    skip(permission, session, pool)
)]
pub async fn add_permission(
    mut permission: web::Json<Permission>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::insert_permission(&mut permission, current_permission.get_permissions(), &pool.0).await {
                Ok(_) => build_http_response_data(permission.into_inner()),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to add permission."))
    )
}

#[tracing::instrument(
    name = "update permission API",
    skip(permission_ext, session, pool)
)]
pub async fn update_permission(
    permission_ext: web::Json<PermissionExt>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            // 获取数据库里的权限
            let stored_permission = service::get_permission_by_id(&permission_ext.permission_id, current_permission.get_permissions(), &pool.get_ref().0).await;
            // 权限存在且有权限更新
            if let Ok(Some(_)) = stored_permission {
                // 准备
                let permission = permission_ext.get_permission();
                let role_and_permission_array = permission_ext.get_role_and_permission_array();
                // 权限更新
                if permission.is_some() {
                    let mut permission = permission.unwrap();
                    match service::update_permission(&mut permission, current_permission.get_permissions(), &pool.0).await {
                        Ok(_) => {},
                        Err(e) => {
                            return build_http_response_error_data(e);
                        },
                    };
                }
                // 权限角色更新
                if role_and_permission_array.is_some() {
                    // 获取当前用户有权限编辑的角色
                    let stored_roles = RoleService::get_roles(current_permission.get_permissions(), &pool.0).await;
                    let stored_roles_under_permission = RoleService::get_roles_by_permission_id(&permission_ext.permission_id, current_permission.get_permissions(), &pool.0).await;
                    if let (Ok(stored_roles), Ok(stored_roles_under_permission)) = (stored_roles, stored_roles_under_permission) {
                        let stored_roles_under_permission_len = stored_roles_under_permission.len();
                        // 保存目标
                        let role_and_permission_array = role_and_permission_array.unwrap();
                        // 有权限的可保存目标
                        let role_and_permission_array: Vec<RoleAndPermission> = role_and_permission_array
                            .into_iter()
                            .filter(|role_and_permission| 
                                stored_roles
                                    .iter()
                                    .any(|role| role.role_id == role_and_permission.role_id)
                            )
                            .collect();
                        // 有权限的待插入目标
                        let insert_role_and_permission_array = if stored_roles_under_permission_len > 0 {
                            role_and_permission_array.clone()
                                .into_iter()
                                .filter(|role_and_permission|
                                    !stored_roles_under_permission
                                        .iter()
                                        .any(|role| role.role_id == role_and_permission.role_id)
                                )
                                .collect()
                        } else {
                            role_and_permission_array.clone()
                        };
                        // 有权限的待删除目标
                        let delete_role_and_permission_array = if stored_roles_under_permission_len > 0 {
                            stored_roles_under_permission
                                .into_iter()
                                .filter(|role| 
                                    !role_and_permission_array
                                        .iter()
                                        .any(|role_and_permission| role.role_id == role_and_permission.role_id)
                                )
                                .map(|role| RoleAndPermission { role_id: role.role_id, permission_id: permission_ext.permission_id.clone() })
                                .collect()
                        } else {
                            vec![]
                        };
                        match service::save_role_and_permission_array(&insert_role_and_permission_array, &delete_role_and_permission_array,  &pool.0).await {
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
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to update permission."))
    )
}

#[tracing::instrument(
    name = "get permission by id API",
    skip(permission_id, session, pool)
)]
pub async fn get_permission_by_id(
    permission_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::get_permission_by_id(&permission_id, current_permission.get_permissions(), &pool.get_ref().0).await {
                Ok(permission) => build_http_response_data(permission),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get permission."))
    )
}

#[tracing::instrument(
    name = "Get permissions by role_id API",
    skip(role_id, session, pool)
)]
pub async fn get_permissions_by_role_id(
    role_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::get_permissions_by_role_id(&role_id, current_permission.get_permissions(), &pool.0).await {
                Ok(permissions) => build_http_response_data(permissions),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get permissions by role_id: {}.", &role_id))
    )
}

#[tracing::instrument(
    name = "delete permission by id API",
    skip(permission_id, session, pool)
)]
pub async fn delete_permission_by_id(
    permission_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::delete_permission_by_id(&permission_id, current_permission.get_permissions(), &pool.get_ref().0).await {
                Ok(_) => build_http_response_empty_data(),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to delete permission."))
    )
}

#[tracing::instrument(
    name = "check permission msg id API",
    skip(msg_id, session, pool)
)]
pub async fn check_permission_msg_id(
    msg_id: web::Path<String>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        // 管理员
        if current_permission.is_admin() {
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
            return match service::get_permission_by_msg_id(&msg_id, &namespaces, &pool.get_ref().0).await {
                Ok(Some(permission)) => build_http_response_data(permission.get_permission_id().to_string()),
                Ok(None) => build_http_response_empty_data(),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to check permission msg id."))
    )
}

#[tracing::instrument(
    name = "check permission inner value API",
    skip(permission, session, pool)
)]
pub async fn check_permission_value(
    permission: web::Path<String>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        // 管理员
        if current_permission.is_admin() {
            // 校验 permission
            match Namespace::validate_value(&permission) {
                Ok(_) => {},
                Err(e) => {
                    return build_http_response_error_data(
                        CommonError::InvalidInputError(e.into())
                    );
                },
            }
            // 创建可见所有命名空间值的命名空间
            let n = match Namespace::has("") {
                Ok(n) => n,
                Err(e) => {
                    return build_http_response_error_data(
                        CommonError::UnexpectedError(e.into())
                    );
                }
            };
            let namespaces = vec![n];
            return match service::get_permission_by_permission(&permission, &namespaces, &pool.get_ref().0).await {
                Ok(Some(permission)) => build_http_response_data(permission.get_permission_id().to_string()),
                Ok(None) => build_http_response_empty_data(),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to check permission inner value."))
    )
}