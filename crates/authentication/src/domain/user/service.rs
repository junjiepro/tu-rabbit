//! 用户相关功能服务

use data_transmission::error::CommonError;
use sqlx::PgPool;
use uuid::Uuid;

use crate::connectors::RoleToBind;
use crate::domain::namespace::Namespace;
use crate::domain::user::dao;
use crate::domain::user::{User, UserListItem, RegisterUser};
use crate::domain::role::{service as RoleService, UserAndRole};

/// 检查用户名存在
#[tracing::instrument(name = "Service -> check username", skip(username, pool))]
pub async fn check_username(username: &str, pool: &PgPool) -> Result<Option<Uuid>, CommonError> {
    dao::check_username(username, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 保存新用户
#[tracing::instrument(name = "Service -> Store new user", skip(user, pool))]
pub async fn store_new_user(user: &RegisterUser, pool: &PgPool) -> Result<Uuid, CommonError> {
    store_new_user_action(user, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e).into())
}
async fn store_new_user_action(user: &RegisterUser, pool: &PgPool) -> Result<Uuid, anyhow::Error> {
    let mut transaction = pool.begin().await?;
    let uuid = dao::store_new_user(user, &mut transaction).await?;
    transaction.commit().await?;
    Ok(uuid)
}

/// 保存用户
#[tracing::instrument(
    name = "Service -> Update user",
    skip(user, pool)
)]
pub async fn update_user(user: &User, pool: &PgPool) -> Result<(), CommonError> {
    update_user_action(user, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e).into())
}
async fn update_user_action(user: &User, pool: &PgPool) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::update_user(user, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 保存用户密码
#[tracing::instrument(
    name = "Service -> Update user password",
    skip(user, user_id, pool)
)]
pub async fn update_user_password(user: &RegisterUser, user_id: &uuid::Uuid, pool: &PgPool) -> Result<(), CommonError> {
    update_user_password_action(user, user_id, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e).into())
}
async fn update_user_password_action(user: &RegisterUser, user_id: &uuid::Uuid, pool: &PgPool) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::update_user_password(user, user_id, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 获取所有用户
#[tracing::instrument(
    name = "Service -> Get users",
    skip(namespaces, pool)
)]
pub async fn get_users(
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<UserListItem>, CommonError> {
    dao::get_users(namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据ID获取用户
#[tracing::instrument(
    name = "Service -> Get user by id",
    skip(user_id, namespaces, pool)
)]
pub async fn get_user_by_id(
    user_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<UserListItem>, CommonError> {
    dao::get_user_by_id(user_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 获取角色下所有用户
#[tracing::instrument(
    name = "Service -> Get users by role_id",
    skip(role_id, namespaces, pool)
)]
pub async fn get_users_by_role_id(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<UserListItem>, CommonError> {
    dao::get_users_by_role_id(role_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 直接绑定用户与角色
#[tracing::instrument(
    name = "Service -> bind user with role",
    skip(role_to_bind, pool)
)]
pub async fn bind_user_with_role(
    user_id: &uuid::Uuid,
    role_to_bind: &RoleToBind,
    pool: &PgPool
) -> Result<(), CommonError> {
    // 最高权限
    let namespaces = vec![
        Namespace::has("").map_err(|e| CommonError::UnexpectedError(e.into()))?
    ];
    // 获取角色
    let role = RoleService::get_role_by_msg_id(&role_to_bind.role_msg_id, &namespaces, pool)
        .await?;
    // 绑定
    if let Some(role) = role {
        // 已有角色
        let roles = RoleService::get_roles_by_user_id(user_id, &namespaces, pool).await?;
        let r = roles.iter().find(|r| r.role_id == role.role_id);
        // 未有目标角色
        if r.is_none() {
            RoleService::insert_user_and_role(&UserAndRole {
                user_id: user_id.clone(),
                role_id: role.role_id,
            }, pool)
                .await
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}