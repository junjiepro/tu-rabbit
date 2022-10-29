//! 角色相关功能

use data_transmission::error::CommonError;
use data_transmission::data::DataEntity;
use sqlx::{PgPool, Transaction, Postgres};

use crate::domain::namespace::Namespace;
use crate::domain::permission::service::delete_role_and_permission_by_role_id;
use crate::domain::role::{dao, Role, UserAndRole};

/// 获取所有角色
#[tracing::instrument(
    name = "Service -> Get roles",
    skip(namespaces, pool)
)]
pub async fn get_roles(
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Role>, CommonError> {
    dao::get_roles(namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据编号获取角色
#[tracing::instrument(
    name = "Service -> Get role by id",
    skip(role_id, namespaces, pool)
)]
pub async fn get_role_by_id(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Role>, CommonError> {
    dao::get_role_by_id(role_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据消息编号获取角色
#[tracing::instrument(
    name = "Service -> Get role by msg_id",
    skip(msg_id, namespaces, pool)
)]
pub async fn get_role_by_msg_id(
    msg_id: &str,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Role>, CommonError> {
    dao::get_role_by_msg_id(msg_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据用户编号获取角色
#[tracing::instrument(
    name = "Service -> Get roles by user_id ",
    skip(user_id, namespaces, pool)
)]
pub async fn get_roles_by_user_id(
    user_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Role>, CommonError> {
    dao::get_roles_by_user_id(user_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据权限编号获取角色
#[tracing::instrument(
    name = "Service -> Get roles by permission_id ",
    skip(permission_id, namespaces, pool)
)]
pub async fn get_roles_by_permission_id(
    permission_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Role>, CommonError> {
    dao::get_roles_by_permission_id(permission_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 插入角色
#[tracing::instrument(
    name = "Service -> Insert role",
    skip(role, pool)
)]
pub async fn insert_role(
    role: &mut Role,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<(), CommonError> {
    if Namespace::validate_required_namespace(
        namespaces,
        &role.namespace
    )
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
        && Namespace::validate_msg(&role.msg_id)
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
    {
        insert_role_action(role, pool)
            .await
            .map_err(|e| CommonError::UnexpectedError(e))
    } else {
        Err(
            CommonError::NoPermissionError(
                anyhow::anyhow!(format!("No Permission to insert role with namespace value: {}", &role.namespace)
            ))
        )
    }
}
async fn insert_role_action(
    role: &mut Role,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    role.pre_insert();
    dao::insert_role(role, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 更新角色
#[tracing::instrument(
    name = "Service -> Update role",
    skip(role, namespaces, pool)
)]
pub async fn update_role(
    role: &mut Role,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<(), CommonError> {
    if Namespace::validate_required_namespace(
        namespaces,
        &role.namespace
    )
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
        && Namespace::validate_msg(&role.msg_id)
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
    {
        update_role_action(role, pool)
            .await
            .map_err(|e| CommonError::UnexpectedError(e))
    } else {
        Err(
            CommonError::NoPermissionError(
                anyhow::anyhow!(format!("No Permission to insert role with namespace value: {}", &role.namespace)
            ))
        )
    }
}
async fn update_role_action(
    role: &mut Role,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    role.pre_update();
    dao::update_role(role, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 根据编号删除角色
#[tracing::instrument(
    name = "Service -> Delete role by id",
    skip(role_id, namespaces, pool)
)]
pub async fn delete_role_by_id(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<(), CommonError> {
    delete_role_by_id_action(role_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn delete_role_by_id_action(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::delete_user_and_role_by_role_id(role_id, &mut transaction).await?;
    delete_role_and_permission_by_role_id(role_id, &mut transaction).await?;
    dao::delete_role_by_id(role_id, namespaces, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 插入用户、角色关系
#[tracing::instrument(
    name = "Service -> Insert user and role",
    skip(user_and_role, pool)
)]
pub async fn insert_user_and_role(
    user_and_role: &UserAndRole,
    pool: &PgPool
) -> Result<(), CommonError> {
    insert_user_and_role_action(user_and_role, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn insert_user_and_role_action(
    user_and_role: &UserAndRole,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::insert_user_and_role(user_and_role, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 保存用户、角色关系
#[tracing::instrument(
    name = "Service -> Save user and role array",
    skip(user_and_role_array, delete_user_and_role_array, pool)
)]
pub async fn save_user_and_role_array(
    user_and_role_array: &Vec<UserAndRole>,
    delete_user_and_role_array: &Vec<UserAndRole>,
    pool: &PgPool
) -> Result<(), CommonError> {
    save_user_and_role_array_action(user_and_role_array, delete_user_and_role_array, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn save_user_and_role_array_action(
    user_and_role_array: &Vec<UserAndRole>,
    delete_user_and_role_array: &Vec<UserAndRole>,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::delete_user_and_role_array(delete_user_and_role_array, &mut transaction).await?;
    dao::insert_user_and_role_array(user_and_role_array, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 删除用户、角色关系
#[tracing::instrument(
    name = "Service -> Delete user and role",
    skip(user_and_role, pool)
)]
pub async fn delete_user_and_role(
    user_and_role: &UserAndRole,
    pool: &PgPool
) -> Result<(), CommonError> {
    delete_user_and_role_action(user_and_role, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn delete_user_and_role_action(
    user_and_role: &UserAndRole,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::delete_user_and_role(user_and_role, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 根据用户编号删除用户、角色关系
#[tracing::instrument(
    name = "Service -> Delete user and role relationships by user_id",
    skip(user_id, transaction)
)]
pub async fn delete_user_and_role_by_user_id(
    user_id: &uuid::Uuid,
    transaction: &mut Transaction<'static, Postgres>,
) -> Result<(), anyhow::Error> {
    dao::delete_user_and_role_by_user_id(user_id, transaction).await?;
    Ok(())
}
