//! 权限相关功能

use data_transmission::error::CommonError;
use data_transmission::data::DataEntity;
use sqlx::{PgPool, Transaction, Postgres};

use crate::domain::namespace::Namespace;
use crate::domain::permission::{dao, Permission, RoleAndPermission};

/// 获取所有权限
#[tracing::instrument(
    name = "Service -> Get permissions",
    skip(namespaces, pool)
)]
pub async fn get_permissions(
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Permission>, CommonError> {
    dao::get_permissions(namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据编号获取权限
#[tracing::instrument(
    name = "Service -> Get permission by id",
    skip(permission_id, namespaces, pool)
)]
pub async fn get_permission_by_id(
    permission_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Permission>, CommonError> {
    dao::get_permission_by_id(permission_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据消息编号获取权限
#[tracing::instrument(
    name = "Service -> Get permission by msg_id",
    skip(msg_id, namespaces, pool)
)]
pub async fn get_permission_by_msg_id(
    msg_id: &str,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Permission>, CommonError> {
    dao::get_permission_by_msg_id(msg_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据权限值获取权限
#[tracing::instrument(
    name = "Service -> Get permission by permission",
    skip(permission, namespaces, pool)
)]
pub async fn get_permission_by_permission(
    permission: &str,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Permission>, CommonError> {
    dao::get_permission_by_permission(permission, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据角色编号获取权限
#[tracing::instrument(
    name = "Service -> Get permissions by role_id ",
    skip(role_id, namespaces, pool)
)]
pub async fn get_permissions_by_role_id(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Permission>, CommonError> {
    dao::get_permissions_by_role_id(role_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 插入权限
#[tracing::instrument(
    name = "Service -> Insert permission",
    skip(permission, pool)
)]
pub async fn insert_permission(
    permission: &mut Permission,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<(), CommonError> {
    if Namespace::validate_required_namespace(
        namespaces,
        &permission.permission,
    )
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
        && Namespace::validate_msg(&permission.msg_id)
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
    {
        insert_permission_action(permission, pool)
            .await
            .map_err(|e| CommonError::UnexpectedError(e))
    } else {
        Err(
            CommonError::NoPermissionError(
                anyhow::anyhow!(format!("No Permission to insert permission with permission inner value: {}", &permission.permission)
            ))
        )
    }
}
async fn insert_permission_action(
    permission: &mut Permission,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    permission.pre_insert();
    dao::insert_permission(permission, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 更新权限
#[tracing::instrument(
    name = "Service -> Update permission",
    skip(permission, pool)
)]
pub async fn update_permission(
    permission: &mut Permission,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<(), CommonError> {
    if Namespace::validate_required_namespace(
        namespaces,
        &permission.permission
    )
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
        && Namespace::validate_msg(&permission.msg_id)
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
    {
        update_permission_action(permission, pool)
            .await
            .map_err(|e| CommonError::UnexpectedError(e))
    } else {
        Err(
            CommonError::NoPermissionError(
                anyhow::anyhow!(format!("No Permission to insert permission with inner value: {}", &permission.permission)
            ))
        )
    }
}
async fn update_permission_action(
    permission: &mut Permission,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    permission.pre_update();
    dao::update_permission(permission, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 根据编号删除权限
#[tracing::instrument(
    name = "Service -> Delete permission by id",
    skip(permission_id, namespaces, pool)
)]
pub async fn delete_permission_by_id(
    permission_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<(), CommonError> {
    delete_permission_by_id_action(permission_id, namespaces, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn delete_permission_by_id_action(
    permission_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::delete_role_and_permission_by_permission_id(permission_id, &mut transaction).await?;
    dao::delete_permission_by_id(permission_id, namespaces, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 插入角色、权限关系
#[tracing::instrument(
    name = "Service -> Insert role and permission",
    skip(role_and_permission, pool)
)]
pub async fn insert_role_and_permission(
    role_and_permission: &RoleAndPermission,
    pool: &PgPool
) -> Result<(), CommonError> {
    insert_role_and_permission_action(role_and_permission, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn insert_role_and_permission_action(
    role_and_permission: &RoleAndPermission,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::insert_role_and_permission(role_and_permission, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 保存角色、权限关系
#[tracing::instrument(
    name = "Service -> Save role and permission array",
    skip(role_and_permission_array, delete_role_and_permission_array, pool)
)]
pub async fn save_role_and_permission_array(
    role_and_permission_array: &Vec<RoleAndPermission>,
    delete_role_and_permission_array: &Vec<RoleAndPermission>,
    pool: &PgPool
) -> Result<(), CommonError> {
    save_role_and_permission_array_action(role_and_permission_array, delete_role_and_permission_array, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn save_role_and_permission_array_action(
    role_and_permission_array: &Vec<RoleAndPermission>,
    delete_role_and_permission_array: &Vec<RoleAndPermission>,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::delete_role_and_permission_array(delete_role_and_permission_array, &mut transaction).await?;
    dao::insert_role_and_permission_array(role_and_permission_array, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 删除角色、权限关系
#[tracing::instrument(
    name = "Service -> Delete role and permission",
    skip(role_and_permission, pool)
)]
pub async fn delete_role_and_permission(
    role_and_permission: &RoleAndPermission,
    pool: &PgPool
) -> Result<(), CommonError> {
    delete_role_and_permission_action(role_and_permission, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn delete_role_and_permission_action(
    role_and_permission: &RoleAndPermission,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::delete_role_and_permission(role_and_permission, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 根据角色编号删除角色、权限关系
#[tracing::instrument(
    name = "Service -> Delete role and permission relationships by role_id",
    skip(role_id, transaction)
)]
pub async fn delete_role_and_permission_by_role_id(
    role_id: &uuid::Uuid,
    transaction: &mut Transaction<'static, Postgres>,
) -> Result<(), anyhow::Error> {
    dao::delete_role_and_permission_by_role_id(role_id, transaction).await?;
    Ok(())
}

/// 根据用户编号获取权限
#[tracing::instrument(
    name = "Service -> Get permissions by user_id ",
    skip(user_id, pool)
)]
pub async fn get_permissions_by_user_id(
    user_id: &uuid::Uuid,
    pool: &PgPool
) -> Result<Vec<Permission>, CommonError> {
    dao::get_permissions_by_user_id(user_id, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}