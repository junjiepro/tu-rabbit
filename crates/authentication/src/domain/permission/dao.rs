//! 权限相关数据库操作
//! 

use anyhow::Context;
use chrono::prelude::*;
use sqlx::{Transaction, Postgres, PgPool};

use crate::domain::namespace::Namespace;
use crate::domain::permission::{Permission, RoleAndPermission};

/// 获取所有权限
#[tracing::instrument(
    name = "DAO -> Get permissions",
    skip(namespaces, pool)
)]
pub async fn get_permissions(
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Permission>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT permission_id, msg_id, default_msg, permission, remarks
        FROM permissions
        WHERE permission_id IS NOT NULL
        "#);
        let offset = 1;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql.push_str("ORDER BY msg_id ");
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_all(pool)
        .await
        .context("Failed to perform a query to retrieve stored permissions.")?;

    Ok(row)
}

/// 根据编号获取权限
#[tracing::instrument(
    name = "DAO -> Get permission by id",
    skip(permission_id, namespaces, pool)
)]
pub async fn get_permission_by_id(
    permission_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Permission>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT permission_id, msg_id, default_msg, permission, remarks
        FROM permissions
        WHERE permission_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql.push_str("ORDER BY msg_id ");
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql).bind(permission_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_optional(pool)
        .await
        .context(format!("Failed to perform a query to retrieve stored permission by permission_id: {}.", permission_id))?;

    Ok(row)
}

/// 根据消息编号获取权限
#[tracing::instrument(
    name = "DAO -> Get permission by msg_id",
    skip(msg_id, namespaces, pool)
)]
pub async fn get_permission_by_msg_id(
    msg_id: &str,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Permission>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT permission_id, msg_id, default_msg, permission, remarks
        FROM permissions
        WHERE msg_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql).bind(msg_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_optional(pool)
        .await
        .context(format!("Failed to perform a query to retrieve stored permission by msg_id: {}.", msg_id))?;

    Ok(row)
}

/// 根据权限值获取权限
#[tracing::instrument(
    name = "DAO -> Get permission by permission value",
    skip(permission, namespaces, pool)
)]
pub async fn get_permission_by_permission(
    permission: &str,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Permission>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT permission_id, msg_id, default_msg, permission, remarks
        FROM permissions
        WHERE permission = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql).bind(permission),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_optional(pool)
        .await
        .context(format!("Failed to perform a query to retrieve stored permission by permission inner value: {}.", permission))?;

    Ok(row)
}

/// 根据角色编号获取权限
#[tracing::instrument(
    name = "DAO -> Get permissions by role_id ",
    skip(role_id, namespaces, pool)
)]
pub async fn get_permissions_by_role_id(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Permission>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT p.permission_id, p.msg_id, p.default_msg, p.permission, p.remarks
        FROM permissions p
        JOIN role_and_permission r_p ON p.permission_id = r_p.permission_id
        WHERE r_p.role_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((p.permission LIKE CONCAT(${}, ':%') OR p.permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (p.permission LIKE CONCAT(${}, ':%') OR p.permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (p.permission LIKE CONCAT(${}, ':%') OR p.permission = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (p.permission LIKE CONCAT(${}, ':%') OR p.permission = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql.push_str("ORDER BY p.msg_id ");
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql).bind(role_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_all(pool)
        .await
        .context(format!("Failed to perform a query to retrieve stored permissions by role_id: {}.", role_id))?;

    Ok(row)
}

/// 插入权限
#[tracing::instrument(
    name = "DAO -> Insert permission",
    skip(permission, transaction)
)]
pub async fn insert_permission(
    permission: &Permission,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        "INSERT INTO permissions (permission_id, msg_id, default_msg, permission, remarks)
        VALUES ($1, $2, $3, $4, $5)",
        permission.permission_id,
        permission.msg_id,
        permission.default_msg,
        permission.permission,
        permission.remarks,
    )
    .execute(transaction)
    .await
    .context("Failed to store new permission.")?;

    Ok(())
}

/// 更新权限
#[tracing::instrument(
    name = "DAO -> Update permission",
    skip(permission, transaction)
)]
pub async fn update_permission(
    permission: &Permission,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        "UPDATE permissions
        SET 
            msg_id = $1,
            default_msg = $2,
            permission = $3,
            remarks = $4,
            update_at = $5
        WHERE permission_id = $6",
        permission.msg_id,
        permission.default_msg,
        permission.permission,
        permission.remarks,
        Local::now().naive_local(),
        permission.permission_id,
    )
    .execute(transaction)
    .await
    .context("Failed to update stored permission.")?;

    Ok(())
}

/// 根据编号删除权限
#[tracing::instrument(
    name = "DAO -> Delete permission by id",
    skip(permission_id, namespaces, transaction)
)]
pub async fn delete_permission_by_id(
    permission_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        DELETE FROM permissions
        WHERE permission_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (permission LIKE CONCAT(${}, ':%') OR permission = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql
    };
    // 注入参数并执行
    namespaces
        .iter()
        .fold(
            sqlx::query(&sql).bind(permission_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .execute(transaction)
        .await
        .context(format!("Failed to perform a query to delete stored permission by permission_id: {}.", permission_id))?;

    Ok(())
}

/// 插入角色、权限关系
#[tracing::instrument(
    name = "DAO -> Insert role and permission",
    skip(role_and_permission, transaction)
)]
pub async fn insert_role_and_permission(
    role_and_permission: &RoleAndPermission,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"INSERT INTO role_and_permission (role_id, permission_id)
        VALUES ($1, $2) "#,
        role_and_permission.role_id,
        role_and_permission.permission_id,
    )
    .execute(transaction)
    .await
    .context("Failed to store new role_and_permission relationship.")?;

    Ok(())
}

/// 批量插入角色、权限关系
#[tracing::instrument(
    name = "DAO -> Batch insert role and permission",
    skip(role_and_permission_array, transaction)
)]
pub async fn insert_role_and_permission_array(
    role_and_permission_array: &Vec<RoleAndPermission>,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    let len = role_and_permission_array.len();
    if len == 0 {
        return Ok(());
    }
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"INSERT INTO role_and_permission (role_id, permission_id) VALUES "#);
        let mut index = 1;
        role_and_permission_array
            .iter()
            .enumerate()
            .for_each(|(i, _)| {
                if i == len - 1 {
                    sql.push_str(&format!(r#"(${}, ${}) "#, index, index + 1));
                } else {
                    sql.push_str(&format!(r#"(${}, ${}), "#, index, index + 1));
                }
                index = index + 2;
            });
        sql
    };
    // 注入参数并执行
    role_and_permission_array
        .iter()
        .fold(
            sqlx::query(&sql),
            |query, role_and_permission| query.bind(role_and_permission.role_id).bind(role_and_permission.permission_id)
        )
        .execute(transaction)
        .await
        .context("Failed to store new role_and_permission relationship.")?;

    Ok(())
}

/// 删除角色、权限关系
#[tracing::instrument(
    name = "DAO -> Delete role and permission",
    skip(role_and_permission, transaction)
)]
pub async fn delete_role_and_permission(
    role_and_permission: &RoleAndPermission,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"DELETE FROM role_and_permission
        WHERE role_id = $1
        AND permission_id = $2"#,
        role_and_permission.role_id,
        role_and_permission.permission_id,
    )
    .execute(transaction)
    .await
    .context("Failed to delete stored role_and_permission relationship.")?;

    Ok(())
}

/// 批量删除角色、权限关系
#[tracing::instrument(
    name = "DAO -> Batch delete role and permission",
    skip(role_and_permission_array, transaction)
)]
pub async fn delete_role_and_permission_array(
    role_and_permission_array: &Vec<RoleAndPermission>,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    let len = role_and_permission_array.len();
    if len == 0 {
        return Ok(());
    }
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"DELETE FROM role_and_permission
        WHERE "#);
        let mut index = 1;
        role_and_permission_array
            .iter()
            .enumerate()
            .for_each(|(i, _)| {
                if i == 0 {
                    sql.push_str(&format!(r#"
                        (role_id = ${}
                        AND permission_id = ${})
                        "#, index, index + 1)
                    );
                } else {
                    sql.push_str(&format!(r#"
                        OR (role_id = ${}
                        AND permission_id = ${})
                        "#, index, index + 1)
                    );
                }
                
                index = index + 2;
            });
        sql
    };
    // 注入参数并执行
    role_and_permission_array
        .iter()
        .fold(
            sqlx::query(&sql),
            |query, role_and_permission| query.bind(role_and_permission.role_id).bind(role_and_permission.permission_id)
        )
        .execute(transaction)
        .await
        .context("Failed to delete stored role_and_permission relationship.")?;
    
    Ok(())
}

/// 根据角色编号删除角色、权限关系
#[tracing::instrument(
    name = "DAO -> Delete role and permission relationships by role_id",
    skip(role_id, transaction)
)]
pub async fn delete_role_and_permission_by_role_id(
    role_id: &uuid::Uuid,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"DELETE FROM role_and_permission
        WHERE role_id = $1"#,
        role_id,
    )
    .execute(transaction)
    .await
    .context("Failed to delete stored role_and_permission relationship.")?;

    Ok(())
}

/// 根据权限编号删除角色、权限关系
#[tracing::instrument(
    name = "DAO -> Delete role and permission relationships by permission_id",
    skip(permission_id, transaction)
)]
pub async fn delete_role_and_permission_by_permission_id(
    permission_id: &uuid::Uuid,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"DELETE FROM role_and_permission
        WHERE permission_id = $1"#,
        permission_id,
    )
    .execute(transaction)
    .await
    .context("Failed to delete stored role_and_permission relationship.")?;

    Ok(())
}

/// 根据用户编号获取权限
#[tracing::instrument(
    name = "DAO -> Get permissions by user_id ",
    skip(user_id, pool)
)]
pub async fn get_permissions_by_user_id(
    user_id: &uuid::Uuid,
    pool: &PgPool
) -> Result<Vec<Permission>, anyhow::Error> {
    sqlx::query_as!(
        Permission,
        r#"SELECT p.permission_id, p.msg_id, p.default_msg, p.permission, p.remarks
        FROM permissions p
        JOIN role_and_permission r_p ON p.permission_id = r_p.permission_id
        JOIN user_and_role u_r ON r_p.role_id = u_r.role_id
        WHERE u_r.user_id = $1
        ORDER BY p.msg_id"#,
        user_id,
    )
    .fetch_all(pool)
    .await
    .context("Failed to delete stored role_and_permission relationship.")
}