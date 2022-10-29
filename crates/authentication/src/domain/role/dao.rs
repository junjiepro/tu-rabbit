//! 角色相关数据库操作
//! 

use anyhow::Context;
use sqlx::{Transaction, Postgres, PgPool};
use chrono::prelude::*;

use crate::domain::namespace::Namespace;
use crate::domain::role::{Role, UserAndRole};

/// 获取所有角色
#[tracing::instrument(
    name = "DAO -> Get roles",
    skip(namespaces, pool)
)]
pub async fn get_roles(
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Role>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT role_id, msg_id, default_msg, namespace, remarks
        FROM roles
        WHERE role_id IS NOT NULL
        "#);
        let offset = 1;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1 {
                    sql.push_str(&format!(r#"AND ((namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql.push_str("ORDER BY msg_id");
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
        .context("Failed to perform a query to retrieve stored roles.")?;

    Ok(row)
}

/// 根据编号获取角色
#[tracing::instrument(
    name = "DAO -> Get role by id",
    skip(role_id, namespaces, pool)
)]
pub async fn get_role_by_id(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Role>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT role_id, msg_id, default_msg, namespace, remarks
        FROM roles
        WHERE role_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1 {
                    sql.push_str(&format!(r#"AND ((namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1 {
                    sql.push_str(&format!(r#"AND (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql).bind(role_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_optional(pool)
        .await
        .context(format!("Failed to perform a query to retrieve stored role by role_id: {}.", role_id))?;

    Ok(row)
}

/// 根据消息编号获取角色
#[tracing::instrument(
    name = "DAO -> Get role by msg_id",
    skip(msg_id, namespaces, pool)
)]
pub async fn get_role_by_msg_id(
    msg_id: &str,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<Role>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT role_id, msg_id, default_msg, namespace, remarks
        FROM roles
        WHERE msg_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1 {
                    sql.push_str(&format!(r#"AND ((namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1 {
                    sql.push_str(&format!(r#"AND (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
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
        .context(format!("Failed to perform a query to retrieve stored role by msg_id: {}.", msg_id))?;

    Ok(row)
}

/// 根据用户编号获取角色
#[tracing::instrument(
    name = "DAO -> Get roles by user_id ",
    skip(user_id, namespaces, pool)
)]
pub async fn get_roles_by_user_id(
    user_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Role>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT r.role_id, r.msg_id, r.default_msg, r.namespace, r.remarks
        FROM roles r
        JOIN user_and_role u_r ON r.role_id = u_r.role_id
        WHERE u_r.user_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((r.namespace LIKE CONCAT(${}, ':%') OR r.namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (r.namespace LIKE CONCAT(${}, ':%') OR r.namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (r.namespace LIKE CONCAT(${}, ':%') OR r.namespace = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (r.namespace LIKE CONCAT(${}, ':%') OR r.namespace = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql.push_str("ORDER BY r.msg_id");
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql).bind(user_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_all(pool)
        .await
        .context(format!("Failed to perform a query to retrieve stored roles by user_id: {}.", user_id))?;

    Ok(row)
}

/// 根据权限编号获取角色
#[tracing::instrument(
    name = "DAO -> Get roles by permission_id ",
    skip(permission_id, namespaces, pool)
)]
pub async fn get_roles_by_permission_id(
    permission_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<Role>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        SELECT r.role_id, r.msg_id, r.default_msg, r.namespace, r.remarks
        FROM roles r
        JOIN role_and_permission r_p ON r.role_id = r_p.role_id
        WHERE r_p.permission_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((r.namespace LIKE CONCAT(${}, ':%') OR r.namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (r.namespace LIKE CONCAT(${}, ':%') OR r.namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (r.namespace LIKE CONCAT(${}, ':%') OR r.namespace = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (r.namespace LIKE CONCAT(${}, ':%') OR r.namespace = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql.push_str("ORDER BY r.msg_id");
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql).bind(permission_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_all(pool)
        .await
        .context(format!("Failed to perform a query to retrieve stored roles by permission_id: {}.", permission_id))?;

    Ok(row)
}

/// 插入角色
#[tracing::instrument(
    name = "DAO -> Insert role",
    skip(role, transaction)
)]
pub async fn insert_role(
    role: &Role,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        "INSERT INTO roles (role_id, msg_id, default_msg, namespace, remarks)
        VALUES ($1, $2, $3, $4, $5)",
        role.role_id,
        role.msg_id,
        role.default_msg,
        role.namespace,
        role.remarks,
    )
    .execute(transaction)
    .await
    .context("Failed to store new role.")?;

    Ok(())
}

/// 更新角色
#[tracing::instrument(
    name = "DAO -> Update role",
    skip(role, transaction)
)]
pub async fn update_role(
    role: &Role,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        "UPDATE roles
        SET 
            msg_id = $1,
            default_msg = $2,
            namespace = $3,
            remarks = $4,
            update_at = $5
        WHERE role_id = $6",
        role.msg_id,
        role.default_msg,
        role.namespace,
        role.remarks,
        Local::now().naive_local(),
        role.role_id,
    )
    .execute(transaction)
    .await
    .context("Failed to update stored role.")?;

    Ok(())
}

/// 根据编号删除角色
#[tracing::instrument(
    name = "DAO -> Delete role by id",
    skip(role_id, namespaces, transaction)
)]
pub async fn delete_role_by_id(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"
        DELETE FROM roles
        WHERE role_id = $1
        "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1{
                    sql.push_str(&format!(r#"AND ((namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(r#"AND (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                } else if index == len - 1 {
                    sql.push_str(&format!(r#"OR (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '')) "#, i, i, i));
                } else {
                    sql.push_str(&format!(r#"OR (namespace LIKE CONCAT(${}, ':%') OR namespace = ${} OR ${} = '') "#, i, i, i));
                }
            });
        sql
    };
    // 注入参数并执行
    namespaces
        .iter()
        .fold(
            sqlx::query(&sql).bind(role_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .execute(transaction)
        .await
        .context(format!("Failed to perform a query to delete stored role by role_id: {}.", role_id))?;

    Ok(())
}

/// 插入用户、角色关系
#[tracing::instrument(
    name = "DAO -> Insert user and role",
    skip(user_and_role, transaction)
)]
pub async fn insert_user_and_role(
    user_and_role: &UserAndRole,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"INSERT INTO user_and_role (user_id, role_id)
        VALUES ($1, $2) "#,
        user_and_role.user_id,
        user_and_role.role_id,
    )
    .execute(transaction)
    .await
    .context("Failed to store new user_and_role relationship.")?;

    Ok(())
}

/// 批量插入用户、角色关系
#[tracing::instrument(
    name = "DAO -> Batch insert user and role",
    skip(user_and_role_array, transaction)
)]
pub async fn insert_user_and_role_array(
    user_and_role_array: &Vec<UserAndRole>,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    let len = user_and_role_array.len();
    if len == 0 {
        return Ok(());
    }
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"INSERT INTO user_and_role (user_id, role_id) VALUES "#);
        let mut index = 1;
        user_and_role_array
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
    user_and_role_array
        .iter()
        .fold(
            sqlx::query(&sql),
            |query, user_and_role| query.bind(user_and_role.user_id).bind(user_and_role.role_id)
        )
        .execute(transaction)
        .await
        .context("Failed to store new user_and_role relationship.")?;

    Ok(())
}

/// 删除用户、角色关系
#[tracing::instrument(
    name = "DAO -> Delete user and role",
    skip(user_and_role, transaction)
)]
pub async fn delete_user_and_role(
    user_and_role: &UserAndRole,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"DELETE FROM user_and_role
        WHERE user_id = $1
        AND role_id = $2"#,
        user_and_role.user_id,
        user_and_role.role_id,
    )
    .execute(transaction)
    .await
    .context("Failed to delete stored user_and_role relationship.")?;

    Ok(())
}

/// 批量删除用户、角色关系
#[tracing::instrument(
    name = "DAO -> Batch delete user and role",
    skip(user_and_role_array, transaction)
)]
pub async fn delete_user_and_role_array(
    user_and_role_array: &Vec<UserAndRole>,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    let len = user_and_role_array.len();
    if len == 0 {
        return Ok(());
    }
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"DELETE FROM user_and_role
        WHERE "#);
        let mut index = 1;
        user_and_role_array
            .iter()
            .enumerate()
            .for_each(|(i, _)| {
                if i == 0 {
                    sql.push_str(&format!(r#"
                        (user_id = ${}
                        AND role_id = ${})
                        "#, index, index + 1)
                    );
                } else {
                    sql.push_str(&format!(r#"
                        OR (user_id = ${}
                        AND role_id = ${})
                        "#, index, index + 1)
                    );
                }
                
                index = index + 2;
            });
        sql
    };
    // 注入参数并执行
    user_and_role_array
        .iter()
        .fold(
            sqlx::query(&sql),
            |query, user_and_role| query.bind(user_and_role.user_id).bind(user_and_role.role_id)
        )
        .execute(transaction)
        .await
        .context("Failed to delete stored user_and_role relationship.")?;
    
    Ok(())
}

/// 根据用户编号删除用户、角色关系
#[tracing::instrument(
    name = "DAO -> Delete user and role relationships by user_id",
    skip(user_id, transaction)
)]
pub async fn delete_user_and_role_by_user_id(
    user_id: &uuid::Uuid,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"DELETE FROM user_and_role
        WHERE user_id = $1"#,
        user_id,
    )
    .execute(transaction)
    .await
    .context("Failed to delete stored user_and_role relationship.")?;

    Ok(())
}

/// 根据角色编号删除用户、角色关系
#[tracing::instrument(
    name = "DAO -> Delete user and role relationships by role_id",
    skip(role_id, transaction)
)]
pub async fn delete_user_and_role_by_role_id(
    role_id: &uuid::Uuid,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"DELETE FROM user_and_role
        WHERE role_id = $1"#,
        role_id,
    )
    .execute(transaction)
    .await
    .context("Failed to delete stored user_and_role relationship.")?;

    Ok(())
}