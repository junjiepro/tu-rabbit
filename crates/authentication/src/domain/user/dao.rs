//! 用户相关数据库操作

use chrono::prelude::*;
use sqlx::{PgPool, Transaction, Postgres};
use anyhow::Context;
use uuid::Uuid;
use secrecy::ExposeSecret;

use crate::domain::{user::{User, RegisterUser, Status, UserListItem}, namespace::Namespace, credentials::compute_password_hash};

/// 检查用户名存在
#[tracing::instrument(name = "DAO -> Check username", skip(username, pool))]
pub async fn check_username(username: &str, pool: &PgPool) -> Result<Option<Uuid>, anyhow::Error> {
    let row = sqlx::query!(
        r#"
        SELECT user_id
        FROM users
        WHERE username = $1
        "#,
        username,
    )
    .fetch_optional(pool)
    .await
    .context("Failed to perform a query to retrieve stored user.")?
    .map(|row| row.user_id);

    Ok(row)
}

/// 保存新用户
#[tracing::instrument(name = "DAO -> Store new user", skip(user, transaction))]
pub async fn store_new_user(
    user: &RegisterUser,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<Uuid, anyhow::Error> {
    let password_hash = compute_password_hash(user.get_password())?;
    
    let user_id = Uuid::new_v4();
    let status: i32 = Status::Confirmed.into();
    sqlx::query!(
        "INSERT INTO users (user_id, username, user_type, password_hash, status)
        VALUES ($1, $2, $3, $4, $5)",
        &user_id,
        user.get_username(),
        user.get_user_type(),
        password_hash.expose_secret(),
        status,
    )
    .execute(transaction)
    .await
    .context("Failed to store new user.")?;

    Ok(user_id)
}

/// 更新用户
#[tracing::instrument(
    name = "DAO -> Update user",
    skip(user, transaction)
)]
pub async fn update_user(
    user: &User,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        "UPDATE users
        SET 
            name = $1,
            update_at = $2
        WHERE user_id = $3",
        user.name,
        Local::now().naive_local(),
        user.user_id,
    )
    .execute(transaction)
    .await
    .context("Failed to update stored permission.")?;

    Ok(())
}

/// 保存用户密码
#[tracing::instrument(name = "DAO -> Update user password", skip(user, user_id, transaction))]
pub async fn update_user_password(
    user: &RegisterUser,
    user_id: &uuid::Uuid,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    let password_hash = compute_password_hash(user.get_password())?;
    
    sqlx::query!(
        "UPDATE users
        SET password_hash = $1
        WHERE user_id = $2",
        password_hash.expose_secret(),
        &user_id,
    )
    .execute(transaction)
    .await
    .context("Failed to update user password.")?;

    Ok(())
}

/// 获取所有用户
#[tracing::instrument(
    name = "DAO -> Get users",
    skip(namespaces, pool)
)]
pub async fn get_users(
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<UserListItem>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"SELECT u.user_id, u.username, u.user_type, u.status, u.name
        FROM users u
        LEFT JOIN user_and_role u_r ON u.user_id = u_r.user_id
        LEFT JOIN roles r ON u_r.role_id = r.role_id
        WHERE u.user_id IS NOT NULL "#);
        let offset = 1;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1 {
                    sql.push_str(&format!(
                        r#"AND (
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(
                        r#"AND 
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                } else if index == len - 1 {
                    sql.push_str(&format!(
                        r#"OR 
                            (
                                r.namespace LIKE CONCAT(${}, ':%') OR 
                                r.namespace = ${} OR 
                                ${} = ''
                            )
                        ) "#, i, i, i
                    ));
                } else {
                    sql.push_str(&format!(
                        r#"OR 
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                }
            });
        sql.push_str(
            r#"GROUP BY u.user_id
            ORDER BY u.username "#
        );
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
        .context("Failed to perform a query to retrieve stored users.")?;

    Ok(row)
}

/// 根据ID获取用户
#[tracing::instrument(
    name = "DAO -> Get user by id",
    skip(user_id, namespaces, pool)
)]
pub async fn get_user_by_id(
    user_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Option<UserListItem>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"SELECT u.user_id, u.username, u.user_type, u.status, u.name
        FROM users u
        LEFT JOIN user_and_role u_r ON u.user_id = u_r.user_id
        LEFT JOIN roles r ON u_r.role_id = r.role_id
        WHERE u.user_id = $1 "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1 {
                    sql.push_str(&format!(
                        r#"AND (
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(
                        r#"AND 
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                } else if index == len - 1 {
                    sql.push_str(&format!(
                        r#"OR 
                            (
                                r.namespace LIKE CONCAT(${}, ':%') OR 
                                r.namespace = ${} OR 
                                ${} = ''
                            )
                        ) "#, i, i, i
                    ));
                } else {
                    sql.push_str(&format!(
                        r#"OR 
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                }
            });
        sql.push_str(
            r#"GROUP BY u.user_id
            ORDER BY u.username "#
        );
        sql
    };
    // 注入参数并执行
    let row = namespaces
        .iter()
        .fold(
            sqlx::query_as(&sql).bind(user_id),
            |query, namespace| query.bind(namespace.get_value())
        )
        .fetch_optional(pool)
        .await
        .context(format!("Failed to perform a query to retrieve stored user by id: {}.", user_id))?;

    Ok(row)
}

/// 获取角色下所有用户
#[tracing::instrument(
    name = "DAO -> Get users by role_id",
    skip(role_id, namespaces, pool)
)]
pub async fn get_users_by_role_id(
    role_id: &uuid::Uuid,
    namespaces: &Vec<Namespace>,
    pool: &PgPool
) -> Result<Vec<UserListItem>, anyhow::Error> {
    // 组织 SQL 语句
    let sql = {
        let mut sql = String::from(r#"SELECT u.user_id, u.username, u.user_type, u.status, u.name
        FROM users u
        JOIN user_and_role u_r ON u.user_id = u_r.user_id
        JOIN roles r ON u_r.role_id = r.role_id
        WHERE u.user_id IS NOT NULL
        AND r.role_id = $1 "#);
        let offset = 2;
        let len = namespaces.len();
        namespaces
            .iter()
            .enumerate()
            .for_each(|(index, _)| {
                let i = index + offset;
                if index == 0 && len > 1 {
                    sql.push_str(&format!(
                        r#"AND (
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                } else if index == 0 && len == 1{
                    sql.push_str(&format!(
                        r#"AND 
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                } else if index == len - 1 {
                    sql.push_str(&format!(
                        r#"OR 
                            (
                                r.namespace LIKE CONCAT(${}, ':%') OR 
                                r.namespace = ${} OR 
                                ${} = ''
                            )
                        ) "#, i, i, i
                    ));
                } else {
                    sql.push_str(&format!(
                        r#"OR 
                        (
                            r.namespace LIKE CONCAT(${}, ':%') OR 
                            r.namespace = ${} OR 
                            ${} = ''
                        ) "#, i, i, i
                    ));
                }
            });
        sql.push_str(
            r#"GROUP BY u.user_id
            ORDER BY u.username "#
        );
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
        .context(format!("Failed to perform a query to retrieve stored users by role_id: {}.", role_id))?;

    Ok(row)
}
