//! 应用相关数据库操作
//! 

use anyhow::Context;
use chrono::prelude::*;
use sqlx::{Transaction, Postgres, PgPool};

use crate::domain::application::Application;

/// 获取所有应用
#[tracing::instrument(
    name = "DAO -> Get applications",
    skip(pool)
)]
pub async fn get_applications(
    pool: &PgPool
) -> Result<Vec<Application>, anyhow::Error> {
    let row = sqlx::query_as!(
        Application,
        r#"
        SELECT application_id, msg_id, default_msg, role_msg_id, remarks
        FROM applications
        WHERE application_id IS NOT NULL
        ORDER BY msg_id
        "#
    )
    .fetch_all(pool)
    .await
    .context("Failed to perform a query to retrieve stored applications.")?;

    Ok(row)
}

/// 根据编号获取应用
#[tracing::instrument(
    name = "DAO -> Get application by id",
    skip(application_id, pool)
)]
pub async fn get_application_by_id(
    application_id: &uuid::Uuid,
    pool: &PgPool
) -> Result<Option<Application>, anyhow::Error> {
    let row = sqlx::query_as!(
        Application,
        r#"
        SELECT application_id, msg_id, default_msg, role_msg_id, remarks
        FROM applications
        WHERE application_id = $1
        "#,
        application_id,
    )
    .fetch_optional(pool)
    .await
    .context(format!("Failed to perform a query to retrieve stored application by application_id: {}.", application_id))?;

    Ok(row)
}

/// 根据消息编号获取应用
#[tracing::instrument(
    name = "DAO -> Get application by msg_id",
    skip(msg_id, pool)
)]
pub async fn get_application_by_msg_id(
    msg_id: &str,
    pool: &PgPool
) -> Result<Option<Application>, anyhow::Error> {
    let row = sqlx::query_as!(
        Application,
        r#"
        SELECT application_id, msg_id, default_msg, role_msg_id, remarks
        FROM applications
        WHERE msg_id = $1
        "#,
        msg_id,
    )
    .fetch_optional(pool)
    .await
    .context(format!("Failed to perform a query to retrieve stored application by msg_id: {}.", msg_id))?;

    Ok(row)
}

/// 插入应用
#[tracing::instrument(
    name = "DAO -> Insert application",
    skip(application, transaction)
)]
pub async fn insert_application(
    application: &Application,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        "INSERT INTO applications (application_id, msg_id, default_msg, role_msg_id, remarks)
        VALUES ($1, $2, $3, $4, $5)",
        application.application_id,
        application.msg_id,
        application.default_msg,
        application.role_msg_id,
        application.remarks,
    )
    .execute(transaction)
    .await
    .context("Failed to store new application.")?;

    Ok(())
}

/// 更新应用
#[tracing::instrument(
    name = "DAO -> Update application",
    skip(application, transaction)
)]
pub async fn update_application(
    application: &Application,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"UPDATE applications
        SET 
            msg_id = $1,
            default_msg = $2,
            role_msg_id = $3,
            remarks = $4,
            update_at = $5
        WHERE application_id = $6"#,
        application.msg_id,
        application.default_msg,
        application.role_msg_id,
        application.remarks,
        Local::now().naive_local(),
        application.application_id,
    )
    .execute(transaction)
    .await
    .context("Failed to update stored application.")?;

    Ok(())
}

/// 根据编号删除应用
#[tracing::instrument(
    name = "DAO -> Delete application by id",
    skip(application_id, transaction)
)]
pub async fn delete_application_by_id(
    application_id: &uuid::Uuid,
    transaction: &mut Transaction<'static, Postgres>
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"DELETE FROM applications
        WHERE application_id = $1"#,
        application_id,
    )
    .execute(transaction)
    .await
    .context(format!("Failed to perform a query to delete stored application by application_id: {}.", application_id))?;

    Ok(())
}
