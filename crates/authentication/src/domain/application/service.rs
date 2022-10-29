//! 应用相关功能

use data_transmission::error::CommonError;
use data_transmission::data::DataEntity;
use sqlx::PgPool;

use crate::domain::application::{dao, Application};
use crate::domain::namespace::Namespace;

/// 获取所有应用
#[tracing::instrument(
    name = "Service -> Get applications",
    skip(pool)
)]
pub async fn get_applications(
    pool: &PgPool
) -> Result<Vec<Application>, CommonError> {
    dao::get_applications(pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据编号获取应用
#[tracing::instrument(
    name = "Service -> Get application by id",
    skip(application_id, pool)
)]
pub async fn get_application_by_id(
    application_id: &uuid::Uuid,
    pool: &PgPool
) -> Result<Option<Application>, CommonError> {
    dao::get_application_by_id(application_id, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 根据消息编号获取应用
#[tracing::instrument(
    name = "Service -> Get application by msg_id",
    skip(msg_id, pool)
)]
pub async fn get_application_by_msg_id(
    msg_id: &str,
    pool: &PgPool
) -> Result<Option<Application>, CommonError> {
    dao::get_application_by_msg_id(msg_id, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}

/// 插入应用
#[tracing::instrument(
    name = "Service -> Insert application",
    skip(application, pool)
)]
pub async fn insert_application(
    application: &mut Application,
    pool: &PgPool
) -> Result<(), CommonError> {
    if Namespace::validate_msg(&application.msg_id)
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
    {
        insert_application_action(application, pool)
            .await
            .map_err(|e| CommonError::UnexpectedError(e))
    } else {
        Err(
            CommonError::NoPermissionError(
                anyhow::anyhow!(format!("No Permission to insert application with msg_id: {}", &application.msg_id)
            ))
        )
    }
}
async fn insert_application_action(
    application: &mut Application,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    application.pre_insert();
    dao::insert_application(application, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 更新应用
#[tracing::instrument(
    name = "Service -> Update application",
    skip(application, pool)
)]
pub async fn update_application(
    application: &mut Application,
    pool: &PgPool
) -> Result<(), CommonError> {
    if Namespace::validate_msg(&application.msg_id)
        .map_err(|e| CommonError::InvalidInputError(e.into()))?
    {
        update_application_action(application, pool)
            .await
            .map_err(|e| CommonError::UnexpectedError(e))
    } else {
        Err(
            CommonError::NoPermissionError(
                anyhow::anyhow!(format!("No Permission to update application with msg_id: {}", &application.msg_id)
            ))
        )
    }
}
async fn update_application_action(
    application: &mut Application,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    application.pre_update();
    dao::update_application(application, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

/// 根据编号删除应用
#[tracing::instrument(
    name = "Service -> Delete application by id",
    skip(application_id, pool)
)]
pub async fn delete_application_by_id(
    application_id: &uuid::Uuid,
    pool: &PgPool
) -> Result<(), CommonError> {
    delete_application_by_id_action(application_id, pool)
        .await
        .map_err(|e| CommonError::UnexpectedError(e))
}
async fn delete_application_by_id_action(
    application_id: &uuid::Uuid,
    pool: &PgPool
) -> Result<(), anyhow::Error> {
    let mut transaction = pool.begin().await?;
    dao::delete_application_by_id(application_id, &mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}
