//! application
//! 
//! 应用

use crate::{domain::{application::{service, Application}, permission::CurrentUserPermissions, namespace::Namespace}, connectors::inner::ApplicationPgPool};
use actix_web::{web, HttpResponse};
use data_transmission::{web::{build_http_response_data, build_http_response_error_data, build_http_response_empty_data}, error::CommonError};
use typed_session::TypedSession;

#[tracing::instrument(
    name = "Get applications API",
    skip(session, pool)
)]
pub async fn get_applications(
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::get_applications(&pool.0).await {
                Ok(applications) => build_http_response_data(applications),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get applications."))
    )
}

#[tracing::instrument(
    name = "Add application API",
    skip(application, session, pool)
)]
pub async fn add_application(
    mut application: web::Json<Application>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::insert_application(&mut application, &pool.0).await {
                Ok(_) => build_http_response_data(application.into_inner()),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to add application."))
    )
}

#[tracing::instrument(
    name = "update application API",
    skip(application, session, pool)
)]
pub async fn update_application(
    mut application: web::Json<Application>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            // 获取数据库里的应用
            let stored_application = service::get_application_by_id(&application.application_id, &pool.get_ref().0).await;
            // 权限存在且有权限更新
            if let Ok(Some(_)) = stored_application {
                match service::update_application(&mut application, &pool.0).await {
                    Ok(_) => {},
                    Err(e) => {
                        return build_http_response_error_data(e);
                    },
                };
                
                return build_http_response_empty_data();
            }
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to update application."))
    )
}

#[tracing::instrument(
    name = "get application by id API",
    skip(application_id, session, pool)
)]
pub async fn get_application_by_id(
    application_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::get_application_by_id(&application_id, &pool.get_ref().0).await {
                Ok(application) => build_http_response_data(application),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to get application."))
    )
}

#[tracing::instrument(
    name = "delete application by id API",
    skip(application_id, session, pool)
)]
pub async fn delete_application_by_id(
    application_id: web::Path<uuid::Uuid>,
    session: TypedSession,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    if let Ok(Some(current_permission)) = session.get::<CurrentUserPermissions>() {
        if current_permission.get_permissions().len() > 0 {
            return match service::delete_application_by_id(&application_id, &pool.get_ref().0).await {
                Ok(_) => build_http_response_empty_data(),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to delete application."))
    )
}

#[tracing::instrument(
    name = "check application msg id API",
    skip(msg_id, session, pool)
)]
pub async fn check_application_msg_id(
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
            return match service::get_application_by_msg_id(&msg_id, &pool.get_ref().0).await {
                Ok(Some(application)) => build_http_response_data(application.get_application_id().to_string()),
                Ok(None) => build_http_response_empty_data(),
                Err(e) => build_http_response_error_data(e),
            };
        }
    }
    build_http_response_error_data(
        CommonError::NoPermissionError(anyhow::anyhow!("No permission to check application msg id."))
    )
}
