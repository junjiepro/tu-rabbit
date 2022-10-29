//! current user
//! 
//! 获取当前用户

use crate::connectors::RoleToBind;
use crate::connectors::inner::ForbiddenAdminApplicationMsgId;
use crate::connectors::{AuthenticationCurrentUserResult, inner::ApplicationPgPool};
use crate::domain::application::service::get_application_by_msg_id;
use crate::domain::user::service::bind_user_with_role;
use actix_web::web::Path;
use actix_web::{web, HttpResponse};
use data_transmission::web::{build_http_response_data, build_http_response_error_data};

#[tracing::instrument(
    name = "Get current user API",
    skip(user),
    fields(username=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn current_user(
    user: web::ReqData<AuthenticationCurrentUserResult>,
) -> HttpResponse {
    let user = user.into_inner();

    match user {
        AuthenticationCurrentUserResult::User(user, _) => {
            tracing::Span::current()
                .record("user_id", &tracing::field::display(&user.get_user_id()));

            build_http_response_data(user)
        },
        AuthenticationCurrentUserResult::Error(e) => build_http_response_error_data(e)
    }
}

#[tracing::instrument(
    name = "Bind current user API",
    skip(application_msg_id, user, pool, forbidden_admin_application_msg_id),
    fields(application_msg_id=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn bind_current_user(
    application_msg_id: Path<String>,
    user: web::ReqData<AuthenticationCurrentUserResult>,
    pool: web::Data<ApplicationPgPool>,
    forbidden_admin_application_msg_id: web::Data<ForbiddenAdminApplicationMsgId>,
) -> HttpResponse {
    let user = user.into_inner();

    match user {
        AuthenticationCurrentUserResult::User(user, _) => {
            tracing::Span::current()
                .record("application_msg_id", &tracing::field::display(&application_msg_id))
                .record("user_id", &tracing::field::display(&user.get_user_id()));

            let application_msg_id = application_msg_id.into_inner();
            if &application_msg_id == "admin" && forbidden_admin_application_msg_id.get_ref().0 {
                tracing::warn!("Forbidden admin application msg id!")
            } else {
                match get_application_by_msg_id(&application_msg_id, &pool.get_ref().0).await {
                    Ok(Some(application)) => {
                        let result = bind_user_with_role(
                            &user.get_user_id(),
                            &RoleToBind { role_msg_id: application.get_role_msg_id().to_string() },
                            &pool.get_ref().0
                        ).await;
                        if let Err(e) = result {
                            tracing::warn!("{:?}", e);
                        }
                    }
                    Ok(None) => tracing::warn!("The application(msg_id: {}) not exist.", &application_msg_id),
                    Err(e) => tracing::warn!("{:?}", e),
                }
            }

            build_http_response_data(user)
        },
        AuthenticationCurrentUserResult::Error(e) => build_http_response_error_data(e)
    }
}
