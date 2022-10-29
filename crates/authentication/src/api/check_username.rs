//! 检查用户名存在

use actix_web::{HttpResponse, web};
use data_transmission::{web::{build_http_response_error_data, build_http_response_empty_data}, error::authentication::RegisterUserError};
use serde::Deserialize;

use crate::{domain::user::service::check_username as user_check_username, connectors::inner::{ApplicationPgPool}};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckUsername {
    pub username: String,
}

#[tracing::instrument(
    name = "Check username API",
    skip(check_username, pool),
    fields(user_id=tracing::field::Empty, username=tracing::field::Empty)
)]
pub async fn check_username(
    check_username: web::Json<CheckUsername>,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    tracing::Span::current()
        .record("username", &tracing::field::display(&check_username.username));
    match user_check_username(&check_username.username, &pool.get_ref().0).await {
        Ok(user_id) => {
            match user_id {
                Some(_) => build_http_response_error_data(
                    RegisterUserError::UsernameAlreadyExistError(
                        anyhow::anyhow!("Duplicate username input: {:?}.", &check_username.username)
                    )
                ),
                None => build_http_response_empty_data(),
            }
        },
        Err(e) => build_http_response_error_data(e)
    }
}