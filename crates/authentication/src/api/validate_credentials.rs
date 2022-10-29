//! validate_credentials
//! 
//! 校验

use crate::connectors::inner::{HmacSecret, ApplicationPgPool};
use crate::handler::cookie::{set_credentials_cookie, clear_credentials_cookie};
use crate::domain::credentials::{validate_credentials as validate, AuthError, Credentials, CredentialsData, ValidateCredentialsResult};
use data_transmission::error::{CommonError, Error};
use typed_session::TypedSession;
use data_transmission::web::{build_http_response_data, build_http_response_error_data};
use data_transmission::error::authentication::ValidateError;
use actix_web::{web, HttpResponse};
use secrecy::ExposeSecret;

#[tracing::instrument(
    name = "Validate credentials API",
    skip(session, credentials_data, pool, secret),
    fields(username=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn validate_credentials(
    session: TypedSession,
    credentials_data: web::Json<CredentialsData>,
    pool: web::Data<ApplicationPgPool>,
    secret: web::Data<HmacSecret>,
) -> HttpResponse {
    let password = credentials_data.0.password.expose_secret().clone();
    let credentials = Credentials {
        username: credentials_data.0.username,
        password: credentials_data.0.password,
    };
    tracing::Span::current()
        .record("username", &tracing::field::display(&credentials.username));
    // 验证
    match validate(credentials, &pool.get_ref().0).await {
        Ok((user_id, username)) => {
            tracing::Span::current()
                .record("user_id", &tracing::field::display(&user_id));
            
            // 更新session
            session.renew();
            if let Err(e) = session.insert_user_id(user_id) {
                let e = CommonError::UnexpectedError(e.into());
                let response = build_http_response_error_data(e);
                let response = clear_credentials_cookie(response);
                return response;
            }
            if let Err(e) = session.insert_username(&username) {
                let e = CommonError::UnexpectedError(e.into());
                let response = build_http_response_error_data(e);
                let response = clear_credentials_cookie(response);
                return response;
            }

            // 验证成功
            let mut response = build_http_response_data(ValidateCredentialsResult::default());
            // 设置cookie
            match set_credentials_cookie(
                &mut response,
                &username,
                &password,
                credentials_data.0.auto_login,
                &secret.0,
            ) {
                Ok(_) => response,
                Err(e) => {
                    let e = CommonError::UnexpectedError(e.into());
                    let response = build_http_response_error_data(e);
                    let response = clear_credentials_cookie(response);
                    response
                }
            }
        }
        Err(e) => {
            let e: Error = match e {
                AuthError::InvalidCredentials(_) => ValidateError::AuthError(e.into()).into(),
                AuthError::UnexpectedError(_) => CommonError::UnexpectedError(e.into()).into(),
            };
            let response = build_http_response_error_data(e);
            let response = clear_credentials_cookie(response);
            response
        }
    }
}