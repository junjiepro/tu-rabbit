//! 注册用户

use actix_web::{HttpResponse, web};
use data_transmission::{web::{build_http_response_error_data, build_http_response_empty_data}, error::authentication::RegisterUserError};
use typed_session::{TypedSession, data::verification_code::VerificationCode};

use crate::{domain::user::{RegisterUser, service::store_new_user, service::check_username}, connectors::inner::{ApplicationPgPool}};

#[tracing::instrument(
    name = "Register user API",
    skip(session, verification_code, register_user, pool),
    fields(user_id=tracing::field::Empty, username=tracing::field::Empty)
)]
pub async fn register_user(
    session: TypedSession,
    verification_code: VerificationCode,
    register_user: web::Json<RegisterUser>,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    tracing::Span::current()
        .record("username", &tracing::field::display(&register_user.get_username()));
    // 校验密码
    if register_user.validate_password() {
        // 检验验证码
        if register_user.validate_verification_code(verification_code) {
            // 检查用户名存在
            match check_username(&register_user.get_username(), &pool.get_ref().0).await {
                Ok(user_id) => {
                    match user_id {
                        Some(_) => build_http_response_error_data(
                            RegisterUserError::UsernameAlreadyExistError(
                                anyhow::anyhow!("Duplicate username input: {:?}.", &register_user.get_username())
                            )
                        ),
                        None => {
                            // 保存
                            match store_new_user(&register_user.into_inner(), &pool.get_ref().0).await {
                                Ok(user_id) => {
                                    tracing::Span::current()
                                        .record("user_id", &tracing::field::display(&user_id));
                                    // 自动登录
                                    session.renew();
                                    if let Err(e) = session.insert_user_id(user_id) {
                                        tracing::warn!("Failed to insert user id to session. {:?}", e);
                                    }
                                    build_http_response_empty_data()
                                },
                                Err(e) => build_http_response_error_data(e)
                            }
                        }
                    }
                },
                Err(e) => build_http_response_error_data(e)
            }
        } else {
            build_http_response_error_data(
                RegisterUserError::InvalidVerificationCodeError(
                    anyhow::anyhow!("Invalid verification code input: {:?}.", &register_user.get_verification_code())
                )
            )
        }
    } else {
        build_http_response_error_data(
            RegisterUserError::DifferentPasswordError(
                anyhow::anyhow!("Different password input.")
            )
        )
    }
}