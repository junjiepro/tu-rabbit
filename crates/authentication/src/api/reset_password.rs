//! 注册用户

use actix_web::{HttpResponse, web};
use data_transmission::{web::{build_http_response_error_data, build_http_response_empty_data}, error::authentication::{RegisterUserError, ChangePasswordError}};
use typed_session::{TypedSession, data::verification_code::VerificationCode};

use crate::{domain::user::{RegisterUser, service::{check_username, update_user_password}}, connectors::inner::{ApplicationPgPool}};

#[tracing::instrument(
    name = "Reset password API",
    skip(session, verification_code, reset_user, pool),
    fields(user_id=tracing::field::Empty, username=tracing::field::Empty)
)]
pub async fn reset_password(
    session: TypedSession,
    verification_code: VerificationCode,
    reset_user: web::Json<RegisterUser>,
    pool: web::Data<ApplicationPgPool>,
) -> HttpResponse {
    tracing::Span::current()
        .record("username", &tracing::field::display(&reset_user.get_username()));
    // 校验密码
    if reset_user.validate_password() {
        // 检验验证码
        if reset_user.validate_verification_code(verification_code) {
            let username = reset_user.get_username().to_string();
            // 检查用户名存在
            match check_username(&username, &pool.get_ref().0).await {
                Ok(user_id) => {
                    match user_id {
                        Some(user_id) =>
                         // 保存
                        match update_user_password(&reset_user.into_inner(), &user_id, &pool.get_ref().0).await {
                            Ok(_) => {
                                tracing::Span::current()
                                    .record("user_id", &tracing::field::display(&user_id));
                                // 自动登录
                                session.renew();
                                if let Err(e) = session.insert_user_id(user_id) {
                                    tracing::warn!("Failed to insert user id to session. {:?}", e);
                                }
                                if let Err(e) = session.insert_username(&username) {
                                    tracing::warn!("Failed to insert username to session. {:?}", e);
                                }
                                build_http_response_empty_data()
                            },
                            Err(e) => build_http_response_error_data(e)
                        },
                        None => build_http_response_error_data(
                            ChangePasswordError::UsernameNotExistError(
                                anyhow::anyhow!("Username not exist: {:?}.", &username)
                            )
                        )
                    }
                },
                Err(e) => build_http_response_error_data(e)
            }
        } else {
            build_http_response_error_data(
                RegisterUserError::InvalidVerificationCodeError(
                    anyhow::anyhow!("Invalid verification code input: {:?}.", &reset_user.get_verification_code())
                )
            )
        }
    } else {
        build_http_response_error_data(
            ChangePasswordError::DifferentPasswordError(
                anyhow::anyhow!("Different password input.")
            )
        )
    }
}