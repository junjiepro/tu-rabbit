use crate::api::validate_token::validate;
use actix_web::HttpRequest;
use data_transmission::error::authentication::ChangePasswordError;
use sqlx::PgPool;
use actix_web::{HttpResponse, web};
use actix_web_flash_messages::FlashMessage;
use secrecy::Secret;
use secrecy::ExposeSecret;
use unicode_segmentation::UnicodeSegmentation;
use crate::handler::password::{validate_credentials, AuthError};
use crate::handler::cookie::{get_credentials_cookie, clear_credentials_cookie, set_credentials_cookie};
use crate::handler::jwt::JWTError;
use crate::domain::user::User;
use data_transmission::web::{build_http_response_data, build_http_response_error_data};
use data_transmission::error::{authentication::ValidateError, Error};

use crate::api::application::HmacSecret;

#[derive(serde::Deserialize)]
pub struct PasswordData {
    current_password: Secret<String>,
    new_password: Secret<String>,
    new_password_check: Secret<String>,
}

pub async fn change_password(
    request: HttpRequest,
    password_data: web::Json<PasswordData>,
    pool: web::Data<ApplicationPgPool>,
    secret: web::Data<HmacSecret>,
) -> HttpResponse {
    match validate(request, &pool, secret).await {
        Ok((user, auto_login)) => {
            if password_data.new_password.expose_secret() != password_data.new_password_check.expose_secret() {
                let e = ChangePasswordError::DifferentPasswordError(anyhow::anyhow!("You entered two different new passwords - the field values must match."));
                let response = build_http_response_error_data(e);
                if auto_login {
                    auto_login_cookie(response, )
                } else {

                }
            } else {

            }

            let response = build_http_response_data(user);
            if auto_login {
                todo!()
            }
            response
        },
        Err(e) => {
            let response = build_http_response_error_data(e);
            let response = clear_credentials_cookie(response);
            response
        }
    }

    // `Secret<String>` does not implement `Eq`,
    // therefore we need to compare the underlying `String`.
    // if form.new_password.expose_secret() != form.new_password_check.expose_secret() {
    //     FlashMessage::error(
    //         "You entered two different new passwords - the field values must match.",
    //     )
    //     .send();
    //     return Ok(see_other("/admin/password"));
    // }

    // let username = get_username(*user_id, &pool).await.map_err(e500)?;
    // let credentials = Credentials {
    //     username,
    //     password: form.0.current_password,
    // };
    // if let Err(e) = validate_credentials(credentials, &pool).await {
    //     return match e {
    //         AuthError::InvalidCredentials(_) => {
    //             FlashMessage::error("The current password is incorrect.").send();
    //             Ok(see_other("/admin/password"))
    //         }
    //         AuthError::UnexpectedError(_) => Err(e500(e).into()),
    //     }
    // }

    // let vec = form.0.new_password.expose_secret().graphemes(true);
    // let new_password_length = vec.count();
	// let is_too_long = new_password_length > 128;
    // let is_too_short = new_password_length < 12;
    // if is_too_long || is_too_short {
    //     FlashMessage::error(
    //         "The new password is too short/long - passwords should be longer than 12 characters but shorter than 128 characters.",
    //     )
    //     .send();
    //     return Ok(see_other("/admin/password"));
    // }

    // crate::authentication::change_password(*user_id, form.0.new_password, &pool)
    //     .await
    //     .map_err(e500)?;
    // FlashMessage::error("Your password has been changed.").send();
    // Ok(see_other("/admin/password"))
}

fn auto_login_cookie (
    mut response: HttpResponse,
    username: &str,
    password: &str,
    secret: &Secret<String>,
    user_id: &str,
) -> HttpResponse {
    match set_credentials_cookie(
        response,
        username,
        password,
        true,
        secret,
        user_id,
    ) {
        Ok(response) => response,
        Err(e) => {
            let e = ValidateError::UnexpectedError(e.into());
            let response = build_http_response_error_data(e);
            let response = clear_credentials_cookie(response);
            response
        }
    }
}