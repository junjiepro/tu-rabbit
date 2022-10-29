//! guest_credentials
//! 
//! 游客

use crate::domain::user::User;
use crate::handler::cookie::clear_credentials_cookie;
use crate::domain::credentials::ValidateCredentialsResult;
use data_transmission::error::CommonError;
use data_transmission::web::{build_http_response_data, build_http_response_error_data};
use typed_session::TypedSession;
use actix_web::HttpResponse;

#[tracing::instrument(
    name = "Guest credentials API",
    skip(session),
    fields(username=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn guest_credentials(
    session: TypedSession,
) -> HttpResponse {
    let guest = User::generate_guest_user();
    tracing::Span::current()
        .record("username", &tracing::field::display(&guest.username))
        .record("user_id", &tracing::field::display(&guest.user_id));
    
    // 更新session
    session.renew();
    if let Err(e) = session.insert_user_id(guest.user_id) {
        let e = CommonError::UnexpectedError(e.into());
        let response = build_http_response_error_data(e);
        let response = clear_credentials_cookie(response);
        return response;
    }
    if let Err(e) = session.insert_username(&guest.username) {
        let e = CommonError::UnexpectedError(e.into());
        let response = build_http_response_error_data(e);
        let response = clear_credentials_cookie(response);
        return response;
    }

    build_http_response_data(ValidateCredentialsResult::default())
}