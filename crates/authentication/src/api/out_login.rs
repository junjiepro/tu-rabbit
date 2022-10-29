//! 退出登录

use crate::{handler::cookie::clear_credentials_cookie, connectors::AuthenticationCurrentUserResult};
use actix_web::{HttpResponse, web};
use data_transmission::web::{build_http_response_error_data, build_http_response_empty_data};
use typed_session::TypedSession;

#[tracing::instrument(
    name = "out login API",
    skip(session, user),
    fields(username=tracing::field::Empty, user_id=tracing::field::Empty)
)]
pub async fn out_login(
    session: TypedSession,
    user: web::ReqData<AuthenticationCurrentUserResult>,
) -> HttpResponse {
    let user = user.into_inner();

    match user {
        AuthenticationCurrentUserResult::User(user, _) => {
            tracing::Span::current()
                .record("user_id", &tracing::field::display(&user.get_user_id()));
        
            session.log_out();
            session.renew();
            clear_credentials_cookie(build_http_response_empty_data())
        },
        AuthenticationCurrentUserResult::Error(e) => build_http_response_error_data(e)
    }
}