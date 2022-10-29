/// 中间件

use crate::connectors::AuthenticationCurrentUserResult;
use data_transmission::error;
use data_transmission::web::build_http_response_error_data;
use actix_web::web::ReqData;
use actix_web::error::InternalError;
use actix_web_lab::middleware::Next;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::FromRequest;

#[tracing::instrument(
    name = "Middleware ( reject anonymous users )",
    skip(req, next)
)]
pub async fn reject_anonymous_users(
    mut req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    // 获取当前用户
    let current_user_result = {
        let (http_request, payload) = req.parts_mut();
        ReqData::<AuthenticationCurrentUserResult>::from_request(http_request, payload).await
    };
    // 检查
    match current_user_result {
        Ok(current_user_result) => {
            match current_user_result.into_inner() {
                AuthenticationCurrentUserResult::User(_, _) => {
                    next.call(req).await
                },
                AuthenticationCurrentUserResult::Error(e) => {
                    let response = build_http_response_error_data(e);
                    let e = anyhow::anyhow!("The user has not logged in");
                    Err(InternalError::from_response(e, response).into())
                }
            }
        },
        Err(_) => {
            let response = build_http_response_error_data(error::Error::default());
            let e = anyhow::anyhow!("The user has not logged in");
            Err(InternalError::from_response(e, response).into())
        }
    }
}