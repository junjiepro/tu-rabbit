//! Web 连接器中间件

use crate::connectors::{web::WebAuthenticationConnector, AuthenticationCurrentUserResult, ApplicationToBind};
use actix_web::{dev::{ServiceRequest, ServiceResponse}, body::BoxBody, web::Data, FromRequest, HttpMessage};
use actix_web_lab::middleware::Next;
use data_transmission::error;

#[tracing::instrument(
    name = "Middleware ( web middleware fn )",
    skip(req, next)
)]
pub async fn web_middleware_fn(
    mut req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    // 获取连接器
    let connector = {
        let (http_request, payload) = req.parts_mut();
        Data::<WebAuthenticationConnector>::from_request(http_request, payload).await
    };
    // 获取待绑定应用
    let application_to_bind = {
        let (http_request, payload) = req.parts_mut();
        Data::<ApplicationToBind>::from_request(http_request, payload).await
    };

    // 获取当前用户
    let result = match connector {
        Ok(connector) => {
            let (http_request, _) = req.parts_mut();
            connector.current_user(http_request, application_to_bind).await
        },
        Err(_) => AuthenticationCurrentUserResult::Error(error::Error::default()),
    };
    req.extensions_mut().insert(result);

    next.call(req).await
    // 
}