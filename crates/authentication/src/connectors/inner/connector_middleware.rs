//! Inner 连接器中间件

use crate::connectors::{AuthenticationCurrentUserResult, ApplicationToBind};
use crate::connectors::inner::{InnerAuthenticationConnector, ApplicationPgPool, HmacSecret};
use crate::domain::cache::Cache;
use crate::handler::cookie::set_credentials_cookie;
use actix_web::{HttpMessage, FromRequest};
use actix_web::web::Data;
use actix_web_lab::middleware::Next;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use typed_redis::TypedRedis;
use typed_session::TypedSession;
use data_transmission::error::{self, CommonError};
use data_transmission::web::build_http_response_error_data;
use secrecy::ExposeSecret;

#[tracing::instrument(
    name = "Middleware ( inner middleware fn )",
    skip(req, next)
)]
pub async fn inner_middleware_fn(
    mut req: ServiceRequest,
    next: Next<BoxBody>
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    // 准备

    // 获取session
    let session = {
        let (http_request, payload) = req.parts_mut();
        TypedSession::from_request(http_request, payload).await
    };
    // 获取redis
    let typed_redis = {
        let (http_request, payload) = req.parts_mut();
        Data::<TypedRedis>::from_request(http_request, payload).await
    };
    // 获取连接器
    let connector = {
        let (http_request, payload) = req.parts_mut();
        Data::<InnerAuthenticationConnector>::from_request(http_request, payload).await
    };
    // 获取数据库
    let pool = {
        let (http_request, payload) = req.parts_mut();
        Data::<ApplicationPgPool>::from_request(http_request, payload).await
    };
    // 获取秘钥
    let secret = {
        let (http_request, payload) = req.parts_mut();
        Data::<HmacSecret>::from_request(http_request, payload).await
    };
    // 获取待绑定应用
    let application_to_bind = {
        let (http_request, payload) = req.parts_mut();
        Data::<ApplicationToBind>::from_request(http_request, payload).await
    };

    // 执行中间件前置方法

    // 缓存
    let cache = if let Ok(typed_redis) = typed_redis {
        Some(Cache(typed_redis))
    } else {
        None
    };

    // 获取当前用户
    let current_user_result = match (connector, session, pool, &secret) {
        (
            Ok(connector),
            Ok(session),
            Ok(pool),
            Ok(secret)
        ) => {
            let (http_request, _) = req.parts_mut();
            connector.current_user(&session, &cache, http_request, &pool, &secret, application_to_bind).await
        },
        _ => AuthenticationCurrentUserResult::Error(error::Error::default()),
    };
    let credentials = match &current_user_result {
        AuthenticationCurrentUserResult::User(_, Some(credentials)) => Some(credentials.clone()),
        _ => None,
    };
    req.extensions_mut().insert(cache);
    req.extensions_mut().insert(current_user_result);

    // 执行

    let mut resp = next.call(req).await?;

    // 执行中间件后置方法
    
    // 自动登录成功，设置 cookie
    if let Some(credentials) = credentials {
        let username = &credentials.username;
        let password = &credentials.password.expose_secret().to_owned();
        let r = resp.response_mut();

        let resp = match set_credentials_cookie(
            r,
            &username,
            &password,
            true,
            &secret.unwrap().0,
        ) {
            Ok(_) => Ok(resp),
            Err(e) => {
                let response = build_http_response_error_data(CommonError::NoPermissionError(anyhow::anyhow!(format!("The user has not logged in {}.", &e))));
                Ok(resp.into_response(response))
            }
        };

        return resp;
    }

    Ok(resp)
}