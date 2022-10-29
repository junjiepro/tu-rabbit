//! Inner 认证、授权连接器

use crate::connectors::{AuthenticationCurrentUserResult, ApplicationToBind, RoleToBind};
use crate::domain::application::service::get_application_by_msg_id;
use crate::domain::cache::Cache;
use crate::domain::namespace::Namespace;
use crate::domain::permission::service::get_permissions_by_role_id;
use crate::domain::permission::{service::get_permissions_by_user_id, CurrentUserPermissions};
use crate::domain::role::service::get_role_by_msg_id;
use crate::domain::user::service::bind_user_with_role;
use crate::{connectors::AuthenticationConnector, domain::user::User};
use crate::handler::cookie::get_credentials_cookie;
use crate::handler::jwt::JWTError;
use crate::domain::credentials::{validate_credentials, AuthError, Credentials};
use crate::connectors::inner::{HmacSecret, ApplicationPgPool};
use actix_web::{HttpRequest, web::Data};
use connector::Connector;
use typed_session::TypedSession;
use data_transmission::error::CommonError;
use data_transmission::error::Error;
use data_transmission::error::authentication::ValidateError;

/// Inner 认证、授权连接器
#[derive(Debug, Clone)]
pub struct InnerAuthenticationConnector {}

impl Connector for InnerAuthenticationConnector {}

impl AuthenticationConnector for InnerAuthenticationConnector {}

impl InnerAuthenticationConnector {
    /// 健康检查
    pub async fn health_check(&self) -> Result<(), CommonError> {
        Ok(())
    }

    /// 获取当前用户
    #[tracing::instrument(
        name = "Inner Connector -> Get Current User",
        skip(session, cache, http_request, pool, secret)
    )]
    pub(crate) async fn current_user(
        &self,
        session: &TypedSession,
        cache: &Option<Cache>,
        http_request: &HttpRequest,
        pool: &Data<ApplicationPgPool>,
        secret: &Data<HmacSecret>,
        application_to_bind: Result<Data<ApplicationToBind>, actix_web::Error>,
    ) -> AuthenticationCurrentUserResult {
        match validate(session, cache, http_request, pool, secret, application_to_bind).await {
            Ok((user, credentials)) => {
                AuthenticationCurrentUserResult::User(user, credentials)
            },
            Err(e) => {
                AuthenticationCurrentUserResult::Error(e)
            }
        }
    }
}

#[tracing::instrument(
    name = "Inner Connector -> Get Current User -> validate",
    skip(session, cache, request, pool, secret),
    fields(username=tracing::field::Empty, user_id=tracing::field::Empty)
)]
async fn validate<'a>(
    session: &TypedSession,
    cache: &Option<Cache>,
    request: &HttpRequest,
    pool: &Data<ApplicationPgPool>,
    secret: &Data<HmacSecret>,
    application_to_bind: Result<Data<ApplicationToBind>, actix_web::Error>,
) -> Result<(User, Option<Credentials>), Error> {
    // 已经登录
    if let (Ok(Some(user_id)), Ok(Some(username))) = (session.get_user_id(), session.get_username()) {
        tracing::Span::current()
            .record("user_id", &tracing::field::display(&user_id));
        let permissions = current_user_permissions(session, cache, pool, application_to_bind).await?;
        return Ok((User::build(user_id, username, permissions), None));
    }
    // rememberme
    match get_credentials_cookie(request, &secret.0) {
        Ok(cookie_data) => {
            // rememberme
            if let Some(credentials) = cookie_data.to_credentials() {
                tracing::Span::current()
                    .record("username", &tracing::field::display(&credentials.username));
            
                // 验证
                match validate_credentials(credentials.clone(), &pool.get_ref().0).await {
                    Ok((user_id, username)) => {
                        tracing::Span::current()
                            .record("user_id", &tracing::field::display(&user_id));
                        
                        // 更新session
                        session.renew();
                        if let Err(e) = session.insert_user_id(user_id) {
                            let e = CommonError::UnexpectedError(e.into());
                            return Err(e.into());
                        }
                        if let Err(e) = session.insert_username(&username) {
                            let e = CommonError::UnexpectedError(e.into());
                            return Err(e.into());
                        }
                        let permissions = current_user_permissions(session, cache, pool, application_to_bind).await?;

                        Ok((User::build(user_id, username, permissions), Some(credentials)))
                    }
                    Err(e) => {
                        let e: Error = match e {
                            AuthError::InvalidCredentials(_) => ValidateError::AuthError(e.into()).into(),
                            AuthError::UnexpectedError(_) => CommonError::UnexpectedError(e.into()).into(),
                        };
                        Err(e)
                    }
                }
            } else {
                let e = ValidateError::AuthError(anyhow::anyhow!("Empty Token and Rememberme"));
                Err(e.into())
            }
        },
        Err(e) => {
            let e: Error = match e {
                JWTError::InvalidTokenError(_) => ValidateError::AuthError(e.into()).into(),
                JWTError::UnexpectedError(_) => CommonError::UnexpectedError(e.into()).into(),
            };
            Err(e)
        }
    }
}

#[tracing::instrument(
    name = "Inner Connector -> Get Current User -> permissions",
    skip(session, cache, pool)
)]
async fn current_user_permissions(
    session: &TypedSession,
    cache: &Option<Cache>,
    pool: &Data<ApplicationPgPool>,
    application_to_bind: Result<Data<ApplicationToBind>, actix_web::Error>,
) -> Result<Option<CurrentUserPermissions>, Error> {
    // 取缓存
    if let Some(c) = cache {
        if let Some(current_user_permissions) = c.get_current_user_permissions(session).await {
            if let Ok(Some(_)) = session.get::<CurrentUserPermissions>() {
                // session中已有权限不需更新
            } else {
                if let Err(e) = session.insert(&current_user_permissions) {
                    let e = CommonError::UnexpectedError(e.into());
                    return Err(e.into());
                }
            }
            return Ok(Some(current_user_permissions));
        } else {
            tracing::warn!("permissions cache has expired.");
        }
    }
    // 缓存过期，清除session中权限
    if let Some(_) = session.remove::<CurrentUserPermissions>() {
        // 
    }
    // 根据 session user_id 获取
    if let (Ok(Some(user_id)), Ok(Some(username))) = (session.get_user_id(), session.get_username()) {
        // 游客用户
        if User::is_guest_user(&user_id, &username) {
            // 自动绑定角色
            if let Ok(application_to_bind) = application_to_bind {
                match get_application_by_msg_id(&application_to_bind.application_msg_id, &pool.get_ref().0).await {
                    Ok(Some(application)) => {
                        // 创建可见所有命名空间值的命名空间
                        if let Ok(n) = Namespace::has("") {
                            let namespaces = vec![n];
                            // 获取角色
                            if let Ok(Some(role)) = get_role_by_msg_id(application.get_role_msg_id(), &namespaces, &pool.get_ref().0).await {
                                // 获取权限
                                let permissions = get_permissions_by_role_id(
                                    &role.role_id,
                                    &namespaces,
                                    &pool.get_ref().0
                                ).await?;
                                let current_user_permissions = CurrentUserPermissions::build(&permissions);
                                if let Err(e) = session.insert(&current_user_permissions) {
                                    let e = CommonError::UnexpectedError(e.into());
                                    return Err(e.into());
                                }
                                return Ok(Some(current_user_permissions));
                            }
                        }
                    }
                    Ok(None) => tracing::warn!("The application(msg_id: {}) not exist.", &application_to_bind.application_msg_id),
                    Err(e) => tracing::warn!("{:?}", e),
                }
            }

            Ok(None)
        } else {
            // 自动绑定角色
            if let Ok(application_to_bind) = application_to_bind {
                match get_application_by_msg_id(&application_to_bind.application_msg_id, &pool.get_ref().0).await {
                    Ok(Some(application)) => {
                        let result = bind_user_with_role(
                            &user_id,
                            &RoleToBind { role_msg_id: application.get_role_msg_id().to_string() },
                            &pool.get_ref().0
                        ).await;
                        if let Err(e) = result {
                            tracing::warn!("{:?}", e);
                        }
                    }
                    Ok(None) => tracing::warn!("The application(msg_id: {}) not exist.", &application_to_bind.application_msg_id),
                    Err(e) => tracing::warn!("{:?}", e),
                }
            }
            // 获取权限
            let permissions = get_permissions_by_user_id(
                &user_id,
                &pool.get_ref().0
            ).await?;
            let current_user_permissions = CurrentUserPermissions::build(&permissions);
            if let Err(e) = session.insert(&current_user_permissions) {
                let e = CommonError::UnexpectedError(e.into());
                return Err(e.into());
            }

            if let Some(c) = cache {
                c.set_current_user_permissions(&current_user_permissions, session).await;
            }

            Ok(Some(current_user_permissions))
        }
        
    } else {
        Ok(None)
    }
}