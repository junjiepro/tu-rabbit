use crate::connectors::AuthenticationCurrentUserResult;
use crate::domain::namespace::Namespace;
use actix_web::{FromRequest, http, guard};
use actix_web::error::InternalError;
use actix_web::web::{ReqData, Data};
use actix_web_lab::middleware::{Next, from_fn};
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse, HttpServiceFactory};
use data_transmission::error::{self, CommonError};
use actix_web::{Route, dev::{ServiceFactory}, Scope, Error, web};
use data_transmission::web::build_http_response_error_data;

#[derive(Debug)]
struct Permission(pub String);


pub trait PermissionRoute {
    /// 配置带权限路由
    /// 
    /// # examples
    /// ```rust,compile_fail
    /// use actix_web::{App, web};
    /// 
    /// use authentication::connectors::permission_middleware::PermissionRoute;
    /// 
    /// // 访问 /api/user/find_users 路由需要 admin 权限
    /// App::new()
    ///     .service(
    ///         web::scope("/api")
    ///             .service(
    ///                 // 用户
    ///                 web::scope("/user")
    ///                     .route_with_permission("admin", "/find_users", web::get().to(service::user::find_users))
    ///             )
    ///     )
    /// ```
    fn route_with_permission(self: Self, permission: &str, path: &str, route: Route) -> Self;
}

impl<T> PermissionRoute for Scope<T>
where
    T: ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = Error,
        InitError = (),
    >,
{
    fn route_with_permission(self, permission: &str, path: &str, route: Route) -> Self {
        self.service(
            web::scope(path)
                .service(
                    web::scope("")
                        .wrap(from_fn(middleware_fn))
                        .route("", route)
                )
                .app_data(Data::new(Permission(permission.into())))
        )
    }
}

pub trait PermissionService {
    /// 注册带权限 http 服务
    /// 
    /// # examples
    /// ```rust,compile_fail
    /// use actix_web::{App, web};
    /// 
    /// use authentication::connectors::permission_middleware::PermissionService;
    /// 
    /// // 访问 /api/user 下路由需要 admin 权限
    /// App::new()
    ///     .service(
    ///         web::scope("/api")
    ///             // 用户
    ///             .service_with_permission("admin", "/user",
    ///                 web::scope("")
    ///                     .route("/find_users", web::get().to(service::user::find_users))
    ///             )
    ///     )
    /// ```
    fn service_with_permission<F: HttpServiceFactory + 'static>(self: Self, permission: &str, path: &str, factory: F) -> Self;

    /// 配置带权限路由
    /// 
    /// # examples
    /// ```rust,compile_fail
    /// use actix_web::{App, web};
    /// 
    /// use authentication::connectors::permission_middleware::PermissionService;
    /// 
    /// // 访问 /api/user/find_users 路由需要 admin 权限
    /// App::new()
    ///     .service(
    ///         web::scope("/api")
    ///             .service_with_permission_routes("/user", vec![
    ///                 ("admin", "/find_users", http::Method::GET, web::get().to(service::user::find_users)
    ///             ])
    ///     )
    /// ```
    fn service_with_permission_routes(self: Self, path: &str, routes: Vec<(&str, &str, http::Method, Route)>) -> Self;
}

impl<T> PermissionService for Scope<T>
where
    T: ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = Error,
        InitError = (),
    >,
{
    fn service_with_permission<F: HttpServiceFactory + 'static>(self: Self, permission: &str, path: &str, factory: F) -> Self {
        self.service(
            web::scope(path)
                .service(
                    web::scope("")
                        .wrap(from_fn(middleware_fn))
                        .service(factory)
                )
                .app_data(Data::new(Permission(permission.into())))
        )
    }

    fn service_with_permission_routes(self: Self, path: &str, routes: Vec<(&str, &str, http::Method, Route)>) -> Self {
        self.service(
            web::scope(path)
                .service(
                    routes
                        .into_iter()
                        .fold(
                            web::scope(""),
                            |prev, r| {
                                prev.service(
                                    web::resource(r.1)
                                        .wrap(from_fn(middleware_fn))
                                        .app_data(Data::new(Permission(r.0.into())))
                                        .guard(guard::Method(r.2))
                                        .route(r.3)
                                )
                            }
                        )
                )
        )
    }
}

#[tracing::instrument(
    name = "Middleware ( permission middleware fn )",
    skip(req, next)
)]
async fn middleware_fn(
    mut req: ServiceRequest,
    next: Next<BoxBody>
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    // 准备

    // 获取认证当前用户
    let current_user_result = {
        let (http_request, payload) = req.parts_mut();
        ReqData::<AuthenticationCurrentUserResult>::from_request(http_request, payload).await
    };
    // 获取 权限要求
    let permission = {
        let (http_request, payload) = req.parts_mut();
        Data::<Permission>::from_request(http_request, payload).await
    };

    // 执行中间件前置方法

    // 有权限要求
    if let Ok(permission) = permission {
        // 获取当前用户
        if let Ok(current_user_result) = current_user_result {
            if let AuthenticationCurrentUserResult::User(user, _) = current_user_result.into_inner() {
                if let Some(permissions) = user.get_permissions() {
                    match Namespace::validate_required_namespace(permissions.get_permissions(), &permission.0) {
                        Ok(pass) => {
                            // 有权限
                            if pass {
                                return next.call(req).await;
                            } else {
                                let response = build_http_response_error_data(CommonError::NoPermissionError(anyhow::anyhow!(format!("No Permission to access {}.", &permission.0))));
                                let e = anyhow::anyhow!("No Permission to access.");
                                return Err(InternalError::from_response(e, response).into());
                            }
                        },
                        Err(e) => {
                            let response = build_http_response_error_data(CommonError::UnexpectedError(e.into()));
                            let e = anyhow::anyhow!("The permission value is invalid.");
                            return Err(InternalError::from_response(e, response).into());
                        }
                    }
                }
            }
        }
        // 未登录
        let response = build_http_response_error_data(error::Error::default());
        let e = anyhow::anyhow!("The user has not logged in");
        Err(InternalError::from_response(e, response).into())
    } else {
        next.call(req).await
    }
}