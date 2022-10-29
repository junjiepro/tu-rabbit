//! Inner 连接器服务

use crate::api::application_api::{get_applications, update_application, add_application, get_application_by_id, delete_application_by_id, check_application_msg_id};
use crate::api::check_username::check_username;
use crate::api::generate_verification_code_and_send::generate_verification_code_and_send;
use crate::api::guest_credentials::guest_credentials;
use crate::api::middleware::reject_anonymous_users;
use crate::api::health_check::health_check;
use crate::api::permission::{get_permissions, add_permission, update_permission, get_permission_by_id, delete_permission_by_id, check_permission_msg_id, check_permission_value, get_permissions_by_role_id};
use crate::api::reset_password::reset_password;
use crate::api::role::{get_roles, add_role, get_role_by_id, delete_role_by_id, update_role, check_role_msg_id, check_role_namespace, get_roles_by_user_id, get_roles_by_permission_id};
use crate::api::user::{get_users, get_users_by_role_id, update_user};
use crate::api::validate_credentials::validate_credentials;
use crate::api::current_user::{current_user, bind_current_user};
use crate::api::out_login::out_login;
use crate::api::register_user::register_user;
use crate::connectors::ApplicationToBind;
use crate::connectors::inner::{HmacSecret, ApplicationBaseUrl, ApplicationPgPool, InnerAuthenticationConnector, ForbiddenAdminApplicationMsgId};
use crate::connectors::permission_middleware::PermissionService;
use actix_web::Error;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{web::{self, Data}, Scope};
use actix_web_lab::middleware::from_fn;
use connector::ConnectorServer;

#[derive(Debug, Clone)]
pub struct InnerAuthenticationConnectorServer {
    pub(crate) connector: Data<InnerAuthenticationConnector>,
    pub(crate) db_pool: Data<ApplicationPgPool>,
    pub(crate) base_url: Data<ApplicationBaseUrl>,
    pub(crate) hmac_secret: Data<HmacSecret>,
    pub(crate) forbidden_admin_application_msg_id: Data<ForbiddenAdminApplicationMsgId>,
    pub(crate) application_to_bind: Option<Data<ApplicationToBind>>,
}

impl ConnectorServer for InnerAuthenticationConnectorServer {
    fn service_factory<
        T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = Error,
            InitError = (),
        >
    >(&self, path: Option<&str>, scope: Scope<T>) -> Scope<T> {
        match path {
            Some(path) => 
                scope
                    .service(
                        web::scope(path)
                            // 健康检查
                            .route("/health-check", web::get().to(health_check))
                            // 登录
                            .route("/validate-credentials", web::post().to(validate_credentials))
                            // 游客登录
                            .route("/guest-credentials", web::post().to(guest_credentials))
                            // 生成验证码并发送
                            .route("/generate-verification-code", web::post().to(generate_verification_code_and_send))
                            // 注册用户
                            .route("/register-user", web::post().to(register_user))
                            .route("/check-username", web::post().to(check_username))
                            // 注册用户
                            .route("/reset-password", web::post().to(reset_password))
                            .service(
                                web::scope("")
                                    .wrap(from_fn(reject_anonymous_users))
                                    // 当前用户
                                    .route("/current-user", web::get().to(current_user))
                                    .route("/bind-current-user/{application_msg_id}", web::get().to(bind_current_user))
                                    // 用户
                                    .service(
                                        web::scope("/user")
                                            .route("", web::get().to(get_users))
                                            .route("", web::put().to(update_user))
                                            .route("/find-by-role-id/{role_id}", web::get().to(get_users_by_role_id))
                                    )
                                    // 角色
                                    .service(
                                        web::scope("/role")
                                            .route("", web::get().to(get_roles))
                                            .route("", web::post().to(add_role))
                                            .route("", web::put().to(update_role))
                                            .route("/{role_id}", web::get().to(get_role_by_id))
                                            .route("/{role_id}", web::delete().to(delete_role_by_id))
                                            .route("/check-role-msg-id/{msg_id}", web::get().to(check_role_msg_id))
                                            .route("/check-role-namespace/{namespace}", web::get().to(check_role_namespace))
                                            .route("/find-by-user-id/{user_id}", web::get().to(get_roles_by_user_id))
                                            .route("/find-by-permission-id/{permission_id}", web::get().to(get_roles_by_permission_id))
                                    )
                                    // 权限
                                    .service(
                                        web::scope("/permission")
                                            .route("", web::get().to(get_permissions))
                                            .route("", web::post().to(add_permission))
                                            .route("", web::put().to(update_permission))
                                            .route("/{permission_id}", web::get().to(get_permission_by_id))
                                            .route("/{permission_id}", web::delete().to(delete_permission_by_id))
                                            .route("/check-permission-msg-id/{msg_id}", web::get().to(check_permission_msg_id))
                                            .route("/check-permission-value/{permission}", web::get().to(check_permission_value))
                                            .route("/find-by-role-id/{role_id}", web::get().to(get_permissions_by_role_id))
                                    )
                                    // 应用
                                    .service_with_permission("admin", "/application",
                                        web::scope("")
                                            .route("", web::get().to(get_applications))
                                            .route("", web::post().to(add_application))
                                            .route("", web::put().to(update_application))
                                            .route("/{application_id}", web::get().to(get_application_by_id))
                                            .route("/{application_id}", web::delete().to(delete_application_by_id))
                                            .route("/check-application-msg-id/{msg_id}", web::get().to(check_application_msg_id))
                                    )
                                    // 退出登录
                                    .route("/out-login", web::post().to(out_login))
                            )
                    ),
            None => scope,
        }
    }

    fn service_app_data<
        T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = Error,
            InitError = (),
        >
    >(&self, scope: Scope<T>) -> Scope<T> {
        let scope = scope
            .app_data(self.db_pool.clone())
            .app_data(self.base_url.clone())
            .app_data(self.hmac_secret.clone())
            .app_data(self.connector.clone())
            .app_data(self.forbidden_admin_application_msg_id.clone());
        if let Some(application_to_bind) = &self.application_to_bind {
            scope
                .app_data(application_to_bind.clone())
        } else {
            scope
        }
    }
}