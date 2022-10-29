//! API 
//! 
//! 提供相关模块以运行API服务

pub mod configuration;
pub mod application;
pub(crate) mod health_check;
pub(crate) mod validate_credentials;
pub(crate) mod guest_credentials;
pub(crate) mod current_user;
pub(crate) mod out_login;
// mod change_password;
pub(crate) mod middleware;
pub(crate) mod generate_verification_code_and_send;
pub(crate) mod register_user;
pub(crate) mod check_username;
pub(crate) mod role;
pub(crate) mod permission;
pub(crate) mod user;
pub(crate) mod application_api;
pub(crate) mod reset_password;