//! connector 连接器
//! 
//! 提供连接器给其他应用以连接认证、授权服务

pub mod inner;
pub mod web;
pub mod permission_middleware;

use connector::{Connector, ConnectorBuilder};
use data_transmission::error;

use crate::domain::{user::User, credentials::Credentials};

/// 待绑定到当前用户的角色与权限
#[derive(Debug, Clone)]
pub struct RoleToBind {
    pub role_msg_id: String,
}

/// 待绑定应用
#[derive(Debug, Clone)]
pub struct ApplicationToBind {
    pub application_msg_id: String,
}

pub trait AuthenticationConnector: Connector {}

pub trait AuthenticationConnectorBuilder: ConnectorBuilder {
    /// 绑定应用
    /// 
    /// 绑定应用后可让当前用户第一次登录应用时，自动绑定当前应用相关角色
    fn bind_application(self, application_msg_id: &str) -> Self;
}

/// 认证连接器类型
#[derive(Clone)]
pub enum AuthenticationConnectorType {
    /// web 连接器
    Web,
    /// Inner 连接器
    Inner,
}

/// 获取认证当前用户结构
#[derive(Debug, Clone)]
pub enum AuthenticationCurrentUserResult {
    /// 当前用户
    /// 
    /// (当前用户, 自动登录信息)
    User(
        User,
        Option<Credentials>
    ),
    /// 出错
    Error(error::Error),
}