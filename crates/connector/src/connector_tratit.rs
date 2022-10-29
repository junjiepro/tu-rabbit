//! 连接器
//! 

use actix_service::ServiceFactory;
use actix_web::{Error, Scope};
use actix_web::dev::{ServiceRequest, ServiceResponse};

/// 连接器
pub trait Connector: Send + Sync + 'static {}

/// 连接器服务
pub trait ConnectorServer: Send + Sync + 'static {

    /// 连接器服务工厂
    fn service_factory<
        T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = Error,
            InitError = (),
        >
    >(&self, path: Option<&str>, scope: Scope<T>) -> Scope<T>;

    /// 连接器服务数据
    fn service_app_data<
        T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = Error,
            InitError = (),
        >
    >(&self, scope: Scope<T>) -> Scope<T>;
}

/// 连接器构建器
pub trait ConnectorBuilder {
    /// 连接器
    type Connector: Connector;
    /// 连接器服务
    type ConnectorServer: ConnectorServer;

    /// 生成连接器
    fn build_connector(&self) -> Self::Connector;

    /// 生成连接器服务
    fn build_connector_server(&self) -> Self::ConnectorServer;
}

/// 连接器服务 trait
pub trait ConnectorServiceExt {

    /// 提供连接器服务与数据
    fn connector_service<
        S: ConnectorServer,
    >(
        self: Self,
        path: Option<&str>,
        connector_server: &S,
    ) -> Self;

    /// 提供连接器服务
    fn service_with_connector_server<
        S: ConnectorServer,
    >(
        self: Self,
        path: Option<&str>,
        connector_server: &S,
    ) -> Self;

    /// 提供连接器服务数据
    fn service_app_data_with_connector_server<
        S: ConnectorServer,
    >(
        self: Self,
        connector_server: &S,
    ) -> Self;
}

/// 为 actix_web::Scope 实现注册连接器服务 trait
impl<T> ConnectorServiceExt for Scope<T>
where
    T: ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = Error,
        InitError = (),
    >,
{
    fn service_with_connector_server<
        S: ConnectorServer,
    >(
        self: Self,
        path: Option<&str>,
        connector_server: &S,
    ) -> Self {
        connector_server.service_factory(path, self)
    }

    fn service_app_data_with_connector_server<
        S: ConnectorServer,
    >(
        self: Self,
        connector_server: &S,
    ) -> Self {
        connector_server.service_app_data(self)
    }

    fn connector_service<
        S: ConnectorServer,
    >(
        self: Self,
        path: Option<&str>,
        connector_server: &S,
    ) -> Self {
        let s = connector_server.service_factory(path, self);
        connector_server.service_app_data(s)
    }
}

