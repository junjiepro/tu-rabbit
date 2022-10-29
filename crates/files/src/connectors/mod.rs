//! connector 连接器
//! 
//! 提供连接器给其他应用以连接务

pub mod inner;
pub mod web;

use connector::{Connector, ConnectorBuilder};

pub trait FilesConnector: Connector {}

pub trait FilesConnectorBuilder: ConnectorBuilder {}

/// 连接器类型
#[derive(Clone)]
pub enum FilesConnectorType {
    /// web 连接器
    Web,
    /// Inner 连接器
    Inner,
}
