//! 角色相关实体

use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use data_transmission::data::DataEntity;

use crate::domain::permission::RoleAndPermission;

/// 角色
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    /// 角色编号 唯一
    pub(crate) role_id: uuid::Uuid,
    /// 国际化消息编号 唯一
    pub(crate) msg_id: String,
    /// 默认消息
    pub(crate) default_msg: String,
    /// 命名空间
    pub(crate) namespace: String,
    /// 备注
    pub(crate) remarks: String,
}

impl Role {
    pub fn get_role_id(&self) -> uuid::Uuid {
        self.role_id
    }

    pub fn get_msg_id(&self) -> &str {
        &self.msg_id
    }
}

impl DataEntity for Role {
    fn pre_insert(&mut self) {
        self.role_id = uuid::Uuid::new_v4();
    }

    fn pre_update(&mut self) {
        
    }
}

/// 用户、角色关系
#[derive(Debug, Clone)]
pub struct UserAndRole {
    pub(crate) user_id: uuid::Uuid,
    pub(crate) role_id: uuid::Uuid,
}

/// 角色扩展
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleExt {
    /// 角色编号 唯一
    pub(crate) role_id: uuid::Uuid,
    /// 国际化消息编号 唯一
    pub(crate) msg_id: Option<String>,
    /// 默认消息
    pub(crate) default_msg: Option<String>,
    /// 命名空间
    pub(crate) namespace: Option<String>,
    /// 备注
    pub(crate) remarks: Option<String>,
    /// 绑定用户
    pub(crate) user_ids: Option<Vec<uuid::Uuid>>,
    /// 绑定权限
    pub(crate) permission_ids: Option<Vec<uuid::Uuid>>,
}

impl RoleExt {
    pub fn get_role(&self) -> Option<Role> {
        if self.msg_id.is_some() &&
            self.default_msg.is_some() &&
            self.namespace.is_some() &&
            self.remarks.is_some()
        {
            Some(Role {
                role_id: self.role_id,
                msg_id: self.msg_id.as_ref().unwrap().clone(),
                default_msg: self.default_msg.as_ref().unwrap().clone(),
                namespace: self.namespace.as_ref().unwrap().clone(),
                remarks: self.remarks.as_ref().unwrap().clone(),
            })
        } else {
            None
        }
    }

    pub fn get_user_and_role_array(&self) -> Option<Vec<UserAndRole>> {
        if self.user_ids.is_some() {
            Some(
                self
                    .user_ids
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|user_id| UserAndRole { user_id: *user_id, role_id: self.role_id.clone() })
                    .collect()
            )
        } else {
            None
        }
    }

    pub fn get_role_and_permission_array(&self) -> Option<Vec<RoleAndPermission>> {
        if self.permission_ids.is_some() {
            Some(
                self
                    .permission_ids
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|permission_id| RoleAndPermission { permission_id: *permission_id, role_id: self.role_id.clone() })
                    .collect()
            )
        } else {
            None
        }
    }
}