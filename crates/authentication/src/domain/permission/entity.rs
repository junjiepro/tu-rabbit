//! 权限相关实体

use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use typed_session::TypedSessionData;
use data_transmission::data::DataEntity;
use crate::domain::namespace::{Namespace, NamespaceType};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Permission {
    /// 权限编号 唯一
    pub(crate) permission_id: uuid::Uuid,
    /// 国际化消息编号 唯一
    pub(crate) msg_id: String,
    /// 默认消息
    pub(crate) default_msg: String,
    /// 权限值 唯一
    pub(crate) permission: String,
    /// 备注
    pub(crate) remarks: String,
}

impl Permission {
    pub fn get_permission_id(&self) -> uuid::Uuid {
        self.permission_id
    }

    pub fn get_msg_id(&self) -> &str {
        &self.msg_id
    }
}

impl DataEntity for Permission {
    fn pre_insert(&mut self) {
        self.permission_id = uuid::Uuid::new_v4();
    }

    fn pre_update(&mut self) {
        
    }
}

/// 角色、权限关系
#[derive(Debug, Clone)]
pub struct RoleAndPermission {
    pub(crate) role_id: uuid::Uuid,
    pub(crate) permission_id: uuid::Uuid,
}

/// 权限扩展
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionExt {
    /// 权限编号 唯一
    pub(crate) permission_id: uuid::Uuid,
    /// 国际化消息编号 唯一
    pub(crate) msg_id: Option<String>,
    /// 默认消息
    pub(crate) default_msg: Option<String>,
    /// 权限值 唯一
    pub(crate) permission: Option<String>,
    /// 备注
    pub(crate) remarks: Option<String>,
    /// 绑定角色
    pub(crate) role_ids: Option<Vec<uuid::Uuid>>,
}

impl PermissionExt {
    pub fn get_permission(&self) -> Option<Permission> {
        if self.msg_id.is_some() &&
            self.default_msg.is_some() &&
            self.permission.is_some() &&
            self.remarks.is_some()
        {
            Some(Permission {
                permission_id: self.permission_id,
                msg_id: self.msg_id.as_ref().unwrap().clone(),
                default_msg: self.default_msg.as_ref().unwrap().clone(),
                permission: self.permission.as_ref().unwrap().clone(),
                remarks: self.remarks.as_ref().unwrap().clone(),
            })
        } else {
            None
        }
    }

    pub fn get_role_and_permission_array(&self) -> Option<Vec<RoleAndPermission>> {
        if self.role_ids.is_some() {
            Some(
                self
                    .role_ids
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|role_id| RoleAndPermission { role_id: *role_id, permission_id: self.permission_id.clone() })
                    .collect()
            )
        } else {
            None
        }
    }
}

/// 当前用户权限
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentUserPermissions {
    permissions: Vec<Namespace>,
}

impl CurrentUserPermissions {
    pub(crate) fn build(permissions: &Vec<Permission>) -> Self {
        // 权限转命名空间
        let mut permissions: Vec<Namespace> = permissions
            .iter()
            .map(|permission| permission.into())
            .filter(|permission: &Namespace| permission.get_namespace_type() != NamespaceType::Invalid)
            .collect();
        // 扩展命名空间，admin/:admin 也拥有上一层的命名空间
        let mut expands: Vec<Namespace> = permissions
            .iter()
            .filter_map(|permission|
                if permission.get_value() == "admin" {
                    Some("")
                } else {
                    permission
                        .get_value()
                        .strip_suffix(":admin")
                }
            )
            .filter_map(|permission|
                Namespace::has(permission)
                    .map_or_else(|_| None, |v| Some(v))
            )
            .collect();

        permissions.append(&mut expands);

        Self { permissions }
    }

    pub fn get_permissions(&self) -> &Vec<Namespace> {
        &self.permissions
    }

    pub fn is_super_admin(&self) -> bool {
        self
            .permissions
            .iter()
            .any(|p| p.get_value() == "admin" || p.get_value() == "")
    }

    pub fn is_admin(&self) -> bool {
        self.is_super_admin() ||
        self
            .permissions
            .iter()
            .any(|p| p.get_value().strip_suffix(":admin").is_some())
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        match Namespace::validate_required_namespace(
            &self.permissions,
            permission
        ) {
            Ok(has) => has,
            Err(_) => false,
        }
    }
}

impl TypedSessionData for CurrentUserPermissions {
    const TYPED_SESSION_KEY: &'static str = "current_user_permissions";

    fn typed_session_key(&self) -> &str {
        Self::TYPED_SESSION_KEY
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::permission::{Permission, CurrentUserPermissions};
    use regex::Regex;

    fn build_invalid_permission() -> Permission {
        let re = Regex::new("[0-9]+").unwrap();
        Permission {
            permission_id: uuid::Uuid::new_v4(),
            msg_id: uuid::Uuid::new_v4().to_string(),
            default_msg: uuid::Uuid::new_v4().to_string(),
            permission: re.replace_all(&uuid::Uuid::new_v4().to_string(), "a").to_string(),
            remarks: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn build_valid_permission() -> Permission {
        let re = Regex::new("[0-9]+").unwrap();
        Permission {
            permission_id: uuid::Uuid::new_v4(),
            msg_id: uuid::Uuid::new_v4().to_string(),
            default_msg: uuid::Uuid::new_v4().to_string(),
            permission: re.replace_all(&uuid::Uuid::new_v4().to_string(), "a").to_string().replace("-", ":"),
            remarks: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn build_valid_admin_permission() -> Permission {
        let re = Regex::new("[0-9]+").unwrap();
        Permission {
            permission_id: uuid::Uuid::new_v4(),
            msg_id: uuid::Uuid::new_v4().to_string(),
            default_msg: uuid::Uuid::new_v4().to_string(),
            permission: format!("{}:admin", re.replace_all(&uuid::Uuid::new_v4().to_string(), "a").to_string().replace("-", ":")),
            remarks: uuid::Uuid::new_v4().to_string(),
        }
    }

    #[test]
    fn build_with_invalid_permission_return_empty_current_user_permissions() {
        // Arrange
        let permissions: Vec<Permission> = (0..10)
            .map(|_| build_invalid_permission())
            .collect();

        // Act
        let result = CurrentUserPermissions::build(&permissions);

        // Assert
        assert_eq!(0, result.get_permissions().len());
    }

    #[test]
    fn build_with_valid_permission_return_valid_current_user_permissions() {
        // Arrange
        let permissions: Vec<Permission> = (0..10)
            .map(|_| build_valid_permission())
            .collect();
        // Act
        let result = CurrentUserPermissions::build(&permissions);

        // Assert
        assert_eq!(10, result.get_permissions().len());

        // Arrange
        let mut permissions: Vec<Permission> = (0..10)
            .map(|_| build_valid_permission())
            .collect();
        permissions.push(build_valid_admin_permission());

        // Act
        let result = CurrentUserPermissions::build(&permissions);

        // Assert
        assert_eq!(12, result.get_permissions().len());
    }
}