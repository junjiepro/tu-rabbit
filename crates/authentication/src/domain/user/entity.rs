//! 用户相关实体

use data_transmission::data::TransmissionData;
use sqlx::{FromRow, Type};
use typed_session::data::verification_code::VerificationCode;
use secrecy::{Secret, ExposeSecret};
use serde::{Serialize, Deserialize, de::{self, Unexpected}};

use crate::domain::{role::{Role, UserAndRole}, permission::CurrentUserPermissions};

/// 用户
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// 用户编号 唯一
    pub(crate) user_id: uuid::Uuid,
    /// 用户名 唯一
    pub(crate) username: String,
    /// 用户类型
    user_type: Option<UserType>,
    /// 用户昵称
    pub(crate) name: Option<String>,
    /// 用户状态
    status: Option<Status>,
    /// 角色列表
    roles: Option<Vec<Role>>,
    /// 当前用户权限
    current_user_permissions: Option<CurrentUserPermissions>,
}

/// 用户
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UserListItem {
    /// 用户编号 唯一
    pub(crate) user_id: uuid::Uuid,
    /// 用户名 唯一
    username: String,
    /// 用户类型
    user_type: UserType,
    /// 用户昵称
    name: Option<String>,
    /// 用户状态
    status: Status,
}

impl UserListItem {
    pub fn get_user_id(&self) -> uuid::Uuid {
        self.user_id
    }

    pub fn get_name(&self) -> Option<&String> {
        self.name.as_ref()
    }
}

/// 用户扩展
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserExt {
    /// 用户编号 唯一
    pub(crate) user_id: uuid::Uuid,
    /// 用户名 唯一
    pub(crate) username: Option<String>,
    /// 用户类型
    pub(crate) user_type: Option<UserType>,
    /// 用户昵称
    pub(crate) name: Option<String>,
    /// 用户状态
    pub(crate) status: Option<Status>,
    /// 角色ID列表
    pub(crate) role_ids: Option<Vec<uuid::Uuid>>,
}

impl UserExt {
    pub fn get_user(&self) -> Option<User> {
        if self.name.is_some()
        {
            Some(User {
                user_id: self.user_id,
                username: "".to_string(),
                user_type: self.user_type.clone(),
                name: self.name.clone(),
                status: self.status.clone(),
                roles: None,
                current_user_permissions: None,
            })
        } else {
            None
        }
    }

    pub fn get_user_and_role_array(&self) -> Option<Vec<UserAndRole>> {
        if self.role_ids.is_some() {
            Some(
                self
                    .role_ids
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|role_id| UserAndRole { role_id: *role_id, user_id: self.user_id.clone() })
                    .collect()
            )
        } else {
            None
        }
    }
}

impl<'a> TransmissionData<'a> for User {}

impl User {
    pub(crate) fn build(user_id: uuid::Uuid, username: String, current_user_permissions: Option<CurrentUserPermissions>) -> User {
        User {
            user_id,
            username,
            user_type: None,
            name: None,
            status: None,
            roles: None,
            current_user_permissions,
        }
    }

    pub(crate) fn generate_guest_user() -> Self {
        let user_id = uuid::Uuid::new_v4();
        let username = format!("Guest-{}", &user_id);

        User {
            user_id,
            username,
            user_type: None,
            name: None,
            status: None,
            roles: None,
            current_user_permissions: None,
        }
    }

    pub(crate) fn is_guest_user(user_id: &uuid::Uuid, username: &str) -> bool {
        username == &format!("Guest-{}", &user_id)
    }

    pub fn get_user_id(&self) -> uuid::Uuid {
        self.user_id
    }

    pub fn get_username(&self) -> &str {
        &self.username
    }

    pub fn get_permissions(&self) -> Option<&CurrentUserPermissions> {
        self.current_user_permissions.as_ref()
    }

    pub fn permissions_string_array(&self) -> Vec<String> {
        if let Some(permissions) = self.current_user_permissions.as_ref() {
            permissions
                .get_permissions()
                .iter()
                .map(|permission| permission.get_value().into())
                .fold(vec![], |mut accum, item| {
                    if !accum.iter().any(|p| *p == item) {
                        accum.push(item);
                    }
                    accum
                })
        } else {
            vec![]
        }
    }
}

/// 注册用户
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterUser {
    username: String,
    user_type: UserType,
    password: Secret<String>,
    confirmed_password: Secret<String>,
    verification_code: String,
}

impl RegisterUser {
    pub(crate) fn get_username(&self) -> &str {
        &self.username
    }

    pub(crate) fn get_user_type(&self) -> i32 {
        self.user_type.clone().into()
    }

    pub(crate) fn get_password(&self) -> Secret<String> {
        self.password.clone()
    }

    pub(crate) fn get_verification_code(&self) -> &str {
        &self.verification_code
    }

    /// 检验密码与确认密码是否一致
    pub(crate) fn validate_password(&self) -> bool {
        if self.password.expose_secret() == self.confirmed_password.expose_secret() {
            true
        } else {
            false
        }
    }

    /// 校验验证码
    pub(crate) fn validate_verification_code(&self, verification_code: VerificationCode) -> bool {
        verification_code.validate_verification_code(
            &self.username,
            &self.verification_code,
        )
    }
}

/// 用户类型
#[derive(Debug, Clone, Type)]
#[repr(i32)]
pub enum UserType {
    AdminUser = 0,
    EmailUser = 1,
    PhoneUser = 2,
    WechatUser = 3,
}

impl From<UserType> for i32 {
    fn from(user_type: UserType) -> Self {
        match user_type {
            UserType::AdminUser => 0,
            UserType::EmailUser => 1,
            UserType::PhoneUser => 2,
            UserType::WechatUser => 3,
        }
    }
}

impl Serialize for UserType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_i32(i32::from(self.clone()))
    }
}

impl<'de> Deserialize<'de> for UserType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let i = i32::deserialize(deserializer)?;
        match i {
            0 => Ok(UserType::AdminUser),
            1 => Ok(UserType::EmailUser),
            2 => Ok(UserType::PhoneUser),
            3 => Ok(UserType::WechatUser),
            _ => Err(de::Error::invalid_type(Unexpected::Enum, &"an invalid integer")),
        }
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Default implementation just delegates to `deserialize` impl.
        *place = Deserialize::deserialize(deserializer)?;
        Ok(())
    }
}

/// 用户状态
#[derive(Debug, Clone, Type)]
#[repr(i32)]
pub enum Status {
    Unconfirmed = 0,
    Confirmed = 1,
    Deleted = 2,
}

impl From<Status> for i32 {
    fn from(status: Status) -> Self {
        match status {
            Status::Unconfirmed => 0,
            Status::Confirmed => 1,
            Status::Deleted => 2,
        }
    }
}

impl Serialize for Status {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_i32(i32::from(self.clone()))
    }
}

impl<'de> Deserialize<'de> for Status {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let i = i32::deserialize(deserializer)?;
        match i {
            0 => Ok(Status::Unconfirmed),
            1 => Ok(Status::Confirmed),
            2 => Ok(Status::Deleted),
            _ => Err(de::Error::invalid_type(Unexpected::Enum, &"an invalid integer")),
        }
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Default implementation just delegates to `deserialize` impl.
        *place = Deserialize::deserialize(deserializer)?;
        Ok(())
    }
}
