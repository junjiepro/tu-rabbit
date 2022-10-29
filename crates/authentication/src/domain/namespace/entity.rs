//! 命名空间相关实体

use data_transmission::error::authentication::ValidateValueError;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Serialize, Deserialize};

use crate::domain::permission::Permission;

/// 命名空间
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Namespace {
    value: String,
    namespace_type: u8,
}

impl Namespace {
    /// 校验命名空间值是否有效
    pub fn validate_value(namespace: &str) -> Result<(), ValidateValueError> {
        lazy_static! {
            static ref RE: Regex = Regex::new("^[A-Za-z]+(:[A-Za-z]+)*$").unwrap();
        }
        if namespace == "" || RE.is_match(namespace) {
            Ok(())
        } else {
            Err(ValidateValueError::InvalidValue)
        }
    }

    /// 校验消息编号是否有效
    pub fn validate_msg(msg: &str) -> Result<bool, ValidateValueError> {
        lazy_static! {
            static ref RE: Regex = Regex::new("^[A-Za-z]+(.[A-Za-z]+)*$").unwrap();
        }
        if RE.is_match(msg) {
            Ok(true)
        } else {
            Err(ValidateValueError::InvalidValue)
        }
    }

    /// 校验是否满足命名空间要求
    pub fn validate_required_namespace(namespaces: &Vec<Namespace>, required_namespace: &str) -> Result<bool, ValidateValueError> {
        Self::validate_value(required_namespace)?;
        if namespaces.len() == 0 {
            Ok(false)
        } else {
            Ok(namespaces.iter().any(|n| n.validate(required_namespace)))
        }
    }

    /// 是该命名空间
    pub fn is(namespace: impl Into<String>) -> Result<Self, ValidateValueError> {
        Self::build(namespace, NamespaceType::Is)
    }

    /// 该命名空间之下
    pub fn has(namespace: impl Into<String>) -> Result<Self, ValidateValueError> {
        Self::build(namespace, NamespaceType::Has)
    }

    /// 不是该命名空间
    pub fn not(namespace: impl Into<String>) -> Result<Self, ValidateValueError> {
        Self::build(namespace, NamespaceType::Not)
    }

    fn build(namespace: impl Into<String>, namespace_type: NamespaceType) -> Result<Self, ValidateValueError> {
        let namespace = namespace.into();
        match Self::validate_value(&namespace) {
            Err(ValidateValueError::InvalidValue) => Err(ValidateValueError::InvalidValue),
            _ => Ok(Namespace {
                value: namespace,
                namespace_type: namespace_type.into(),
            })
        }
    }

    pub fn get_namespace_type(&self) -> NamespaceType {
        self.namespace_type.into()
    }

    pub fn get_value(&self) -> &str {
        &self.value
    }

    /// 校验是否满足命名空间要求
    pub fn validate(&self, namespace: &str) -> bool {
        match self.namespace_type.into() {
            NamespaceType::Is => &self.value == namespace,
            NamespaceType::Has => &self.value == "" || &self.value == namespace || namespace.starts_with(&format!("{}:", &self.value)),
            NamespaceType::Not => &self.value != namespace,
            NamespaceType::Invalid => false,
        }
    }
}

impl From<&Permission> for Namespace {
    fn from(permission: &Permission) -> Self {
        match Self::has(&permission.permission) {
            Ok(namespace) => namespace,
            Err(_) => Self {
                value: "__Invalid__".into(),
                namespace_type: NamespaceType::Invalid.into(),
            }
        }
    }
}

/// 命名空间类型
#[derive(PartialEq)]
pub enum NamespaceType {
    Is,
    Has,
    Not,
    /// 异常
    Invalid,
}

impl From<NamespaceType> for u8 {
    fn from(namespace_type: NamespaceType) -> Self {
        match namespace_type {
            NamespaceType::Is => 1,
            NamespaceType::Has => 2,
            NamespaceType::Not => 3,
            NamespaceType::Invalid => 4,
        }
    }
}

impl From<u8> for NamespaceType {
    fn from(namespace_type: u8) -> Self {
        match namespace_type {
            1 => NamespaceType::Is,
            2 => NamespaceType::Has,
            3 => NamespaceType::Not,
            _ => NamespaceType::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::namespace::Namespace;

    #[test]
    fn validate_value_with_valid_value_return_success() {
        // Act
        let result = Namespace::validate_value("hello:world:user");

        // Assert
        assert!(result.is_ok());

        // Act
        let result = Namespace::validate_value("");

        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn validate_value_with_invalid_value_return_error() {
        // Act
        let result = Namespace::validate_value("hello:world:user123");

        // Assert
        assert!(result.is_err());

        // Act
        let result = Namespace::validate_value("hello:world::user");

        // Assert
        assert!(result.is_err());

        // Act
        let result = Namespace::validate_value("hello:world:user:");

        // Assert
        assert!(result.is_err());

        // Act
        let result = Namespace::validate_value(&uuid::Uuid::new_v4().to_string());

        // Assert
        assert!(result.is_err());
    }
}