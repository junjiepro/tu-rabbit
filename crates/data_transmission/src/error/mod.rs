//! 定义错误传输格式
//! 
//! 

use crate::data::TransmissionData;
use telemetry::error_chain_fmt;
use serde::{Serialize, Deserialize};
use actix_web::http::StatusCode;

pub mod authentication;
pub mod openapi;

/// 错误
/// 
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Error {
    error_code: u16,
    /// 每种包相关错误以百位以上数字区分
    pub msg_code: u16,
    /// 用以获取国际化文本
    pub msg_id: String,
}

impl TransmissionData<'_> for Error {}

impl Default for Error {
    fn default() -> Self {
        CommonError::UnexpectedError(anyhow::anyhow!("Default Unexpected Error")).into()
    }
}

impl Error {
    pub fn build(error_code: u16, msg_code: u16, msg_id: &str) -> Error {
        Error {
            error_code,
            msg_code,
            msg_id: msg_id.to_string(),
        }
    }

    pub fn status_code(&self) -> StatusCode {
        match StatusCode::from_u16(self.error_code) {
            Ok(status_code) => status_code,
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(thiserror::Error)]
pub enum CommonError {
    #[error("No Permission to access")]
    NoPermissionError(#[source] anyhow::Error),
    #[error("Invalid input")]
    InvalidInputError(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl std::fmt::Debug for CommonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl<'a> From<CommonError> for Error {
    fn from(error: CommonError) -> Self {
        match error {
            CommonError::NoPermissionError(_) => Error {
                error_code: StatusCode::FORBIDDEN.as_u16(),
                msg_code: 1,
                msg_id: "noPermissionError".to_string()
            },
            CommonError::InvalidInputError(_) => Error {
                error_code: StatusCode::BAD_REQUEST.as_u16(),
                msg_code: 2,
                msg_id: "invalidInputError".to_string()
            },
            CommonError::UnexpectedError(_) => Error {
                error_code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                msg_code: 0,
                msg_id: "internalServerError".to_string()
            },
        }
    }
}