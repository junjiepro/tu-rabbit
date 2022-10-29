//! 认证相关实体

use data_transmission::data::TransmissionData;
use serde::{Serialize, Deserialize};
use secrecy::Secret;

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials.")]
    InvalidCredentials(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: Secret<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsData {
    pub username: String,
    pub password: Secret<String>,
    pub auto_login: bool,
    pub user_type: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateCredentialsResult {
    pub status: String,
    pub status_code: u16,
}

impl<'a> TransmissionData<'a> for ValidateCredentialsResult {}

impl Default for ValidateCredentialsResult {
    fn default() -> Self {
        Self { status: "success".to_string(), status_code: 0 }
    }
}