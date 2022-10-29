//! 验证码相关实体

use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

use crate::typed_session::{TypedSessionData, TypedSessionExt};

/// 验证码
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationCode {
    key: String,
    code: String,
}

impl VerificationCode {
    pub fn build(key: String) -> Self {
        let code = Uuid::new_v4().to_string();
        VerificationCode {
            key,
            code,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    pub fn get_key(&self) -> &str {
        &self.key
    }

    pub fn get_code(&self) -> &str {
        &self.code
    }

    pub fn validate_verification_code(&self, key: &str, code: &str) -> bool {
        if &self.key == key && &self.code == code {
            true
        } else {
            false
        }
    }
}

impl Default for VerificationCode {
    fn default() -> Self {
        Self { key: "".into(), code: "".into() }
    }
}

impl TypedSessionData for VerificationCode {
    const TYPED_SESSION_KEY: &'static str = "verification_code";

    fn typed_session_key(&self) -> &str {
        VerificationCode::TYPED_SESSION_KEY
    }
}

impl FromRequest for VerificationCode {
    type Error = actix_web::Error;

    type Future = Ready<Result<VerificationCode, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let session = req.get_typed_session();
        ready(
            match session.get::<VerificationCode>() {
                Ok(Some(code)) => Ok(code),
                Ok(None) => Ok(VerificationCode::default()),
                Err(e) => Err(e.into()),
            }
        )
    }
}