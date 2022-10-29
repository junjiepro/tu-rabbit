//! openapi 相关错误
//! 
//! msg_code 以200开始分配
//! 
//! next msg_code 202

use crate::error::Error;
use telemetry::error_chain_fmt;
use actix_web::http::StatusCode;

#[derive(thiserror::Error)]
pub enum DeserializeError {
    #[error("Deserialize input failed")]
    DeserializeError(#[source] anyhow::Error),
}

impl std::fmt::Debug for DeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl<'a> From<DeserializeError> for Error {
    fn from(error: DeserializeError) -> Self {
        match error {
            DeserializeError::DeserializeError(_) => Error {
                error_code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                msg_code: 201,
                msg_id: "openapi.deserializeError.deserializeError".to_string()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::error::openapi;
    use actix_web::http::StatusCode;

    #[derive(thiserror::Error)]
    pub enum TestError {
        #[error("Something went wrong")]
        SomeError,
    }

    impl std::fmt::Debug for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f, "{}\n", self)
        }
    }

    #[test]
    fn turn_validate_error_into_error_success() {
        // Act - DeserializeError::DeserializeError
        let error: Error = openapi::DeserializeError::DeserializeError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR.as_u16(), error.status_code());
        assert_eq!(201, error.msg_code);
    }
}