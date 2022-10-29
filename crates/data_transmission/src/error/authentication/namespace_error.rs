use crate::error::Error;
use telemetry::error_chain_fmt;
use actix_web::http::StatusCode;

/// 命名空间值校验错误
#[derive(thiserror::Error)]
pub enum ValidateValueError {
    #[error("Invalid value, only support [A-Za-z] and [:].")]
    InvalidValue,
}

impl std::fmt::Debug for ValidateValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl<'a> From<ValidateValueError> for Error {
    fn from(error: ValidateValueError) -> Self {
        match error {
            ValidateValueError::InvalidValue => Error {
                error_code: StatusCode::BAD_REQUEST.as_u16(),
                msg_code: 108,
                msg_id: "authentication.namespaceError.validateValueError".to_string()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::error::authentication;
    use actix_web::http::StatusCode;

    #[test]
    fn turn_validate_value_error_into_error_success() {
        // Act - ValidateValueError::AuthError
        let error: Error = authentication::ValidateValueError::InvalidValue.into();

        // Assert
        assert_eq!(StatusCode::BAD_REQUEST.as_u16(), error.status_code());
        assert_eq!(108, error.msg_code);
    }
}