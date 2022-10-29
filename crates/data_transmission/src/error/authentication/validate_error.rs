//! 认证、授权相关错误
//! 
//! msg_code 以100开始分配

use crate::error::Error;
use telemetry::error_chain_fmt;
use actix_web::http::StatusCode;

#[derive(thiserror::Error)]
pub enum ValidateError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
}

impl std::fmt::Debug for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl<'a> From<ValidateError> for Error {
    fn from(error: ValidateError) -> Self {
        match error {
            ValidateError::AuthError(_) => Error {
                error_code: StatusCode::UNAUTHORIZED.as_u16(),
                msg_code: 101,
                msg_id: "authentication.validateError.authError".to_string()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::error::authentication;
    use actix_web::http::StatusCode;

    #[derive(thiserror::Error)]
    pub enum TestError {
        #[error("Something failed")]
        SomeError,
    }

    impl std::fmt::Debug for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(f, "{}\n", self)
        }
    }

    #[test]
    fn turn_validate_error_into_error_success() {
        // Act - ValidateError::AuthError
        let error: Error = authentication::ValidateError::AuthError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::UNAUTHORIZED.as_u16(), error.status_code());
        assert_eq!(101, error.msg_code);
    }
}