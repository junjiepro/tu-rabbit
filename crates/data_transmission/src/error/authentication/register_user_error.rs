//! 认证、授权相关错误
//! 
//! msg_code 以100开始分配

use crate::error::Error;
use telemetry::error_chain_fmt;
use actix_web::http::StatusCode;

#[derive(thiserror::Error)]
pub enum RegisterUserError {
    #[error("Two different passwords")]
    DifferentPasswordError(#[source] anyhow::Error),
    #[error("Invalid verification code")]
    InvalidVerificationCodeError(#[source] anyhow::Error),
    #[error("Username already exist")]
    UsernameAlreadyExistError(#[source] anyhow::Error),
}

impl std::fmt::Debug for RegisterUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl<'a> From<RegisterUserError> for Error {
    fn from(error: RegisterUserError) -> Self {
        match error {
            RegisterUserError::DifferentPasswordError(_) => Error {
                error_code: StatusCode::BAD_REQUEST.as_u16(),
                msg_code: 105,
                msg_id: "authentication.registerUserError.differentPasswordError".to_string()
            },
            RegisterUserError::InvalidVerificationCodeError(_) => Error {
                error_code: StatusCode::BAD_REQUEST.as_u16(),
                msg_code: 106,
                msg_id: "authentication.registerUserError.invalidVerificationCodeError".to_string()
            },
            RegisterUserError::UsernameAlreadyExistError(_) => Error {
                error_code: StatusCode::BAD_REQUEST.as_u16(),
                msg_code: 107,
                msg_id: "authentication.registerUserError.usernameAlreadyExistError".to_string()
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
    fn turn_error_into_error_success() {
        // Act - RegisterUserError::DifferentPasswordError
        let error: Error = authentication::RegisterUserError::DifferentPasswordError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::BAD_REQUEST.as_u16(), error.status_code());
        assert_eq!(105, error.msg_code);

        // Act - RegisterUserError::InvalidVerificationCodeError
        let error: Error = authentication::RegisterUserError::InvalidVerificationCodeError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::BAD_REQUEST.as_u16(), error.status_code());
        assert_eq!(106, error.msg_code);

        // Act - RegisterUserError::UsernameAlreadyExistError
        let error: Error = authentication::RegisterUserError::UsernameAlreadyExistError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::BAD_REQUEST.as_u16(), error.status_code());
        assert_eq!(107, error.msg_code);
    }
}