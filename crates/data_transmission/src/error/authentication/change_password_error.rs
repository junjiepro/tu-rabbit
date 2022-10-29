//! 修改密码相关错误
//! 
//! msg_code 以100开始分配

use crate::error::Error;
use telemetry::error_chain_fmt;
use actix_web::http::StatusCode;

#[derive(thiserror::Error)]
pub enum ChangePasswordError {
    #[error("Two different new passwords")]
    DifferentPasswordError(#[source] anyhow::Error),
    #[error("Username not exist")]
    UsernameNotExistError(#[source] anyhow::Error),
}

impl std::fmt::Debug for ChangePasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl<'a> From<ChangePasswordError> for Error {
    fn from(error: ChangePasswordError) -> Self {
        match error {
            ChangePasswordError::DifferentPasswordError(_) => Error {
                error_code: StatusCode::BAD_REQUEST.as_u16(),
                msg_code: 102,
                msg_id: "authentication.changePasswordError.differentPasswordError".to_string()
            },
            ChangePasswordError::UsernameNotExistError(_) => Error {
                error_code: StatusCode::BAD_REQUEST.as_u16(),
                msg_code: 109,
                msg_id: "authentication.changePasswordError.usernameNotExistError".to_string()
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
    fn turn_change_password_error_into_error_success() {
        // Act - ChangePasswordError::DifferentPasswordError
        let error: Error = authentication::ChangePasswordError::DifferentPasswordError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::BAD_REQUEST.as_u16(), error.status_code());
        assert_eq!(102, error.msg_code);

        // Act - ChangePasswordError::UsernameNotExistError
        let error: Error = authentication::ChangePasswordError::UsernameNotExistError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::BAD_REQUEST.as_u16(), error.status_code());
        assert_eq!(109, error.msg_code);
    }
}