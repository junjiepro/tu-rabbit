//! 生成验证码并发送相关错误
//! 
//! msg_code 以100开始分配

use crate::error::Error;
use telemetry::error_chain_fmt;
use actix_web::http::StatusCode;

#[derive(thiserror::Error)]
pub enum GenerateVerificationCodeError {
    #[error("Empty value")]
    EmptyValueError(#[source] anyhow::Error),
}

impl std::fmt::Debug for GenerateVerificationCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl<'a> From<GenerateVerificationCodeError> for Error {
    fn from(error: GenerateVerificationCodeError) -> Self {
        match error {
            GenerateVerificationCodeError::EmptyValueError(_) => Error {
                error_code: StatusCode::BAD_REQUEST.as_u16(),
                msg_code: 103,
                msg_id: "authentication.generateVerificationCodeError.emptyValueError".to_string()
            },
        }
    }
}

#[derive(thiserror::Error)]
pub enum SendVerificationCodeError {
    #[error("This type is not supported yet")]
    NotSupportedYetError(#[source] anyhow::Error),
}

impl std::fmt::Debug for SendVerificationCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl<'a> From<SendVerificationCodeError> for Error {
    fn from(error: SendVerificationCodeError) -> Self {
        match error {
            SendVerificationCodeError::NotSupportedYetError(_) => Error {
                error_code: StatusCode::NOT_IMPLEMENTED.as_u16(),
                msg_code: 104,
                msg_id: "authentication.sendVerificationCodeError.notSupportedYetError".to_string()
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
    fn turn_generate_verification_code_error_into_error_success() {
        // Act - GenerateVerificationCodeError::EmptyValueError
        let error: Error = authentication::GenerateVerificationCodeError::EmptyValueError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::BAD_REQUEST.as_u16(), error.status_code());
        assert_eq!(103, error.msg_code);
    }

    #[test]
    fn turn_send_verification_code_error_into_error_success() {
        // Act - SendVerificationCodeError::NotSupportedYetError
        let error: Error = authentication::SendVerificationCodeError::NotSupportedYetError(TestError::SomeError.into()).into();

        // Assert
        assert_eq!(StatusCode::BAD_REQUEST.as_u16(), error.status_code());
        assert_eq!(104, error.msg_code);
    }
}