//! 认证、授权相关错误
//! 
//! msg_code 以100开始分配
//! 
//! next msg_code 110

mod validate_error;
mod change_password_error;
mod generate_verification_code_and_send_error;
mod register_user_error;
mod namespace_error;

pub use validate_error::*;
pub use change_password_error::*;
pub use generate_verification_code_and_send_error::*;
pub use register_user_error::*;
pub use namespace_error::*;