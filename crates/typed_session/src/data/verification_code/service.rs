//! 验证码相关功能服务

use crate::typed_session::TypedSession;
use crate::data::verification_code::VerificationCode;

#[tracing::instrument(
    name = "Generate verification code",
    skip(session, key),
    fields(key=tracing::field::Empty)
)]
fn generate_verification_code(
    session: TypedSession,
    key: String,
) -> Result<VerificationCode, serde_json::Error> {
    tracing::Span::current()
        .record("key", &tracing::field::display(&key));
    
    let verification_code = VerificationCode::build(key);
    session.insert(&verification_code)?;

    Ok(verification_code)
}