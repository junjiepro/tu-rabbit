//! 生成验证码并发送

use std::fmt::Display;

use actix_web::{HttpResponse, web};
use data_transmission::{error::{authentication::{GenerateVerificationCodeError, SendVerificationCodeError}, CommonError}, web::{build_http_response_error_data, build_http_response_empty_data}};
use mail::{connectors::inner::InnerMailConnector, api::configuration::MailSettings, domain::mail_builder::MailBuilder};
use serde::{Deserialize, de::{Unexpected, self}};
use typed_session::{TypedSession, data::verification_code::VerificationCode};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateVerificationCodeData {
    pub key: String,
    pub key_type: SendVerificationCodeType,
}

pub enum SendVerificationCodeType {
    Email = 1,
    Phone = 2,
}

impl<'de> Deserialize<'de> for SendVerificationCodeType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let i = i32::deserialize(deserializer)?;
        match i {
            1 => Ok(SendVerificationCodeType::Email),
            2 => Ok(SendVerificationCodeType::Phone),
            _ => Err(de::Error::invalid_type(Unexpected::Enum, &"an invalid integer")),
        }
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Default implementation just delegates to `deserialize` impl.
        *place = Deserialize::deserialize(deserializer)?;
        Ok(())
    }
}

impl Display for SendVerificationCodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            SendVerificationCodeType::Email => "Email",
            SendVerificationCodeType::Phone => "Phone",
        })
    }
}

#[tracing::instrument(
    name = "Generate verification code and send API",
    skip(session, mail_connector, mail_settings, generate_verification_code_data),
    fields(key=tracing::field::Empty, key_type=tracing::field::Empty)
)]
pub async fn generate_verification_code_and_send(
    session: TypedSession,
    mail_connector: web::Data<InnerMailConnector>,
    mail_settings: web::Data<MailSettings>,
    generate_verification_code_data: web::Json<GenerateVerificationCodeData>,
) -> HttpResponse {
    // Key 空检验
    if generate_verification_code_data.key.is_empty() {
        build_http_response_error_data(
            GenerateVerificationCodeError::EmptyValueError(
                anyhow::anyhow!("Empty Key")
            )
        )
    } else {
        tracing::Span::current()
            .record("key", &tracing::field::display(&generate_verification_code_data.key))
            .record("key_type", &tracing::field::display(&generate_verification_code_data.key_type));
    
        // 生成验证码
        let code = VerificationCode::build(generate_verification_code_data.key.clone());
        // 保存在 Session
        match session.insert(&code) {
            Ok(_) => {
                // 发送验证码
                match generate_verification_code_data.key_type {
                    // 邮箱
                    SendVerificationCodeType::Email => {
                        match mail_connector.send_mail(
                            mail_settings.get_ref(),
                            MailBuilder::new()
                                .to(code.get_key())
                                .subject("TU-RABBIT Verification Code")
                                .text(format!("Your Verification Code: {}", code.get_code())),
                        ) {
                            Ok(_) => build_http_response_empty_data(),
                            Err(e) => build_http_response_error_data(e),
                        }
                    },
                    // 手机
                    SendVerificationCodeType::Phone => {
                        build_http_response_error_data(
                            SendVerificationCodeError::NotSupportedYetError(
                                anyhow::anyhow!("{} is not supported yet.", generate_verification_code_data.key_type)
                            )
                        )
                    },
                }
            },
            Err(err) => 
                build_http_response_error_data(
                    CommonError::UnexpectedError(
                        err.into()
                    )
                ),
        }
    }
}