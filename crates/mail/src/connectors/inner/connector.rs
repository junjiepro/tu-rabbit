//! Inner 认证、授权连接器

use crate::{connectors::MailConnector, api::configuration::MailSettings, domain::mail_builder::MailBuilder};
use connector::Connector;
use data_transmission::error::{Error, CommonError};
use lettre::Transport;

/// Inner 连接器
#[derive(Debug, Clone)]
pub struct InnerMailConnector {}

impl Connector for InnerMailConnector {}

impl MailConnector for InnerMailConnector {}

impl InnerMailConnector {
    /// 健康检查
    pub async fn health_check(&self) -> Result<(), Error> {
        Ok(())
    }

    /// 发送邮件
    #[tracing::instrument(
        name = "Inner Connector -> Send Mail",
        skip(mail_settings, email_builder)
    )]
    pub fn send_mail(
        &self,
        mail_settings: &MailSettings,
        email_builder: MailBuilder,
    ) -> Result<(), CommonError> {
        match email_builder
                .to_email_builder()
                .from(&*mail_settings.username)
                .build()
        {
            Ok(email) => {
                // Open a connection
                let mut mailer = mail_settings.smtp_transport();

                // Send the email
                match mailer.send(email.into()) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(CommonError::UnexpectedError(e.into()))
                }
            },
            Err(e) => Err(CommonError::UnexpectedError(e.into()))
        }
    }
}
