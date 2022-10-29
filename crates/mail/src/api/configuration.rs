//! 配置
//! 
//! 获取服务配置

use std::{path::PathBuf, time::Duration};

use configuration::get_configuration;
use lettre::{smtp::authentication::{Credentials, Mechanism}, SmtpTransport, SmtpClient, ClientSecurity};
use secrecy::{Secret, ExposeSecret};
use serde_aux::field_attributes::deserialize_number_from_string;

#[derive(serde::Deserialize, Clone)]
pub struct Settings {
    pub application: ApplicationSettings,
    pub mail: MailSettings,
}

#[derive(serde::Deserialize, Clone)]
pub struct ApplicationSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub host: String,
    pub base_url: String,
    pub hmac_secret: Secret<String>
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct MailSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub(crate) port: u16,
    pub(crate) host: String,
    pub(crate) username: String,
    pub(crate) password: Secret<String>,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub(crate) timeout: u64,
}

impl MailSettings {
    pub fn smtp_transport(&self) -> SmtpTransport {
        let credentials = Credentials::new(
            self.username.clone(),
            self.password.expose_secret().clone(),
        );

        SmtpTransport::new(
            SmtpClient::new(
                (self.host.clone(), self.port),
                ClientSecurity::None,
            )
            .unwrap()
            .credentials(credentials)
            .authentication_mechanism(Mechanism::Login)
            .timeout(Some(Duration::from_secs(self.timeout)))
            .smtp_utf8(true)
        )
    }
}

pub fn get_mail_configuration(base_path: Option<PathBuf>) ->Result<Settings, config::ConfigError> { 
    let base_path = match base_path {
        Some(base_path) => base_path,
        None => std::env::current_dir().expect("Failed to determine the current directory")
    };
    get_configuration(base_path, "mail")?.try_deserialize()
}