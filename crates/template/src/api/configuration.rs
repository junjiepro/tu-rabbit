//! 配置
//! 
//! 获取服务配置

use std::path::PathBuf;

use configuration::get_configuration;
use secrecy::Secret;
use serde_aux::field_attributes::deserialize_number_from_string;

#[derive(serde::Deserialize, Clone)]
pub struct Settings {
    pub application: ApplicationSettings,
}

#[derive(serde::Deserialize, Clone)]
pub struct ApplicationSettings {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    pub host: String,
    pub base_url: String,
    pub hmac_secret: Secret<String>
}

pub fn get_template_configuration(base_path: Option<PathBuf>) ->Result<Settings, config::ConfigError> { 
    let base_path = match base_path {
        Some(base_path) => base_path,
        None => std::env::current_dir().expect("Failed to determine the current directory")
    };
    get_configuration(base_path, "template")?.try_deserialize()
}