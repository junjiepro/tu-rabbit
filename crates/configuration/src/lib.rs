//! configuration 配置
//! 
//! 提供配置读取等功能

use std::path::PathBuf;

use config::Config;

pub fn get_configuration(base_path: PathBuf, application: &str) ->Result<Config, config::ConfigError> {
    let configuration_directory = base_path.join(format!("configuration/{}", application));

    // Detect the running environment.
    // Default to `local` if unspecified.
    let environment: Environment = std::env::var("APP_ENVIRONMENT")
        .unwrap_or_else(|_| "local".into())
        .try_into()
        .expect("Failed to parse APP_ENVIRONMENT.");
    let environment = environment.as_str();

    let prefix = format!("app_{}", application);
    let settings = Config::builder()
        .add_source(config::File::from(configuration_directory.join("base")).required(true))
        .add_source(config::File::from(configuration_directory.join(environment)).required(true))
        // Add in settings from environment variables (with a prefix of APP and '__' as separator)
        // E.g. `APP_APPLICATION__PORT=5001 would set `Settings.application.port`
        .add_source(config::Environment::with_prefix(&prefix).separator("__"))
        .build()?;
    
    // Try to convert the configuration values it read into
    // our Settings type
    // settings.try_deserialize()
    Ok(settings)
}

/// The possible runtime environment for our application.
pub enum Environment {
    Local,
    Production,
}

impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Local => "local",
            Environment::Production => "production",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "production" => Ok(Self::Production),
            other => Err(format!(
                "{} is not a supported environment. Use either `local` or `production`.",
                other
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::get_configuration;
    use serde_aux::field_attributes::deserialize_number_from_string;
    use std::env;
    use uuid::Uuid;

    #[derive(serde::Deserialize, Clone)]
    struct Settings {
        pub application: ApplicationSettings,
    }

    #[derive(serde::Deserialize, Clone)]
    struct ApplicationSettings {
        #[serde(deserialize_with = "deserialize_number_from_string")]
        pub port: u16,
        pub host: String,
        pub base_url: Option<String>,
    }

    #[test]
    fn get_configuration_with_invalid_path_return_error() {
        // Arrange
        let key = "APP_ENVIRONMENT";
        env::remove_var(key);
        let application = "invalid";
        let custom_key = format!("APP_{}_APPLICATION__HOST", &application);
        env::remove_var(&custom_key);

        // Act
        let base_path = std::env::current_dir().expect("Failed to determine the current directory");
        let config = get_configuration(base_path, application);
        env::remove_var(key);
        env::remove_var(&custom_key);

        // Assert
        assert!(config.is_err());
    }

    #[test]
    fn get_configuration_with_valid_path_return_default_local_settings() {
        // Arrange
        let key = "APP_ENVIRONMENT";
        env::remove_var(key);
        let application = "test";
        let custom_key = format!("APP_{}_APPLICATION__HOST", &application);
        env::remove_var(&custom_key);

        // Act
        let base_path = std::env::current_dir().expect("Failed to determine the current directory");
        let config = get_configuration(base_path, application).unwrap();
        let settings: Settings = config.try_deserialize().unwrap();
        env::remove_var(key);
        env::remove_var(&custom_key);

        // Assert
        assert_eq!(8020, settings.application.port);
        assert_eq!("127.0.0.1".to_string(), settings.application.host);
        assert!(settings.application.base_url.is_some());
        assert_eq!("http://127.0.0.1".to_string(), settings.application.base_url.unwrap());
    }

    #[test]
    fn get_configuration_with_valid_path_and_production_env_return_production_settings() {
        // Arrange
        let key = "APP_ENVIRONMENT";
        env::remove_var(&key);
        env::set_var(key, "production");
        let application = "test";
        let custom_key = format!("APP_{}_APPLICATION__HOST", &application);
        env::remove_var(&custom_key);

        // Act
        let base_path = std::env::current_dir().expect("Failed to determine the current directory");
        let config = get_configuration(base_path, application).unwrap();
        let settings: Settings = config.try_deserialize().unwrap();
        env::remove_var(key);
        env::remove_var(&custom_key);

        // Assert
        assert_eq!(8020, settings.application.port);
        assert_eq!("0.0.0.0".to_string(), settings.application.host);
        assert!(settings.application.base_url.is_none());
    }

    #[test]
    fn get_configuration_with_valid_path_and_custom_env_return_default_local_settings_with_custom_value() {
        // Arrange
        let key = "APP_ENVIRONMENT";
        env::remove_var(key);
        let application = "test";
        let custom_key = "APP_APPLICATION__HOST"; // format!("APP_{}_APPLICATION__HOST", &application);
        let value = Uuid::new_v4().to_string();
        env::set_var(custom_key, &value);

        // Act
        let base_path = std::env::current_dir().expect("Failed to determine the current directory");
        let config = get_configuration(base_path, application).unwrap();
        let settings: Settings = config.try_deserialize().unwrap();
        env::remove_var(key);
        env::remove_var(custom_key);

        // Assert
        assert_eq!(8020, settings.application.port);
        assert_eq!(value, settings.application.host);
        assert!(settings.application.base_url.is_some());
        assert_eq!("http://127.0.0.1".to_string(), settings.application.base_url.unwrap());
    }
}