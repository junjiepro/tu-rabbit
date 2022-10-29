//! authentication 认证、授权微服务
//! 
//! 把认证、授权功能构建为单独一个应用

use telemetry::{get_subscriber, init_subscriber};
use authentication::api;
use mail::api::configuration::get_mail_configuration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = get_subscriber("authentication".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    // Read configuration
    let configuration = api::configuration::get_authentication_configuration(None).expect("Failed to read configuration.");
    let mail_configuration = get_mail_configuration(None).expect("Failed to read configuration.");
    let application = api::application::Application::build(configuration, mail_configuration).await?;
    application.run_until_stopped().await?;

    Ok(())
}