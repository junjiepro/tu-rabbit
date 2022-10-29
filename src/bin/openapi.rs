//! openapi openapi微服务
//! 
//! 把openapi功能构建为单独一个应用

use telemetry::{get_subscriber, init_subscriber};
use openapi::api;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = get_subscriber("openapi".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    // Read configuration
    let configuration = api::configuration::get_openapi_configuration(None).expect("Failed to read configuration.");
    let application = api::application::Application::build(configuration).await?;
    application.run_until_stopped().await?;

    Ok(())
}