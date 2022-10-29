//! web 连接器

use crate::connectors::MailConnector;
use anyhow::Context;
use connector::Connector;
use data_transmission::{error::{self, CommonError}, web::get_empty_http_data_wraper_from_str};

/// web 连接器
#[derive(Debug, Clone)]
pub struct WebMailConnector {
    pub(crate) address: String,
    pub(crate) client: reqwest::Client,
}

impl Connector for WebMailConnector {}

impl MailConnector for WebMailConnector {}

impl WebMailConnector {
    /// 健康检查
    pub async fn health_check(&self) -> Result<(), error::Error> {
        let response = self.client
            .get(&format!("{}/health-check", &self.address))
            .send()
            .await
            .context("Failed to execute request.")
            .map_err(|e| <error::Error>::from(CommonError::UnexpectedError(e)))?;
        
        let status_code = response.status();
        let context = response.text().await.unwrap().clone();
        if status_code.eq(&200) {
            let data = get_empty_http_data_wraper_from_str(context.as_str());
            match data {
                Some(data) => {
                    if data.is_success() {
                        Ok(())
                    } else {
                        match data.get_error() {
                            Some(error ) => Err(error),
                            None => Err(error::Error::default()),
                        }
                    }
                    
                },
                None => Err(error::Error::default()),
            }
        } else {
            Err(error::Error::default())
        }
    }
}
