//! web 认证、授权连接器

use crate::{connectors::{AuthenticationConnector, AuthenticationCurrentUserResult, ApplicationToBind}, domain::user::User};
use actix_web::{HttpRequest, web::Data, Error};
use anyhow::Context;
use connector::Connector;
use data_transmission::{error::{self, CommonError}, web::{get_http_data_wraper_from_str, get_empty_http_data_wraper_from_str}};

/// web 认证、授权连接器
#[derive(Debug, Clone)]
pub struct WebAuthenticationConnector {
    pub(crate) address: String,
    pub(crate) client: reqwest::Client,
}

impl Connector for WebAuthenticationConnector {}

impl AuthenticationConnector for WebAuthenticationConnector {}

impl WebAuthenticationConnector {
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

    /// 获取当前用户
    pub(crate) async fn current_user(
        &self,
        request: &HttpRequest,
        application_to_bind: Result<Data<ApplicationToBind>, Error>,
    ) -> AuthenticationCurrentUserResult {
        let mut map = reqwest::header::HeaderMap::new();
        request
            .headers()
            .iter()
            .for_each(|(name, value)| {
                let name = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes().clone());
                let val = reqwest::header::HeaderValue::from_bytes(value.as_bytes().clone());
                if let (Ok(name), Ok(val)) = (name, val) {
                    map.insert(name, val);
                }
            });
        if let Ok(to_bind) = application_to_bind {
            if let Err(e) = self.client
                .get(&format!("{}/bind-current-user/{}", &self.address, to_bind.application_msg_id))
                .headers(map.clone())
                .send()
                .await
            {
                tracing::warn!("{:?}", e);
            }
        }
        let response = self.client
            .get(&format!("{}/current-user", &self.address))
            .headers(map)
            .send()
            .await
            .context("Failed to execute request.");
        let response = match response {
            Ok(response) => response,
            Err(e) => { return AuthenticationCurrentUserResult::Error(CommonError::UnexpectedError(e).into()); }
        };

        let status_code = response.status();
        let context = response.text().await.unwrap().clone();
        if status_code.eq(&200) {
            let user = get_http_data_wraper_from_str::<User>(context.as_str());
            match user {
                Some(user) => {
                    if user.is_success() {
                        match user.get_data() {
                            Some(user ) => AuthenticationCurrentUserResult::User(user, None),
                            None => AuthenticationCurrentUserResult::Error(error::Error::default()),
                        }
                    } else {
                        match user.get_error() {
                            Some(error ) => AuthenticationCurrentUserResult::Error(error),
                            None => AuthenticationCurrentUserResult::Error(error::Error::default()),
                        }
                    }
                    
                },
                None => AuthenticationCurrentUserResult::Error(error::Error::default()),
            }
        } else {
            AuthenticationCurrentUserResult::Error(error::Error::default())
        }
    }
}
