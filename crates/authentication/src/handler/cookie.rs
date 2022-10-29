use std::collections::BTreeMap;
use crate::domain::credentials::Credentials;
use crate::handler::jwt;
use actix_web::cookie::CookieBuilder;
use actix_web::cookie::time::Duration;
use actix_web::{HttpRequest, HttpResponse, cookie::Cookie};
use secrecy::Secret;

/// 从 cookie 中解析出来的认证数据
#[derive(Debug)]
pub struct CredentialsCookieData {
    username: Option<String>,
    password: Option<Secret<String>>,
}

impl CredentialsCookieData {
    pub fn to_credentials(self) -> Option<Credentials> {
        match (self.username, self.password) {
            (Some(username), Some(password)) => Some(
                Credentials { username, password }
            ),
            _ => None,
        }
    }
}

/// （认证成功后）设置认证 cookie
pub fn set_credentials_cookie(
    response: &mut HttpResponse,
    username: &str,
    password: &str,
    auto_login: bool,
    secret: &Secret<String>,
) -> Result<(), jwt::JWTError> {
    // Rememberme
    if auto_login {
        let mut claims = BTreeMap::new();
        claims.insert("username", username);
        claims.insert("password", password);
        response.add_cookie(
            &build_cookie(Cookie::build("rememberme", jwt::sign(claims, secret)?.as_str()))
        )
        .map_err(|e| jwt::JWTError::UnexpectedError(e.into()))?;
    }

    Ok(())
}

/// 清空认证 cookie
pub fn clear_credentials_cookie(mut response: HttpResponse,) -> HttpResponse {
    let result = response.add_cookie(
        &build_cookie(Cookie::build("rememberme", ""))
    );
    if let Err(_) = result {
        tracing::warn!("Failed to clear credentials cookie");
    }

    response
}

/// 从 cookie 中获取认证数据
pub fn get_credentials_cookie(
    request: &HttpRequest,
    secret: &Secret<String>,
) -> Result<CredentialsCookieData, jwt::JWTError> {
    // 解析 rememberme cookie 得到 username 和 password
    let (username, password) = match request.cookie("rememberme") {
        Some(rememberme) => {
            let value = rememberme.value();
            let claims = jwt::verificate(value, secret)?;
            (
                Some(claims["username"].to_owned()),
                Some(Secret::new(claims["password"].to_owned())),
            )
        },
        None => (None, None),
    };

    Ok(CredentialsCookieData {
        username,
        password,
    })
}

fn build_cookie(builder: CookieBuilder) -> Cookie {
    builder
        .path("/")
        .http_only(true)
        .max_age(Duration::days(360))
        .finish()
}