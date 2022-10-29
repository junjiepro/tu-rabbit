//! Session 相关

mod typed_session;
pub mod data;

use actix_session::{SessionMiddleware, SessionMiddlewareBuilder, storage::RedisSessionStore};

use actix_web::cookie::Key;
pub use typed_session::*;

pub struct TypedSessionMiddleware {}

impl TypedSessionMiddleware {
    pub async fn store(redis_uri: impl Into<String>) -> Result<RedisSessionStore, anyhow::Error> {
        RedisSessionStore::new(redis_uri).await
    }

    pub fn builder(redis_store: RedisSessionStore, secret_key: Key) -> SessionMiddlewareBuilder<RedisSessionStore> {
        SessionMiddleware::builder(redis_store, secret_key)
            .cookie_http_only(true)
            .cookie_secure(false)
    }
}