//! Session

use actix_session::Session;
use actix_session::SessionExt;
use actix_web::dev::Payload;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::guard::GuardContext;
use actix_web::{FromRequest, HttpRequest};
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use std::future::{Ready, ready};

/// 定制session
pub struct TypedSession(Session);

impl std::fmt::Debug for TypedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_tuple("TypedSession")
            .field(&self.get_user_id())
            .field(&self.get_username())
            .finish()
    }
}

impl TypedSession {
    const USER_ID_KEY: &'static str = "user_id";
    const USERNAME_KEY: &'static str = "username";

    pub fn renew(&self) {
        self.0.renew();
    }

    pub fn insert_user_id(&self, user_id: Uuid) -> Result<(), serde_json::Error> {
        self.0.insert(Self::USER_ID_KEY, user_id)
    }

    pub fn get_user_id(&self) -> Result<Option<Uuid>, serde_json::Error> {
        self.0.get(Self::USER_ID_KEY)
    }

    pub fn insert_username(&self, username: impl Into<String>) -> Result<(), serde_json::Error> {
        self.0.insert(Self::USERNAME_KEY, username.into())
    }

    pub fn get_username(&self) -> Result<Option<String>, serde_json::Error> {
        self.0.get(Self::USERNAME_KEY)
    }

    pub fn log_out(&self) {
        self.0.purge()
    }

    pub fn insert(&self, data: &impl TypedSessionData) -> Result<(), serde_json::Error> {
        let key = data.typed_session_key().to_string();
        self.0.insert(key, data)
    }

    pub fn get<T: TypedSessionData>(&self) -> Result<Option<T>, serde_json::Error> {
        self.0.get(T::TYPED_SESSION_KEY)
    }

    pub fn remove<T: TypedSessionData>(&self) -> Option<String> {
        self.0.remove(T::TYPED_SESSION_KEY)
    }
}

/// Extract a [`TypedSession`] object from various `actix-web` types (e.g. `HttpRequest`,
/// `ServiceRequest`, `ServiceResponse`).
pub trait TypedSessionExt {
    /// Extract a [`TypedSession`] object.
    fn get_typed_session(&self) -> TypedSession;
}

impl TypedSessionExt for HttpRequest {
    fn get_typed_session(&self) -> TypedSession {
        TypedSession(self.get_session())
    }
}

impl TypedSessionExt for ServiceRequest {
    fn get_typed_session(&self) -> TypedSession {
        TypedSession(self.get_session())
    }
}

impl TypedSessionExt for ServiceResponse {
    fn get_typed_session(&self) -> TypedSession {
        self.request().get_typed_session()
    }
}

impl<'a> TypedSessionExt for GuardContext<'a> {
    fn get_typed_session(&self) -> TypedSession {
        TypedSession(self.get_session())
    }
}

impl FromRequest for TypedSession {
    // This is a complicated way of saying
    // "We return the same error returned by the
    // implementation of `FromRequest` for `Session`".
    type Error = <Session as FromRequest>::Error;
    // Rust does not yet support the `async` syntax in traits.
    // From request expects a `Future` as return type to allow for extractors
    // that need to perform asynchronous operations (e.g. a HTTP call)
    // We do not have a `Future`, because we don't perform any I/O,
    // so we wrap `TypedSession` into `Ready` to convert it into a `Future` that
    // resolves to the wrapped value the first time it's polled by the executor.
    type Future = Ready<Result<TypedSession, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(Ok(req.get_typed_session()))
    }
}

/// 可在 TypedSession 存取的数据
pub trait TypedSessionData: Serialize + DeserializeOwned {
    const TYPED_SESSION_KEY: &'static str;

    fn typed_session_key(&self) -> &str;
}
