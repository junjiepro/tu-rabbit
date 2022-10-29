use std::path::Path;

use actix_web::cookie::Key;
use actix_web::web::{Data, self};
use actix_web::{HttpServer, App, HttpResponse};
use actix_web_lab::middleware::from_fn;
use argon2::{password_hash::SaltString, Algorithm, Version, Params, Argon2, PasswordHasher};
use connector::{ConnectorBuilder, ConnectorServiceExt};
use mail::test::helpers::spawn_configuration as spawn_mail_configuration;
use data_transmission::web::{build_http_response_error_data, build_http_response_data, build_http_response_empty_data};
use regex::Regex;
use typed_redis::TypedRedisBuilder;
use typed_session::TypedSessionMiddleware;
use crate::api::configuration::{DatabaseSettings, Settings};
use crate::api::configuration::get_authentication_configuration;
use crate::api::application::Application;
use crate::connectors::{AuthenticationCurrentUserResult, AuthenticationConnectorType};
use crate::connectors::inner::{get_connection_pool, InnerAuthenticationConnector, inner_middleware_fn};
use crate::connectors::web::{WebAuthenticationConnector, web_middleware_fn};
use crate::domain::user::Status;
use secrecy::{Secret, ExposeSecret};
use tracing_actix_web::TracingLogger;
use reqwest::header::HeaderMap;
use sqlx::{PgPool, PgConnection, Connection, Executor};
use telemetry::tracing;
use uuid::Uuid;
use std::net::TcpListener;

pub struct TestApp {
    pub port: u16,
    pub address: String,
    pub db_pool: PgPool,
    pub test_user: TestUser,
    pub api_client: reqwest::Client,
}


impl TestApp {
    pub fn spawn_msg_id(&self) -> String {
        let re = Regex::new("[0-9]+").unwrap();
        re.replace_all(&uuid::Uuid::new_v4().to_string(), "a").to_string().replace("-", ".")
    }

    pub fn spawn_namespace(&self) -> String {
        let re = Regex::new("[0-9]+").unwrap();
        re.replace_all(&uuid::Uuid::new_v4().to_string(), "a").to_string().replace("-", ":")
    }

    pub async fn generate_verification_code_and_send<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}/authentication/generate-verification-code", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn register_user<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}/authentication/register-user", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn validate_credentials<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}/authentication/validate-credentials", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_current_user(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/current-user", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn bind_current_user_with_admin_role(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/bind-current-user/admin", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_current_user_with_headers(&self, headers: HeaderMap) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/current-user", &self.address))
            .headers(headers)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_users(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/user", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn update_user<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .put(&format!("{}/authentication/user", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_roles(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/role", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn add_role<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}/authentication/role", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn update_role<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .put(&format!("{}/authentication/role", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_role_by_id(&self, id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/role/{}", &self.address, id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn delete_role_by_id(&self, id: &str) -> reqwest::Response {
        self.api_client
            .delete(&format!("{}/authentication/role/{}", &self.address, id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn check_role_msg_id(&self, msg_id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/role/check-role-msg-id/{}", &self.address, msg_id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn check_role_namespace(&self, namespace: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/role/check-role-namespace/{}", &self.address, namespace))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_roles_by_user_id(&self, user_id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/role/find-by-user-id/{}", &self.address, user_id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_roles_by_permission_id(&self, permission_id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/role/find-by-permission-id/{}", &self.address, permission_id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_permissions(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/permission", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn add_permission<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}/authentication/permission", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn update_permission<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .put(&format!("{}/authentication/permission", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_permission_by_id(&self, id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/permission/{}", &self.address, id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn delete_permission_by_id(&self, id: &str) -> reqwest::Response {
        self.api_client
            .delete(&format!("{}/authentication/permission/{}", &self.address, id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn check_permission_msg_id(&self, msg_id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/permission/check-permission-msg-id/{}", &self.address, msg_id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn check_permission_value(&self, permission: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/permission/check-permission-value/{}", &self.address, permission))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_permissions_by_role_id(&self, role_id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/permission/find-by-role-id/{}", &self.address, role_id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_applications(&self) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/application", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn add_application<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .post(&format!("{}/authentication/application", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn update_application<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.api_client
            .put(&format!("{}/authentication/application", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn get_application_by_id(&self, id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/application/{}", &self.address, id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn delete_application_by_id(&self, id: &str) -> reqwest::Response {
        self.api_client
            .delete(&format!("{}/authentication/application/{}", &self.address, id))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn check_application_msg_id(&self, msg_id: &str) -> reqwest::Response {
        self.api_client
            .get(&format!("{}/authentication/application/check-application-msg-id/{}", &self.address, msg_id))
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

#[derive(Clone)]
pub struct TestUser {
    pub user_id: Uuid,
    pub username: String,
    pub password: String
}

impl TestUser {
    pub fn generate() -> Self {
        Self {
            user_id: Uuid::new_v4(),
            username: Uuid::new_v4().to_string(),
            password: Uuid::new_v4().to_string(),
        }
    }

    pub async fn login_with_auto_login(&self, app: &TestApp) -> reqwest::Response {
        app.validate_credentials(&serde_json::json!({
            "username": &self.username,
            "password": &self.password,
            "autoLogin": true,
            "userType": "",
        }))
        .await
    }

    pub async fn login(&self, app: &TestApp) -> reqwest::Response {
        app.validate_credentials(&serde_json::json!({
            "username": &self.username,
            "password": &self.password,
            "autoLogin": false,
            "userType": "",
        }))
        .await
    }

    async fn store(&self, pool: &PgPool) {
        let salt = SaltString::generate(&mut rand::thread_rng());
        // Match parameters of the default password
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        )
        .hash_password(self.password.as_bytes(), &salt)
        .unwrap()
        .to_string();
        
        let status: i32 = Status::Confirmed.into();
        sqlx::query!(
            "INSERT INTO users (user_id, username, password_hash, status)
            VALUES ($1, $2, $3, $4)",
            self.user_id,
            self.username,
            password_hash,
            status,
        )
        .execute(pool)
        .await
        .expect("Failed to store test user.");
    }
}

pub async fn spawn_configuration(init_database: bool) -> Settings {
    // Randomise configuration to ensure test isolation
    let configuration = {
        let mut c = get_authentication_configuration(
            Some(
                Path::new("../../").to_path_buf()
            )
        ).expect("Failed to read configuration.");
        // Use a different database for each test case
        c.database.database_name = Uuid::new_v4().to_string();
        // Use a random OS port
        c.application.port = 0;
        c
    };
    
    if init_database {
        // Create and migrate the database
        configure_database(&configuration.database).await;
    }

    configuration
}

// Launch our application in the background ~somehow~
pub async fn spawn_app() -> TestApp {
    tracing();
    
    let configuration = spawn_configuration(true).await;
    let mail_configuration = spawn_mail_configuration().await;
    
    let application = Application::build(configuration.clone(), mail_configuration).await.expect("Failed to build application.");
    let application_port = application.port();
    let address = format!("http://localhost:{}", application_port);
    // Launch the server as a background task
    // tokio::spawn returns a handle to the spawned future,
    // but we have no use for it here, hence the non-binding let
    let _ = tokio::spawn(application.run_until_stopped());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    
    let test_app = TestApp {
        address,
        port: application_port,
        db_pool: get_connection_pool(&configuration.database),
        test_user: TestUser::generate(),
        api_client: client,
    };
    test_app.test_user.store(&test_app.db_pool).await;
    test_app
}

async fn configure_database(config: &DatabaseSettings) -> PgPool {
    // Create database
    let mut connection = PgConnection::connect_with(&config.without_db())
        .await
        .expect("Failed to connect to Postgres");
    connection
        .execute(format!(r#"CREATE DATABASE "{}";"#, config.database_name).as_str())
        .await
        .expect("Failed to create database.");
    
    // Migrate database
    let connection_pool = PgPool::connect_with(config.with_db())
        .await
        .expect("Failed to connect to Postgres.");
    
    sqlx::migrate!("../../migrations")
        .run(&connection_pool)
        .await
        .expect("Failed to migrate the database");
    
    connection_pool
}

pub struct ConnectorTestApp {
    pub port: u16,
    pub address: String,
    pub api_client: reqwest::Client,
    pub test_user: TestUser,
}

impl ConnectorTestApp {
    pub async fn to_test_app(&self, configuration: &Settings) -> TestApp {
        let test_app = TestApp {
            port: self.port,
            address: self.address.clone(),
            db_pool: get_connection_pool(&configuration.database),
            test_user: self.test_user.clone(),
            api_client: self.api_client.clone(),
        };
        test_app.test_user.store(&test_app.db_pool).await;
        test_app
    }
}

pub async fn spawn_connector_app(
    connector_builder: impl ConnectorBuilder + Send + 'static,
    connector_type: AuthenticationConnectorType,
    redis_uri: Secret<String>,
) -> ConnectorTestApp {
    tracing();

    let address = format!("127.0.0.1:{}", 0);
    let listener = TcpListener::bind(address).unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("http://localhost:{}", port);

    let _ = tokio::spawn(build_application(
        connector_builder,
        connector_type,
        listener,
        redis_uri,
    ));

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    ConnectorTestApp {
        port,
        address,
        api_client: client,
        test_user: TestUser::generate(),
    }
}

async fn build_application(
    connector_builder: impl ConnectorBuilder,
    connector_type: AuthenticationConnectorType,
    listener: TcpListener,
    redis_uri: Secret<String>,
) -> Result<(), std::io::Error> {
    let connector_server = connector_builder.build_connector_server();
    let connector_server = Data::new(connector_server);

    let secret_key = Key::generate();
    let redis_store = TypedSessionMiddleware::store(redis_uri.expose_secret()).await.unwrap();
    let typed_redis = TypedRedisBuilder::build(redis_uri.expose_secret());
    let server = match connector_type {
        AuthenticationConnectorType::Web => {
            HttpServer::new(move || {
                App::new()
                    .wrap(
                        TypedSessionMiddleware::builder(redis_store.clone(), secret_key.clone()).build()
                    )
                    .wrap(TracingLogger::default())
                    .service(
                        web::scope("")
                        .wrap(from_fn(web_middleware_fn))
                        .connector_service(None, connector_server.get_ref())
                        .route("/test-web/health-check", web::get().to(web_health_check))
                        .route("/test-web/current-user", web::get().to(web_current_user))
                    )
                    .app_data(typed_redis.clone())
            })
            .workers(1)
            .listen(listener)
            .unwrap()
            .run()
        },
        AuthenticationConnectorType::Inner => {
            HttpServer::new(move || {
                App::new()
                    .wrap(
                        TypedSessionMiddleware::builder(redis_store.clone(), secret_key.clone()).build()
                    )
                    .wrap(TracingLogger::default())
                    .service(
                        web::scope("")
                        .wrap(from_fn(inner_middleware_fn))
                        .connector_service(Some("/authentication"), connector_server.get_ref())
                        .route("/test-inner/health-check", web::get().to(inner_health_check))
                        .route("/test-inner/current-user", web::get().to(inner_current_user))
                    )
                    .app_data(typed_redis.clone())
            })
            .workers(1)
            .listen(listener)
            .unwrap()
            .run()
        },
    };
    server.await
}

async fn inner_health_check(connector: Data<InnerAuthenticationConnector>) -> HttpResponse {
    match connector.health_check().await {
        Ok(_) => build_http_response_empty_data(),
        Err(e) => build_http_response_error_data(e),
    }
}

async fn inner_current_user(current_user: web::ReqData<AuthenticationCurrentUserResult>) -> HttpResponse {
    match current_user.into_inner() {
        AuthenticationCurrentUserResult::User(user, _) => build_http_response_data(user),
        AuthenticationCurrentUserResult::Error(e) => build_http_response_error_data(e),
    }
}

async fn web_health_check(connector: Data<WebAuthenticationConnector>) -> HttpResponse {
    match connector.health_check().await {
        Ok(_) => build_http_response_empty_data(),
        Err(e) => build_http_response_error_data(e),
    }
}

async fn web_current_user(current_user: web::ReqData<AuthenticationCurrentUserResult>) -> HttpResponse {
    match current_user.into_inner() {
        AuthenticationCurrentUserResult::User(user, _) => build_http_response_data(user),
        AuthenticationCurrentUserResult::Error(e) => build_http_response_error_data(e),
    }
}