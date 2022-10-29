//! 认证功能服务 
//! 
//! 

use crate::domain::credentials::{Credentials, AuthError};
use crate::domain::credentials::dao::get_stored_credentials;
use telemetry::spawn_blocking_with_tracing;
use argon2::password_hash::SaltString;
use argon2::{
    Algorithm, Argon2, Params, PasswordHash,
    PasswordHasher, PasswordVerifier, Version
};
use anyhow::Context;
use secrecy::{Secret, ExposeSecret};
use sqlx::PgPool;

/// 校验认证
#[tracing::instrument(name = "Service -> Validate credentials", skip(credentials, pool))]
pub async fn validate_credentials(
    credentials: Credentials,
    pool: &PgPool,
) -> Result<(uuid::Uuid, String), AuthError> {
    let mut user_id = None;
    let mut username: Option<String> = None;
    let mut expected_password_hash = Secret::new(
        "$argon2id$v=19$m=15000,t=2,p=1$\
        gZiV/M1gPc22ElAH/Jh1Hw$\
        CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
            .to_string()
    );
    if let Some((stored_user_id, stored_username, stored_password_hash)) = 
        get_stored_credentials(&credentials.username, &pool)
            .await?
    {
        user_id = Some(stored_user_id);
        username = Some(stored_username);
        expected_password_hash = stored_password_hash;
    }

    spawn_blocking_with_tracing(move || {
        verify_password_hash(
            &expected_password_hash,
            &credentials.password
        )
    })
    .await
    .context("Failed to spawn blocking task.")??;

    match (user_id, username) {
        (Some(user_id), Some(username)) => Ok((user_id, username)),
        _ => Err(AuthError::InvalidCredentials(anyhow::anyhow!("Unknown username.")))
    }
}

/// 校验密码哈希
#[tracing::instrument(
    name = "Service -> Verify password hash",
    skip(expected_password_hash, password_candidate)
)]
fn verify_password_hash(
    expected_password_hash: &Secret<String>,
    password_candidate: &Secret<String>,
) -> Result<(), AuthError> {
    let expected_password_hash = PasswordHash::new(
            expected_password_hash.expose_secret()
        )
        .context("Failed to parse hash in PHC string format.")?;

    Argon2::default()
        .verify_password(
            password_candidate.expose_secret().as_bytes(),
            &expected_password_hash
        )
        .context("Invalid password.")
        .map_err(AuthError::InvalidCredentials)
}

/// 计算密码哈希值
pub fn compute_password_hash(
    password: Secret<String>
) -> Result<Secret<String>, anyhow::Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).unwrap(),
    )
    .hash_password(password.expose_secret().as_bytes(), &salt)?
    .to_string();
    Ok(Secret::new(password_hash))
}