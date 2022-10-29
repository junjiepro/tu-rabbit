use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey, Token, Header, AlgorithmType};
use jwt::token::Signed;
use sha2::Sha256;
use secrecy::{Secret, ExposeSecret};
use anyhow::Context;
use std::collections::BTreeMap;

#[derive(thiserror::Error, Debug)]
pub enum JWTError {
    #[error("Invalid JWT Token")]
    InvalidTokenError(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[tracing::instrument(name = "Sign claims to JWT", skip(claims, secret))]
pub fn sign<'a>(
    claims: BTreeMap<&'a str, &'a str>,
    secret: &Secret<String>,
) -> Result<Token<Header, BTreeMap<&'a str, &'a str>, Signed>, JWTError> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.expose_secret().as_bytes()).unwrap();
    let header = Header {
        algorithm: AlgorithmType::Hs256,
        ..Default::default()
    };
    Token::new(header, claims)
        .sign_with_key(&key)
        .context("Failed to sign a claims to JWT.")
        .map_err(|e| JWTError::UnexpectedError(e.into()))
}

#[tracing::instrument(name = "Verificate JWT token to claims", skip(token_str, secret))]
pub fn verificate(
    token_str: &str,
    secret: &Secret<String>,
) -> Result<BTreeMap<String, String>, JWTError> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.expose_secret().as_bytes()).unwrap();
    let token: Result<Token<Header, BTreeMap<String, String>, _>, _> = VerifyWithKey::verify_with_key(token_str, &key);
    let token = token
        .context("Failed to verify JWT token with key.")
        .map_err(JWTError::InvalidTokenError)?;
    let header = token.header();
    let claims = token.claims();
    
    if header.algorithm == AlgorithmType::Hs256 {
        Ok(claims.to_owned())
    } else {
        Err(JWTError::InvalidTokenError(anyhow::anyhow!("Incorrect algorithm type in header.")))
    }
}

#[cfg(test)]
mod tests {
    use crate::handler::jwt::{sign, verificate};
    use secrecy::Secret;
    use std::collections::BTreeMap;

    #[test]
    fn sign_claims_with_secret_return_a_valid_token() {
        // Act
        let secret = Secret::new("some-secret".to_string());
        let mut claims = BTreeMap::new();
        claims.insert("sub", "someone");

        // Act
        let token = sign(claims, &secret).unwrap();

        // Assert
        let token_str = token.as_str();
        assert_eq!("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lb25lIn0.5wwE1sBrs-vftww_BGIuTVDeHtc1Jsjo-fiHhDwR8m0", token_str);
    }

    #[test]
    fn verificate_token_str_with_secret_return_valid_claims() {
        // Act
        let secret = Secret::new("some-secret".to_string());
        let token_str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzb21lb25lIn0.5wwE1sBrs-vftww_BGIuTVDeHtc1Jsjo-fiHhDwR8m0";

        // Act
        let claims = verificate(token_str, &secret).unwrap();

        // Assert
        assert_eq!("someone", claims["sub"])
    }
}