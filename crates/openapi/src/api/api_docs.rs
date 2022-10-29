//! api-docs

use crate::handler::openapi::openapi;
use data_transmission::web::build_http_response_error_data;
use actix_web::HttpResponse;

#[tracing::instrument(
    name = "API docs API",
)]
pub async fn api_docs() -> HttpResponse {
    match openapi() {
        Ok(docs) => HttpResponse::Ok().json(docs),
        Err(e) => build_http_response_error_data(e),
    }
}