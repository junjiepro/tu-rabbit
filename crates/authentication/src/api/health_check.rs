//! 健康检查

use actix_web::HttpResponse;
use data_transmission::web::build_http_response_empty_data;

pub async fn health_check() -> HttpResponse {
    build_http_response_empty_data()
}