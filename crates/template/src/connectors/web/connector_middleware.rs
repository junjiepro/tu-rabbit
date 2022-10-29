//! Web 连接器中间件

use actix_web::{dev::{ServiceRequest, ServiceResponse}, body::BoxBody};
use actix_web_lab::middleware::Next;

pub async fn web_middleware_fn(
    req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    next.call(req).await
}