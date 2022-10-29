//! Inner 连接器中间件

use actix_web_lab::middleware::Next;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};

pub async fn inner_middleware_fn(
    req: ServiceRequest,
    next: Next<BoxBody>
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    // 准备

    // 执行中间件前置方法

    // 执行

    next.call(req).await

    // 执行中间件后置方法
}