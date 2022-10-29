//! 数据传输格式在web传输

use std::fmt::Debug;

use crate::error::Error;
use serde::{Serialize, Deserialize};
use actix_web::HttpResponse;

#[derive(Serialize, Deserialize)]
pub struct HttpDataWraper<D: Sized, E: Sized> {
    success: bool,
    data: Option<D>,
    error: Option<E>,
}

#[derive(Serialize, Deserialize)]
pub struct EmptyData {}

impl<D: Sized, E: Sized> HttpDataWraper<D, E> {
    pub(crate) fn success(data: D) -> Self {
        HttpDataWraper {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub(crate) fn error(error: E) -> Self {
        HttpDataWraper {
            success: false,
            data: None,
            error: Some(error),
        }
    }

    pub fn is_success(&self) -> bool {
        self.success
    }

    pub fn get_data(self) -> Option<D> {
        self.data
    }

    pub fn get_error(self) -> Option<E> {
        self.error
    }
}

/// 数据转 HttpResponse 传输格式
pub fn build_http_response_data<'a>(data: impl Serialize + Deserialize<'a>) -> HttpResponse {
    HttpResponse::Ok().json(HttpDataWraper::<_, Error>::success(data))
}

/// 空数据转 HttpResponse 传输格式
pub fn build_http_response_empty_data<'a>() -> HttpResponse {
    let data = EmptyData {};
    HttpResponse::Ok().json(HttpDataWraper::<_, Error>::success(data))
}

/// 错误转 HttpResponse 传输格式
#[tracing::instrument(name = "build http response error data", skip(data))]
pub fn build_http_response_error_data<'a>(data: impl Into<Error> + Debug) -> HttpResponse {
    tracing::error!("{:?}", data);
    HttpResponse::Ok().json(HttpDataWraper::<Error, _>::error(data.into()))
}

/// 解析获取错误
pub fn get_error_from_str(s: &str) -> Option<Error> {
    let err: Result<HttpDataWraper::<Error, Error>, _> = serde_json::from_str(s);
    match err {
        Ok(err) => err.error,
        Err(_) => None,
    }
}

/// 解析获取数据
pub fn get_data_from_str<'a, D: Deserialize<'a>>(s: &'a str) -> Option<D> {
    let data: Result<HttpDataWraper::<D, Error>, _> = serde_json::from_str(s);
    match data {
        Ok(data) => data.data,
        Err(_) => None,
    }
}

/// 解析获取数据包装器
pub fn get_http_data_wraper_from_str<'a, D: Deserialize<'a>>(s: &'a str) -> Option<HttpDataWraper::<D, Error>> {
    let data: Result<HttpDataWraper::<D, Error>, _> = serde_json::from_str(s);
    match data {
        Ok(data) => Some(data),
        Err(_) => None,
    }
}

/// 解析获取空数据包装器
pub fn get_empty_http_data_wraper_from_str<'a>(s: &'a str) -> Option<HttpDataWraper::<EmptyData, Error>> {
    get_http_data_wraper_from_str::<EmptyData>(s)
}

#[cfg(test)]
mod tests {
    use crate::web::{build_http_response_data, build_http_response_error_data};
    use crate::error::Error;
    use serde::{Serialize, Deserialize};
    use actix_web::http::StatusCode;

    #[derive(Serialize, Deserialize)]
    struct Data {}

    #[test]
    fn build_http_response_data_works() {
        let response = build_http_response_data(Data {});
        assert_eq!(200, response.status().as_u16());
    }

    #[test]
    fn build_http_response_error_data_works() {
        let error = Error::build(StatusCode::OK.as_u16(), 0, "");
        let response = build_http_response_error_data(error);
        assert_eq!(200, response.status().as_u16());
    }
}