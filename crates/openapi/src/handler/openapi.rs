//! 获取OPEN API 文档

use data_transmission::error::openapi::DeserializeError;
use serde_json;
use openapiv3::OpenAPI;

#[tracing::instrument(
    name = "Deserialize API docs",
)]
pub fn openapi() -> Result<OpenAPI, DeserializeError> {
    let data = include_str!("../../openapi.json");
    let result: Result<OpenAPI, _> = serde_json::from_str(data);
    match result {
        Ok(docs) => Ok(docs),
        Err(e) => Err(DeserializeError::DeserializeError(e.into())),
    }
}


#[cfg(test)]
mod tests {
    use crate::handler::openapi::openapi;

    #[test]
    fn openapi_works() {
        // Act
        let result = openapi();

        // Assert
        // 反序列化成功
        assert!(result.is_ok());
        // 判断标题
        let openapi = result.unwrap();
        assert_eq!("API".to_string(), openapi.info.title);
    }
}