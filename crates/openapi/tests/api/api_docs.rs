use crate::helpers::spawn_app;
use serde_json;
use openapiv3::OpenAPI;

#[tokio::test]
async fn api_docs_return_valid_openapi_docs() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let response = app.get_api_docs().await;

    // Assert
    // 请求成功
    assert!(response.status().is_success());
    // 反序列化OpenAPI
    let data = response.text().await.unwrap();
    let result: Result<OpenAPI, _> = serde_json::from_str(&data);
    assert!(result.is_ok());
    // 判断标题
    let openapi = result.unwrap();
    assert_eq!("API".to_string(), openapi.info.title);
}
