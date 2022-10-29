//! Redis

use deadpool_redis::{redis::Cmd,  Pool, Config, Runtime};
use actix_web::web::Data;
use serde::{Serialize, de::DeserializeOwned};

pub struct TypedRedis(Pool);

impl std::fmt::Debug for TypedRedis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TypedRedis").finish()
    }
}

impl TypedRedis {
    /// 保存
    pub async fn set(&self, data: impl TypedRedisData, ttl_seconds: usize) -> Result<(), anyhow::Error> {
        let d = serde_json::to_string(&data)?;
        let mut conn = self.0.get().await?;
        if ttl_seconds > 0 {
            Cmd::set_ex(data.typed_redis_key(), &d, ttl_seconds)
                .query_async::<_, ()>(&mut conn)
                .await
                .map_err(|e| anyhow::anyhow!("{:?}", e))
        } else {
            Cmd::set(data.typed_redis_key(), &d)
                .query_async::<_, ()>(&mut conn)
                .await
                .map_err(|e| anyhow::anyhow!("{:?}", e))
        }
    }

    /// 保存，带半小时有效期
    pub async fn set_half_hour_ex(&self, data: impl TypedRedisData) -> Result<(), anyhow::Error> {
        self.set(data, 1800).await
    }

    /// 获取
    pub async fn get<T: TypedRedisData>(&self, key_param: &str) -> Result<Option<T>, anyhow::Error> {
        let mut conn = self.0.get().await?;
        match Cmd::get(T::generate_typed_redis_key(key_param))
            .query_async::<_, Option<String>>(&mut conn)
            .await
            .map_err(|e| anyhow::anyhow!("{:?}", e))
        {
            Ok(Some(v)) => {
                match serde_json::from_str::<T>(&v) {
                    Ok(t) => Ok(Some(t)),
                    Err(e) => Err(e.into()),
                }
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e)
        }
    }
}

/// 可在 TypedRedis 存取的数据
pub trait TypedRedisData: Serialize + DeserializeOwned {
    fn typed_redis_key(&self) -> String;
    fn generate_typed_redis_key(param: &str) -> String;
}

pub struct TypedRedisBuilder {}

impl TypedRedisBuilder {
    pub fn build(addr: impl Into<String>) -> Data<TypedRedis> {
        let cfg = Config::from_url(addr);
        let pool = cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
        Data::new(TypedRedis(pool))
    }
}