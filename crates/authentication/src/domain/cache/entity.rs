//! cache

use actix_web::web::Data;
use serde::{Serialize, Deserialize};
use typed_redis::{TypedRedis, TypedRedisData};
use typed_session::TypedSession;

use crate::domain::permission::CurrentUserPermissions;

/// 缓存
#[derive(Debug, Clone)]
pub struct Cache(pub(crate) Data<TypedRedis>);

const PERMISSIONS_TYPED_REDIS_KEY: &'static str = "current_user_permissions_cache";

/// 当前用户权限缓存
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CurrentUserPermissionsCache {
    pub user_id: String,
    pub permissions: CurrentUserPermissions
}

impl TypedRedisData for CurrentUserPermissionsCache {
    fn typed_redis_key(&self) -> String {
        format!("{}_{}", PERMISSIONS_TYPED_REDIS_KEY, &self.user_id)
    }

    fn generate_typed_redis_key(param: &str) -> String {
        format!("{}_{}", PERMISSIONS_TYPED_REDIS_KEY, param)
    }
}

impl Cache {
    /// 获取当前用户权限
    pub async fn get_current_user_permissions(&self, session: &TypedSession) -> Option<CurrentUserPermissions> {
        if let Ok(Some(user_id)) = session.get_user_id() {
            match self.0.get::<CurrentUserPermissionsCache>(&user_id.to_string()).await {
                Ok(Some(p)) => Some(p.permissions),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!("{:?}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    /// 设置当前用户权限
    pub async fn set_current_user_permissions(&self, permissions: &CurrentUserPermissions, session: &TypedSession) -> () {
        if let Ok(Some(user_id)) = session.get_user_id() {
            match self.0
                .set_half_hour_ex(
                CurrentUserPermissionsCache {
                        user_id: user_id.to_string(),
                        permissions: permissions.clone()
                    }
                )
                .await
            {
                Ok(_) => (),
                Err(e) => {
                    tracing::warn!("{:?}", e);
                    ()
                }
            }
        }
        ()
    }
}