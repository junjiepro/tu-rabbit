//! 应用相关实体

use serde::{Serialize, Deserialize};
use sqlx::FromRow;

use data_transmission::data::DataEntity;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Application {
    /// 应用编号 唯一
    pub(crate) application_id: uuid::Uuid,
    /// 国际化消息编号 唯一
    pub(crate) msg_id: String,
    /// 默认消息
    pub(crate) default_msg: String,
    /// 应用应用自动绑定角色消息编号
    pub(crate) role_msg_id: String,
    /// 备注
    pub(crate) remarks: String,
}

impl Application {
    pub fn get_application_id(&self) -> uuid::Uuid {
        self.application_id
    }

    pub fn get_msg_id(&self) -> &str {
        &self.msg_id
    }

    pub fn get_role_msg_id(&self) -> &str {
        &self.role_msg_id
    }
}

impl DataEntity for Application {
    fn pre_insert(&mut self) {
        self.application_id = uuid::Uuid::new_v4();
    }

    fn pre_update(&mut self) {
        
    }
}
