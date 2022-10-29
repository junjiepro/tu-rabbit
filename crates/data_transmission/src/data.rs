//! data 数据传输格式
//! 
//! 定义数据传输格式及相关功能

use chrono::prelude::*;
use serde::{Serialize, Deserialize};
use typed_session::TypedSession;

pub trait TransmissionData<'a>: Serialize + Deserialize<'a> {}

pub trait DataEntity {
    fn pre_insert(&mut self);

    fn pre_update(&mut self);
}

pub trait UserDataEntity {
    fn pre_insert(&mut self, session: &TypedSession);

    fn pre_update(&mut self, session: &TypedSession);
}

#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(type_name = "entity_date_time")]
pub struct EntityDateTime(pub DateTime<Local>);

impl From<DateTime<Local>> for EntityDateTime {
    fn from(time: DateTime<Local>) -> Self {
        EntityDateTime(time.clone())
    }
}

impl Serialize for EntityDateTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_i64(self.0.clone().timestamp_millis())
    }
}

impl<'de> Deserialize<'de> for EntityDateTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let secs = i64::deserialize(deserializer)? / 1000;
        let l = Local {};
        Ok(
            EntityDateTime(
                l.from_utc_datetime(&NaiveDateTime::from_timestamp(secs, 0))
            )
        )
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Default implementation just delegates to `deserialize` impl.
        *place = Deserialize::deserialize(deserializer)?;
        Ok(())
    }
}