// this module is a custom serialization to be used with Vec<u8>
// it is meant to be less disk-consuming than the default serialization format

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let base64 = BASE64_ENGINE.encode(v);
    String::serialize(&base64, s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let base64 = String::deserialize(d)?;
    BASE64_ENGINE
        .decode(base64.as_bytes())
        .map_err(serde::de::Error::custom)
}

pub fn serialize_vec<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
    let base64 = v
        .iter()
        .map(|data| BASE64_ENGINE.encode(data))
        .collect::<Vec<_>>();
    Vec::<String>::serialize(&base64, s)
}

pub fn deserialize_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
    let base64 = Vec::<String>::deserialize(d)?;
    let mut decoded = Vec::new();
    for b in base64.iter() {
        decoded.push(
            BASE64_ENGINE
                .decode(b.as_bytes())
                .map_err(serde::de::Error::custom)?,
        );
    }
    Ok(decoded)
}

pub fn serialize_option<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    let base64 = v.as_ref().map(|data| BASE64_ENGINE.encode(data));
    <Option<String>>::serialize(&base64, s)
}

pub fn deserialize_option<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let base64 = <Option<String>>::deserialize(d)?;
    match base64 {
        Some(v) => BASE64_ENGINE
            .decode(v.as_bytes())
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}
