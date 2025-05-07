// this module is a custom serialization to be used with Vec<u8>
// it is meant to be less disk-consuming than the default serialization format

use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    let base64 = base64::encode(v);
    String::serialize(&base64, s)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let base64 = String::deserialize(d)?;
    base64::decode(base64.as_bytes()).map_err(|e| serde::de::Error::custom(e))
}

pub fn serialize_vec<S: Serializer>(v: &Vec<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    let base64 = v.iter().map(|x| base64::encode(x)).collect::<Vec<_>>();
    Vec::<String>::serialize(&base64, s)
}

pub fn deserialize_vec<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
    let base64 = Vec::<String>::deserialize(d)?;
    let mut decoded = Vec::new();
    for b in base64.iter() {
        decoded.push(base64::decode(b.as_bytes()).map_err(|e| serde::de::Error::custom(e))?);
    }
    Ok(decoded)
}

pub fn serialize_option<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    let base64 = match v {
        Some(v) => Some(base64::encode(v)),
        None => None,
    };
    <Option<String>>::serialize(&base64, s)
}

pub fn deserialize_option<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    let base64 = <Option<String>>::deserialize(d)?;
    match base64 {
        Some(v) => {
            base64::decode(v.as_bytes())
                .map(|v| Some(v))
                .map_err(|e| serde::de::Error::custom(e))
        },
        None => Ok(None),
    }
}