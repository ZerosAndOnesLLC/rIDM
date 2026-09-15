//! `Option<Option<T>>` deserialization for PATCH bodies: absent = leave as is,
//! `null` = clear, value = set.

use serde::{Deserialize, Deserializer};

pub fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct P {
        #[serde(deserialize_with = "double_option")]
        email: Option<Option<String>>,
    }

    #[test]
    fn absent_null_and_value() {
        assert_eq!(serde_json::from_str::<P>("{}").unwrap().email, None);
        assert_eq!(
            serde_json::from_str::<P>(r#"{"email": null}"#)
                .unwrap()
                .email,
            Some(None)
        );
        assert_eq!(
            serde_json::from_str::<P>(r#"{"email": "a@b.c"}"#)
                .unwrap()
                .email,
            Some(Some("a@b.c".into()))
        );
    }
}
