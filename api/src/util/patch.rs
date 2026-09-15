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

/// JSON merge patch (RFC 7396): objects merge recursively, `null` removes a
/// member, anything else replaces the target value.
pub fn merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    match patch {
        Value::Object(fields) => {
            if !target.is_object() {
                *target = Value::Object(Default::default());
            }
            let map = target.as_object_mut().expect("object");
            for (k, v) in fields {
                if v.is_null() {
                    map.remove(k);
                } else {
                    merge_patch(map.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
        }
        other => *target = other.clone(),
    }
}

/// JSON pointer paths at which `a` and `b` differ (objects compared member by
/// member, numbers by value so `14` equals `14.0`). Used to detect fields a
/// patch named that the typed settings do not know: they vanish on the
/// round trip through the struct.
pub fn diff_paths(a: &serde_json::Value, b: &serde_json::Value) -> Vec<String> {
    fn walk(a: &serde_json::Value, b: &serde_json::Value, path: &str, out: &mut Vec<String>) {
        use serde_json::Value;
        match (a, b) {
            (Value::Object(x), Value::Object(y)) => {
                let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
                keys.sort();
                keys.dedup();
                for k in keys {
                    let p = format!("{path}/{k}");
                    // A member removed by the patch reappears as `null` after
                    // the round trip; absent and null mean the same thing.
                    match (x.get(k), y.get(k)) {
                        (Some(va), Some(vb)) => walk(va, vb, &p, out),
                        (Some(v), None) | (None, Some(v)) if v.is_null() => {}
                        _ => out.push(p),
                    }
                }
            }
            (Value::Number(x), Value::Number(y)) => {
                if x.as_f64() != y.as_f64() {
                    out.push(path.to_string());
                }
            }
            _ if a != b => out.push(path.to_string()),
            _ => {}
        }
    }
    let mut out = vec![];
    walk(a, b, "", &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_paths_reports_dropped_and_changed_members() {
        let a = serde_json::json!({"x": {"y": 1, "z": 2}, "n": 14, "s": "a", "gone": null});
        let b = serde_json::json!({"x": {"y": 1, "w": null}, "n": 14.0, "s": "b", "extra": true});
        let mut d = diff_paths(&a, &b);
        d.sort();
        assert_eq!(d, ["/extra", "/s", "/x/z"]);
        assert!(diff_paths(&a, &a).is_empty());
    }

    #[test]
    fn merge_patch_follows_rfc_7396() {
        let mut doc = serde_json::json!({"a": "b", "c": {"d": "e", "f": "g"}});
        merge_patch(&mut doc, &serde_json::json!({"a": "z", "c": {"f": null}}));
        assert_eq!(doc, serde_json::json!({"a": "z", "c": {"d": "e"}}));
        merge_patch(&mut doc, &serde_json::json!({"c": [1]}));
        assert_eq!(doc["c"], serde_json::json!([1]));
        merge_patch(&mut doc, &serde_json::json!("scalar"));
        assert_eq!(doc, serde_json::json!("scalar"));
    }

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
