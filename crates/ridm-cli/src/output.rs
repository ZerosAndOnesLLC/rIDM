//! How results reach the terminal: a readable table by default, the server's
//! JSON verbatim with `--output json` so a script can pipe it into `jq`.

use serde::Serialize;
use serde_json::Value;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum Format {
    /// Aligned columns and short sentences, for a person.
    Text,
    /// The API response as it arrived, for a script.
    Json,
}

impl Format {
    pub fn is_json(self) -> bool {
        self == Self::Json
    }
}

/// Pretty-print a value on stdout.
pub fn json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Aligned columns, two spaces apart; empty input prints nothing but a note.
pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("(none)");
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.chars().count());
            }
        }
    }
    println!("{}", line(headers.iter().map(|h| h.to_string()), &widths));
    for row in rows {
        println!("{}", line(row.iter().cloned(), &widths));
    }
}

fn line(cells: impl Iterator<Item = String>, widths: &[usize]) -> String {
    let cells: Vec<String> = cells.collect();
    let last = cells.len().saturating_sub(1);
    cells
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if i == last {
                c.clone()
            } else {
                let pad = widths.get(i).copied().unwrap_or(0);
                format!("{c:<pad$}")
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

/// A JSON field as a column: strings unquoted, absent values as `-`.
pub fn field(value: &Value, key: &str) -> String {
    match value.get(key) {
        None | Some(Value::Null) => "-".to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// The `items` of a paged response, or an empty slice.
pub fn items(value: &Value) -> Vec<Value> {
    match value.get("items").and_then(Value::as_array) {
        Some(items) => items.clone(),
        None => value.as_array().cloned().unwrap_or_default(),
    }
}

/// A secret the server will not show again.
pub fn secret(label: &str, value: &str) {
    println!("{label}: {value}");
    eprintln!("  (shown once — store it now)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_missing_field_reads_as_a_dash_and_a_string_loses_its_quotes() {
        let value = json!({"slug": "acme", "status": null, "count": 3});
        assert_eq!(field(&value, "slug"), "acme");
        assert_eq!(field(&value, "status"), "-");
        assert_eq!(field(&value, "missing"), "-");
        assert_eq!(field(&value, "count"), "3");
    }

    #[test]
    fn both_a_page_and_a_bare_array_yield_their_items() {
        assert_eq!(
            items(&json!({"items": [1, 2], "next_cursor": null})).len(),
            2
        );
        assert_eq!(items(&json!([1, 2, 3])).len(), 3);
        assert!(items(&json!({"next_cursor": null})).is_empty());
    }
}
