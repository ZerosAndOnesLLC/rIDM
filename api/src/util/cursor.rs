//! Opaque keyset-pagination cursors: `(created_at, id)` encoded as base64url JSON.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;

pub const DEFAULT_PAGE_SIZE: u32 = 50;
pub const MAX_PAGE_SIZE: u32 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    #[serde(rename = "t")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "i")]
    pub id: Uuid,
}

impl Cursor {
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).expect("cursor serializes"))
    }

    pub fn decode(raw: &str) -> Result<Self, AppError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| AppError::BadRequest("invalid cursor".into()))?;
        serde_json::from_slice(&bytes).map_err(|_| AppError::BadRequest("invalid cursor".into()))
    }
}

/// Clamp a requested page size into `[1, MAX_PAGE_SIZE]`.
pub fn page_size(requested: Option<u32>) -> i64 {
    i64::from(
        requested
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE),
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// Build a page from `limit + 1` rows: the extra row, if present, becomes the cursor.
    pub fn from_rows(mut rows: Vec<T>, limit: i64, cursor_of: impl Fn(&T) -> Cursor) -> Self {
        let has_more = rows.len() as i64 > limit;
        if has_more {
            rows.truncate(limit as usize);
        }
        let next_cursor = if has_more {
            rows.last().map(|last| cursor_of(last).encode())
        } else {
            None
        };
        Self {
            items: rows,
            next_cursor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips() {
        let c = Cursor {
            created_at: Utc::now(),
            id: Uuid::now_v7(),
        };
        assert_eq!(Cursor::decode(&c.encode()).unwrap(), c);
        assert!(Cursor::decode("!!!").is_err());
    }

    #[test]
    fn page_detects_more_rows() {
        let rows: Vec<u32> = (0..6).collect();
        let page = Page::from_rows(rows, 5, |_| Cursor {
            created_at: Utc::now(),
            id: Uuid::nil(),
        });
        assert_eq!(page.items.len(), 5);
        assert!(page.next_cursor.is_some());
        let page = Page::from_rows(vec![1u32, 2], 5, |_| Cursor {
            created_at: Utc::now(),
            id: Uuid::nil(),
        });
        assert!(page.next_cursor.is_none());
    }
}
