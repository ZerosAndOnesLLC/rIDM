//! The admin API as the CLI sees it: a bearer token, a base URL, and requests
//! whose refusals are turned back into the server's problem document.

use reqwest::{Method, StatusCode};
use serde_json::Value;
use url::Url;

use crate::error::{ApiError, CliError, Result};

/// Header the admin API expects the token in; never a query parameter.
const AUTHORIZATION: &str = "Authorization";

#[derive(Debug, Clone)]
pub struct Api {
    http: reqwest::Client,
    /// Origin without a trailing slash.
    base: String,
    bearer: String,
}

impl Api {
    pub fn new(http: reqwest::Client, base: String, bearer: String) -> Self {
        Self {
            http,
            base: crate::config::normalize_url(&base),
            bearer,
        }
    }

    /// `{base}{path}` with `query` percent-encoded onto it.
    fn url(&self, path: &str, query: &[(&str, String)]) -> Result<Url> {
        let mut url = Url::parse(&format!("{}{path}", self.base))
            .map_err(|e| CliError::usage(format!("bad server URL `{}{path}`: {e}", self.base)))?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in query {
                pairs.append_pair(k, v);
            }
        }
        Ok(url)
    }

    /// Send a request and parse the response; `204` and an empty body come
    /// back as `Value::Null`.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = self.url(path, query)?;
        let mut req = self
            .http
            .request(method.clone(), url.clone())
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer));
        if let Some(b) = body {
            req = req.json(b);
        }
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(problem(&method, &url, status, &text).into());
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| {
            CliError::failed(format!(
                "{method} {url} returned a body that is not JSON: {e}"
            ))
        })
    }

    pub async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value> {
        self.send(Method::GET, path, query, None).await
    }

    pub async fn post(&self, path: &str, query: &[(&str, String)], body: &Value) -> Result<Value> {
        self.send(Method::POST, path, query, Some(body)).await
    }

    /// POST with no request body (the server's `rotate` endpoints take none).
    pub async fn post_empty(&self, path: &str) -> Result<Value> {
        self.send(Method::POST, path, &[], None).await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.send(Method::PUT, path, &[], Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.send(Method::DELETE, path, &[], None).await
    }
}

/// Turn a refusal into an [`ApiError`], reading the RFC 9457 document when the
/// server sent one and falling back to the status line when it did not.
fn problem(method: &Method, url: &Url, status: StatusCode, body: &str) -> ApiError {
    let doc: Option<Value> = serde_json::from_str(body).ok();
    let title = doc
        .as_ref()
        .and_then(|d| d.get("title"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| status.canonical_reason().map(str::to_string))
        .unwrap_or_else(|| "error".to_string());
    let detail = doc
        .as_ref()
        .and_then(|d| d.get("detail"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            // OAuth endpoints answer with `error`/`error_description`.
            doc.as_ref()
                .and_then(|d| d.get("error_description").or_else(|| d.get("error")))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| {
            let trimmed = body.trim();
            (!trimmed.is_empty() && doc.is_none()).then(|| trimmed.chars().take(400).collect())
        });
    let fields = doc
        .as_ref()
        .and_then(|d| d.get("errors"))
        .and_then(Value::as_array)
        .map(|errs| {
            errs.iter()
                .map(|e| {
                    (
                        e.get("field")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        e.get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    ApiError {
        method: method.to_string(),
        url: url.to_string(),
        status: status.as_u16(),
        title,
        detail,
        fields,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(status: u16, body: &str) -> ApiError {
        problem(
            &Method::POST,
            &Url::parse("https://idm.example/admin/tenants/acme/users").unwrap(),
            StatusCode::from_u16(status).unwrap(),
            body,
        )
    }

    #[test]
    fn a_problem_document_becomes_the_message_the_operator_reads() {
        let e = err(
            403,
            r#"{"type":"urn:ridm:error:forbidden","title":"Forbidden","status":403,
                "detail":"permission `ridm:users:write` is required"}"#,
        );
        assert_eq!(e.status, 403);
        let text = e.to_string();
        assert!(text.contains("403 Forbidden"), "{text}");
        assert!(text.contains("ridm:users:write"), "{text}");
    }

    #[test]
    fn field_errors_are_listed_under_the_refusal() {
        let e = err(
            400,
            r#"{"title":"Validation failed","status":400,
                "errors":[{"field":"username","message":"already taken"}]}"#,
        );
        assert_eq!(e.fields, vec![("username".into(), "already taken".into())]);
        assert!(e.to_string().contains("username: already taken"));
    }

    #[test]
    fn an_oauth_style_body_still_says_what_went_wrong() {
        let e = err(
            400,
            r#"{"error":"invalid_target","error_description":"unknown resource"}"#,
        );
        assert_eq!(e.detail.as_deref(), Some("unknown resource"));
    }

    #[test]
    fn a_body_that_is_not_json_falls_back_to_the_status_line_and_the_text() {
        let e = err(502, "<html>bad gateway</html>");
        assert_eq!(e.title, "Bad Gateway");
        assert_eq!(e.detail.as_deref(), Some("<html>bad gateway</html>"));
    }

    #[test]
    fn an_empty_body_carries_no_detail_at_all() {
        let e = err(401, "");
        assert_eq!(e.title, "Unauthorized");
        assert!(e.detail.is_none());
    }
}
