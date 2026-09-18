//! The three pages this app has. Hand-written HTML, because a templating
//! engine would be the most interesting thing in an example that is meant to
//! be about OpenID Connect.

use crate::session::Session;

pub fn signed_out(issuer: &str) -> String {
    page(
        "Orders",
        &format!(
            r#"<p class="lede">A server-side web app that signs users in with rIDM.</p>
<p><a class="button" href="/login">Sign in</a></p>
<p class="meta">Issuer: <code>{}</code></p>"#,
            escape(issuer)
        ),
    )
}

pub fn signed_in(session: &Session, orders: &str, notice: Option<&str>) -> String {
    let who = session
        .name
        .clone()
        .or_else(|| session.email.clone())
        .unwrap_or_else(|| session.subject.clone());
    let permissions = if session.permissions.is_empty() {
        "<em>none</em>".to_string()
    } else {
        session
            .permissions
            .iter()
            .map(|p| format!("<code>{}</code>", escape(p)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let notice = notice
        .map(|n| format!(r#"<p class="notice">{}</p>"#, escape(n)))
        .unwrap_or_default();
    let may_write = session.permissions.iter().any(|p| p == "orders:write");
    let form = if may_write {
        r#"<form method="post" action="/orders">
  <input name="item" placeholder="Item" required>
  <input name="quantity" type="number" value="1" min="1" style="width:5rem">
  <button type="submit">Place order</button>
</form>"#
    } else {
        r#"<p class="meta">This account may read orders but not place them, so the API
    would answer <code>403 insufficient_scope</code>. Give the user the
    <code>orders-manager</code> role and sign in again.</p>"#
    };

    page(
        "Orders",
        &format!(
            r#"{notice}
<p class="lede">Signed in as <strong>{who}</strong>.</p>
<p class="meta">Subject <code>{subject}</code> · session <code>{sid}</code><br>
Permissions: {permissions}</p>
<h2>Orders</h2>
{orders}
{form}
<p><a class="button secondary" href="/logout">Sign out</a></p>"#,
            who = escape(&who),
            subject = escape(&session.subject),
            sid = escape(session.sid.as_deref().unwrap_or("—")),
        ),
    )
}

pub fn orders_table(orders: &[serde_json::Value]) -> String {
    if orders.is_empty() {
        return "<p class=\"meta\">No orders yet.</p>".into();
    }
    let rows = orders
        .iter()
        .map(|o| {
            format!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                escape(o["item"].as_str().unwrap_or("?")),
                o["quantity"].as_u64().unwrap_or(0),
                escape(o["placed_by"].as_str().unwrap_or("?")),
            )
        })
        .collect::<String>();
    format!(
        "<table><thead><tr><th>Item</th><th>Qty</th><th>Placed by</th></tr></thead>\
         <tbody>{rows}</tbody></table>"
    )
}

pub fn error(message: &str) -> String {
    page(
        "Something went wrong",
        &format!(
            r#"<p class="notice error">{}</p><p><a class="button" href="/">Start again</a></p>"#,
            escape(message)
        ),
    )
}

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; --fg: #14161a; --bg: #fbfbfc; --muted: #5b6270;
           --line: #e2e5ea; --accent: #2f5bd7; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --fg: #e8eaee; --bg: #14161a; --muted: #9aa2b1; --line: #2a2e36; --accent: #7ea2ff; }}
  }}
  body {{ font: 16px/1.55 system-ui, sans-serif; color: var(--fg); background: var(--bg);
          margin: 0; padding: 3rem 1rem; }}
  main {{ max-width: 42rem; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; margin: 0 0 1.5rem; }}
  h2 {{ font-size: 1.1rem; margin: 2rem 0 .5rem; }}
  .lede {{ font-size: 1.05rem; }}
  .meta {{ color: var(--muted); font-size: .9rem; }}
  .notice {{ padding: .7rem .9rem; border: 1px solid var(--line); border-radius: .5rem; }}
  .notice.error {{ border-color: #d64545; }}
  code {{ font-family: ui-monospace, monospace; font-size: .875em; }}
  a.button, button {{ display: inline-block; padding: .5rem 1rem; border-radius: .5rem;
    border: 1px solid transparent; background: var(--accent); color: #fff;
    text-decoration: none; font: inherit; cursor: pointer; }}
  a.button.secondary {{ background: transparent; color: var(--fg); border-color: var(--line); }}
  table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }}
  th, td {{ text-align: left; padding: .4rem .6rem; border-bottom: 1px solid var(--line); }}
  form {{ display: flex; gap: .5rem; flex-wrap: wrap; margin: 1rem 0; }}
  input {{ padding: .5rem .6rem; border: 1px solid var(--line); border-radius: .5rem;
           background: var(--bg); color: var(--fg); font: inherit; }}
</style>
</head><body><main><h1>{title}</h1>{body}</main></body></html>"#
    )
}

/// Anything that came from a token, an API or a query string is escaped before
/// it reaches the page.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_from_a_token_reaches_the_page_as_markup() {
        let session = Session {
            subject: "<script>alert(1)</script>".into(),
            name: Some("Al \"Ace\" O'Hara & Co".into()),
            email: None,
            sid: None,
            id_token: String::new(),
            access_token: String::new(),
            access_token_expires_at: chrono::Utc::now(),
            refresh_token: None,
            permissions: vec!["<img src=x>".into()],
        };
        let html = signed_in(&session, "", None);
        assert!(!html.contains("<script>"), "{html}");
        assert!(!html.contains("<img src=x>"), "{html}");
        assert!(
            html.contains("Al &quot;Ace&quot; O&#39;Hara &amp; Co"),
            "{html}"
        );
    }

    #[test]
    fn an_empty_list_reads_as_empty_rather_than_as_a_table() {
        assert!(orders_table(&[]).contains("No orders yet"));
        let rows = orders_table(&[serde_json::json!({
            "item": "Anvil", "quantity": 2, "placed_by": "alice"
        })]);
        assert!(rows.contains("<td>Anvil</td>"), "{rows}");
        assert!(rows.contains("<td>2</td>"), "{rows}");
    }
}
