//! Handlebars rendering with each template compiled once per node. Claim
//! mapper templates run for every token and message templates for every
//! message; parsing the same source on each use, into a registry built for
//! the purpose, was most of what rendering cost.

use std::sync::{Arc, LazyLock};

use handlebars::{Context, Handlebars, RenderContext, Renderable, StringOutput, Template};
use serde::Serialize;

/// How rendered values are escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    /// As written: claims, subjects, plain-text bodies.
    None,
    /// HTML-escaped: HTML bodies.
    Html,
}

/// Compiled templates kept per node, by source text.
const COMPILED_KEPT: u64 = 10_000;

static PLAIN: LazyLock<Handlebars<'static>> = LazyLock::new(|| {
    let mut hb = Handlebars::new();
    hb.set_strict_mode(false);
    hb.register_escape_fn(handlebars::no_escape);
    hb
});

static HTML: LazyLock<Handlebars<'static>> = LazyLock::new(|| {
    let mut hb = Handlebars::new();
    hb.set_strict_mode(false);
    hb
});

static COMPILED: LazyLock<moka::sync::Cache<String, Arc<Template>>> =
    LazyLock::new(|| moka::sync::Cache::new(COMPILED_KEPT));

/// Render `source` with `data`. The error is the parser's or renderer's
/// message.
pub fn render(source: &str, data: &impl Serialize, escape: Escape) -> Result<String, String> {
    let template = match COMPILED.get(source) {
        Some(t) => t,
        None => {
            let t = Arc::new(Template::compile(source).map_err(|e| e.to_string())?);
            COMPILED.insert(source.to_string(), t.clone());
            t
        }
    };
    let registry = match escape {
        Escape::None => &*PLAIN,
        Escape::Html => &*HTML,
    };
    let ctx = Context::wraps(data).map_err(|e| e.to_string())?;
    let mut rc = RenderContext::new(template.name.as_ref());
    let mut out = StringOutput::new();
    template
        .render(registry, &ctx, &mut rc, &mut out)
        .map_err(|e| e.to_string())?;
    out.into_string().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn renders_like_a_fresh_registry_and_escapes_on_request() {
        let data = json!({"user": {"name": "<b>Ann</b>"}, "n": 3});
        let src = "Hi {{user.name}} ({{n}}){{missing}}";
        assert_eq!(
            render(src, &data, Escape::None).unwrap(),
            "Hi <b>Ann</b> (3)"
        );
        assert_eq!(
            render(src, &data, Escape::Html).unwrap(),
            "Hi &lt;b&gt;Ann&lt;/b&gt; (3)"
        );
        // A second render comes from the compiled cache and agrees.
        assert_eq!(
            render(src, &data, Escape::None).unwrap(),
            "Hi <b>Ann</b> (3)"
        );
        let fresh = {
            let mut hb = Handlebars::new();
            hb.register_escape_fn(handlebars::no_escape);
            hb.render_template(src, &data).unwrap()
        };
        assert_eq!(render(src, &data, Escape::None).unwrap(), fresh);
        assert!(render("{{#if}}", &data, Escape::None).is_err());
        assert_eq!(
            render(
                "{{#each list}}{{this}},{{/each}}",
                &json!({"list": [1, 2]}),
                Escape::None
            )
            .unwrap(),
            "1,2,"
        );
    }
}
