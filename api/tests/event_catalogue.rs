//! The console's event catalogue (`EVENT_NAMES` in `ui/src/lib/console/ops.ts`,
//! behind the webhook subscription picker and the audit filter) names exactly
//! the events the server emits (`EventKind::name`).

use std::collections::BTreeSet;

const EVENTS_RS: &str = include_str!("../../crates/ridm-core/src/events/event.rs");
const OPS_TS: &str = include_str!("../../ui/src/lib/console/ops.ts");

/// The quoted dotted names in `text`.
fn dotted_names(text: &str) -> BTreeSet<String> {
    text.split('"')
        .skip(1)
        .step_by(2)
        .filter(|s| {
            s.split_once('.').is_some_and(|(a, b)| {
                !a.is_empty()
                    && !b.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_' || c == '.')
            })
        })
        .map(str::to_string)
        .collect()
}

#[test]
fn the_console_lists_every_event_the_server_emits() {
    let name_fn = EVENTS_RS
        .split("pub fn name(&self) -> &'static str {\n        match self {")
        .nth(1)
        .expect("EventKind::name");
    let server = dotted_names(name_fn.split("\n    }\n").next().unwrap());
    assert!(server.len() >= 100, "{} server events parsed", server.len());

    let list = OPS_TS
        .split("export const EVENT_NAMES = [")
        .nth(1)
        .and_then(|s| s.split("];").next())
        .expect("EVENT_NAMES in ops.ts");
    let console = dotted_names(list);

    let missing: Vec<_> = server.difference(&console).collect();
    let unknown: Vec<_> = console.difference(&server).collect();
    assert!(
        missing.is_empty() && unknown.is_empty(),
        "missing from the console: {missing:?}; not emitted by the server: {unknown:?}"
    );
}
