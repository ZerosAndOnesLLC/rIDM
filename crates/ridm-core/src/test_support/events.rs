use std::sync::Mutex;

use crate::events::{Event, EventSink};

/// Records published events so tests can assert on exactly what a service emitted.
#[derive(Debug, Default)]
pub struct RecordingEventSink {
    events: Mutex<Vec<Event>>,
}

impl RecordingEventSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().expect("mock poisoned").clone()
    }

    /// Names (`user.created`, ...) of every recorded event, in order.
    pub fn names(&self) -> Vec<&'static str> {
        self.events().iter().map(Event::name).collect()
    }

    pub fn clear(&self) {
        self.events.lock().expect("mock poisoned").clear();
    }
}

impl EventSink for RecordingEventSink {
    fn publish(&self, event: Event) {
        self.events.lock().expect("mock poisoned").push(event);
    }
}
