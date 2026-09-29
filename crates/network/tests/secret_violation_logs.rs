//! Regression coverage for secret policy diagnostics at the request boundary.

#![cfg(feature = "engine")]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use microsandbox_network::config::builder::SecretBuilder;
use microsandbox_network::secrets::config::{SecretViolationAction, SecretsConfig};
use microsandbox_network::secrets::handler::SecretsHandler;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<CapturedEvent>>>);

struct CapturedEvent {
    level: Level,
    fields: BTreeMap<String, String>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Visit for CapturedEvent {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.fields
            .insert(field.name().into(), format!("{value:?}"));
    }
}

impl Subscriber for CapturedLogs {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut captured = CapturedEvent {
            level: *event.metadata().level(),
            fields: BTreeMap::new(),
        };
        event.record(&mut captured);
        self.0.lock().unwrap().push(captured);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn secret_violation_logs_distinguish_blocking_from_allowed_placeholders() {
    // Keep tracing capture in its own integration-test process so concurrent
    // unit tests cannot change callsite interest while these events are emitted.
    let logs = CapturedLogs::default();
    let _subscriber = tracing::subscriber::set_default(logs.clone());

    for action in [
        SecretViolationAction::Block,
        SecretViolationAction::BlockAndLog,
        SecretViolationAction::BlockAndTerminate,
    ] {
        for tls_intercepted in [false, true] {
            for (location, request) in [
                (
                    "header",
                    "GET / HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer $KEY\r\n\r\n",
                ),
                (
                    "body",
                    "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\n$KEY",
                ),
            ] {
                logs.0.lock().unwrap().clear();
                let config = SecretsConfig {
                    secrets: vec![
                        SecretBuilder::new()
                            .env("API_KEY")
                            .value("real-secret")
                            .placeholder("$KEY")
                            .allow("api.example.com")
                            .build(),
                    ],
                    violation_action: action.clone(),
                    ..Default::default()
                };
                let mut handler = SecretsHandler::new(&config, "api.example.com", tls_intercepted);
                let result = handler.substitute(request.as_bytes());
                let events = logs.0.lock().unwrap();

                if tls_intercepted {
                    let expected = if location == "header" {
                        request.replace("$KEY", "real-secret")
                    } else {
                        request.to_string()
                    };
                    assert_eq!(result.unwrap().as_ref(), expected.as_bytes());
                    assert!(
                        events.is_empty(),
                        "permitted requests must not log violations"
                    );
                    continue;
                }

                assert_eq!(result.unwrap_err(), action);
                if action == SecretViolationAction::Block {
                    assert!(events.is_empty(), "silent blocking must not log violations");
                    continue;
                }

                assert_eq!(events.len(), 1);
                let event = &events[0];
                let (level, action_name, message) = match action {
                    SecretViolationAction::BlockAndLog => (
                        Level::WARN,
                        "block-and-log",
                        "secret violation: placeholder detected where substitution or passthrough is not permitted",
                    ),
                    SecretViolationAction::BlockAndTerminate => (
                        Level::ERROR,
                        "block-and-terminate",
                        "secret violation: placeholder detected where substitution or passthrough is not permitted - terminating",
                    ),
                    SecretViolationAction::Block => unreachable!(),
                };
                assert_eq!(event.fields["message"], message);
                assert_eq!(event.level, level);
                assert_eq!(event.fields["action"], action_name);
                assert_eq!(event.fields["sni"], "api.example.com");
                assert_eq!(event.fields["location"], location);
                assert!(
                    event
                        .fields
                        .values()
                        .all(|value| !value.contains("real-secret"))
                );
            }
        }
    }
}
