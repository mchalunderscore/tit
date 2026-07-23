use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Clone, Default)]
pub(crate) struct Telemetry {
    counters: Arc<Counters>,
    enabled: bool,
}

#[derive(Default)]
struct Counters {
    http_requests: AtomicU64,
    http_errors: AtomicU64,
    http_in_flight: AtomicU64,
    ssh_connections: AtomicU64,
    ssh_auth_rejected: AtomicU64,
    ssh_operations: AtomicU64,
}

pub(crate) struct HttpInFlight {
    counters: Arc<Counters>,
}

impl Drop for HttpInFlight {
    fn drop(&mut self) {
        self.counters.http_in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Telemetry {
    #[allow(
        dead_code,
        reason = "integration tests use disabled telemetry outside the production server"
    )]
    pub(crate) fn enabled() -> Self {
        Self {
            counters: Arc::new(Counters::default()),
            enabled: true,
        }
    }

    pub(crate) fn http_start(&self) -> HttpInFlight {
        self.counters.http_requests.fetch_add(1, Ordering::Relaxed);
        self.counters.http_in_flight.fetch_add(1, Ordering::Relaxed);
        HttpInFlight {
            counters: Arc::clone(&self.counters),
        }
    }

    pub(crate) fn http_finish(
        &self,
        request_id: &str,
        method: &str,
        status: u16,
        duration: Duration,
    ) {
        if status >= 400 {
            self.counters.http_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.write_event(&Event {
            timestamp_ms: timestamp_ms(),
            level: "info",
            event: "http.request",
            request_id: Some(request_id),
            operation_id: None,
            method: Some(method),
            status: Some(status),
            duration_ms: Some(duration.as_millis().min(u128::from(u64::MAX)) as u64),
            outcome: None,
        });
    }

    pub(crate) fn ssh_connection(&self, connection_id: &str) {
        self.counters
            .ssh_connections
            .fetch_add(1, Ordering::Relaxed);
        self.write_ssh_event("ssh.connection", connection_id, "accepted");
    }

    pub(crate) fn ssh_auth(&self, connection_id: &str, accepted: bool) {
        if !accepted {
            self.counters
                .ssh_auth_rejected
                .fetch_add(1, Ordering::Relaxed);
        }
        self.write_ssh_event(
            "ssh.authentication",
            connection_id,
            if accepted { "accepted" } else { "rejected" },
        );
    }

    pub(crate) fn ssh_operation(&self, operation_id: &str) {
        self.counters.ssh_operations.fetch_add(1, Ordering::Relaxed);
        self.write_ssh_event("ssh.operation", operation_id, "started");
    }

    #[allow(
        dead_code,
        reason = "some integration tests compile telemetry without process lifecycle"
    )]
    pub(crate) fn lifecycle(&self, event: &'static str, outcome: &'static str) {
        self.write_event(&Event {
            timestamp_ms: timestamp_ms(),
            level: "info",
            event,
            request_id: None,
            operation_id: None,
            method: None,
            status: None,
            duration_ms: None,
            outcome: Some(outcome),
        });
    }

    pub(crate) fn metrics(&self) -> String {
        format!(
            concat!(
                "tit_http_requests_total {}\n",
                "tit_http_errors_total {}\n",
                "tit_http_requests_in_flight {}\n",
                "tit_ssh_connections_total {}\n",
                "tit_ssh_auth_rejected_total {}\n",
                "tit_ssh_operations_total {}\n"
            ),
            self.counters.http_requests.load(Ordering::Relaxed),
            self.counters.http_errors.load(Ordering::Relaxed),
            self.counters.http_in_flight.load(Ordering::Relaxed),
            self.counters.ssh_connections.load(Ordering::Relaxed),
            self.counters.ssh_auth_rejected.load(Ordering::Relaxed),
            self.counters.ssh_operations.load(Ordering::Relaxed),
        )
    }

    fn write_ssh_event(&self, event: &'static str, operation_id: &str, outcome: &'static str) {
        self.write_event(&Event {
            timestamp_ms: timestamp_ms(),
            level: "info",
            event,
            request_id: None,
            operation_id: Some(operation_id),
            method: None,
            status: None,
            duration_ms: None,
            outcome: Some(outcome),
        });
    }

    fn write_event(&self, event: &Event<'_>) {
        if !self.enabled {
            return;
        }
        let Ok(line) = serde_json::to_string(event) else {
            return;
        };
        let mut error = std::io::stderr().lock();
        let _ = writeln!(error, "{line}");
    }
}

fn timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[derive(Serialize)]
struct Event<'a> {
    timestamp_ms: u64,
    level: &'static str,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::Telemetry;
    use std::time::Duration;

    #[test]
    fn emits_only_fixed_bounded_metrics() {
        let telemetry = Telemetry::default();
        let request = telemetry.http_start();
        telemetry.http_finish("request", "GET", 404, Duration::from_millis(2));
        drop(request);
        telemetry.ssh_connection("connection");
        telemetry.ssh_auth("connection", false);
        telemetry.ssh_operation("operation");

        assert_eq!(
            telemetry.metrics(),
            concat!(
                "tit_http_requests_total 1\n",
                "tit_http_errors_total 1\n",
                "tit_http_requests_in_flight 0\n",
                "tit_ssh_connections_total 1\n",
                "tit_ssh_auth_rejected_total 1\n",
                "tit_ssh_operations_total 1\n"
            )
        );
    }
}
