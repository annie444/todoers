//! HTTP handlers for the health endpoint.

/// `GET /healthz` — simple liveness check for Kubernetes and uptime monitoring.
pub async fn healthz() -> &'static str {
    "ok"
}
