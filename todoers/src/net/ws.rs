//! Real-time transport: subscribe to a list's live update fanout over a
//! WebSocket. The server publishes each appended update as a binary frame of
//! `serde_json(StoredUpdateDto)`; on lag it closes the socket and the caller
//! reconciles via the pull endpoint. Inbound writes are not part of the design —
//! appends go through the HTTP POST path — so this is receive-only.

use anyhow::Context;
use futures::{Stream, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use todoers_types::StoredUpdateDto;

/// Connect to `/v1/lists/{list_id}/ws` and return a receive-only stream of
/// decoded updates. The stream ends (yields `None`) when the server closes the
/// socket (e.g. on broadcast lag) — the caller should then fall back to a pull.
pub async fn ws_subscribe(
    base_url: &str,
    token: &str,
    list_id: Uuid,
) -> anyhow::Result<impl Stream<Item = anyhow::Result<StoredUpdateDto>>> {
    let base = base_url.trim_end_matches('/');
    // http(s) → ws(s); the path mirrors the HTTP routes.
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        // Already a ws(s) URL, or a bare host — pass through.
        base.to_string()
    };
    let url = format!("{ws_base}/v1/lists/{list_id}/ws");

    let mut request = url
        .into_client_request()
        .context("invalid websocket url")?;
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {token}")
            .parse()
            .context("invalid bearer header")?,
    );

    let (socket, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .context("websocket connect failed")?;

    Ok(socket.filter_map(|frame| async move {
        match frame {
            // The server sends Binary; tolerate Text too for inspectability.
            Ok(Message::Binary(bytes)) => Some(decode(&bytes)),
            Ok(Message::Text(text)) => Some(decode(text.as_bytes())),
            // Ping/Pong/Close/frame-level errors carry no update payload.
            Ok(_) => None,
            Err(e) => Some(Err(anyhow::Error::new(e).context("websocket stream error"))),
        }
    }))
}

fn decode(bytes: &[u8]) -> anyhow::Result<StoredUpdateDto> {
    serde_json::from_slice(bytes).context("invalid update frame")
}
