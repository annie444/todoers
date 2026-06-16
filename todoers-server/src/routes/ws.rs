//! Real-time fanout over WebSockets. On connect, subscribe to the list's
//! broadcast channel and forward every published update envelope to the client.
//! Offline members are not this layer's concern — they catch up via the pull
//! endpoint on (re)connect.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use uuid::Uuid;

use crate::state::AppState;

use super::auth::AuthMember;

/// `GET /v1/lists/{list_id}/ws`. Registered with `any()` so the upgrade works
/// over both HTTP/1.1 (GET) and HTTP/2 (CONNECT).
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(list_id): Path<Uuid>,
    // Auth required to attach to a list's stream. (Stub for now; a real impl
    // would also confirm this member belongs to `list_id`.)
    _auth: AuthMember,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, list_id))
}

async fn handle_socket(socket: WebSocket, state: AppState, list_id: Uuid) {
    let tx = state.hub.sender(list_id);
    let mut rx = tx.subscribe();
    let (mut sink, mut stream) = socket.split();

    // Pump broadcast -> client.
    let mut forward = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if sink.send(msg).await.is_err() {
                        break; // client gone
                    }
                }
                // Lagged past the ring buffer: drop the stream and let the
                // client reconcile via pull. Closing is the honest signal.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Drain client -> server (we don't accept inbound writes over WS in this
    // design; appends go through the HTTP POST path. We only watch for Close).
    let mut drain = tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    // First task to finish tears down the other.
    tokio::select! {
        _ = &mut forward => drain.abort(),
        _ = &mut drain => forward.abort(),
    }
}
