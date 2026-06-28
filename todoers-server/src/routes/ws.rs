//! Real-time fanout over WebSockets. On connect, subscribe to the list's
//! broadcast channel and forward every published update envelope to the client.
//! Offline members are not this layer's concern — they catch up via the pull
//! endpoint on (re)connect.

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast::error::RecvError;

use todoers_types::{ListId, MemberId};

use crate::state::AppState;

use super::auth::AuthMember;

/// `GET /v1/lists/ws`. Registered with `any()` so the upgrade works over both
/// HTTP/1.1 (GET) and HTTP/2 (CONNECT). The list to subscribe to arrives as the
/// first postcard frame after the upgrade (paths carry no ids).
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    auth: AuthMember,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, auth.member_id))
}

async fn handle_socket(socket: WebSocket, state: AppState, member_id: MemberId) {
    let (mut sink, mut stream) = socket.split();

    // First frame names the list (postcard `ListId`). A malformed/missing frame
    // or a non-member just gets the stream closed.
    let list_id: ListId = match stream.next().await {
        Some(Ok(Message::Binary(buf))) => match postcard::from_bytes(&buf) {
            Ok(id) => id,
            Err(_) => {
                let _ = sink.send(Message::Close(None)).await;
                return;
            }
        },
        _ => {
            let _ = sink.send(Message::Close(None)).await;
            return;
        }
    };

    // A valid token is not enough: only members of THIS list may attach to its
    // stream, otherwise any authenticated user could tap any list's fanout.
    if !matches!(
        state.db.member_role(&list_id, &member_id).await,
        Ok(Some(_))
    ) {
        let _ = sink.send(Message::Close(None)).await;
        return;
    }

    let tx = state.hub.sender(&list_id);
    let mut rx = tx.subscribe();

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
                Err(RecvError::Lagged(_)) => {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
                Err(RecvError::Closed) => break,
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
