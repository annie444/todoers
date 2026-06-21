//! Off-loop store actor. Owns the `Store` (and thus the secret keys + Loro docs)
//! on its own tokio task so the UI event loop never blocks on db/crypto/Loro
//! work. The UI sends `StoreCommand`s and receives `WorkerMsg`s — chiefly
//! `ViewSnapshot`s of plain `Send` data it installs into the view-model.

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use todoers_types::{ListId, Member, MemberId};

use crate::model::{ListSummary, SortMode, TodoItem, TodoItemInput, ViewTarget};
use crate::store::Store;

/// What the UI asks the worker to do. Layout (split/ratio/focus/selection) stays
/// UI-side; the worker only needs the per-pane targets + sort to compute items.
pub enum StoreCommand {
    /// Replace the worker's notion of what each pane shows; triggers a snapshot.
    SetView {
        targets: Vec<Option<ViewTarget>>,
        sort: SortMode,
    },
    CreateList {
        name: String,
    },
    RenameList {
        list_id: ListId,
        name: String,
    },
    DeleteList(ListId),
    AddTodo {
        list_id: ListId,
        input: TodoItemInput,
    },
    EditTodo {
        list_id: ListId,
        item_id: String,
        input: TodoItemInput,
    },
    ToggleDone {
        list_id: ListId,
        item_id: String,
    },
    DeleteTodo {
        list_id: ListId,
        item_id: String,
    },
    AddMember {
        list_id: ListId,
        member: Member,
    },
    RemoveMember {
        list_id: ListId,
        member_id: MemberId,
    },
    FetchFullItem {
        list_id: ListId,
        item_id: String,
    },
    FetchMembers(ListId),
}

/// Plain, `Send` view data computed by the worker for the current targets+sort.
pub struct ViewSnapshot {
    pub lists: Vec<ListSummary>,
    /// Items per pane, indexed to match the UI's pane order.
    pub panes: Vec<Vec<(ListId, TodoItem)>>,
}

/// Replies from the worker back to the UI loop.
pub enum WorkerMsg {
    Snapshot(Box<ViewSnapshot>),
    /// Reply to `FetchFullItem`: the list id + full item (with subtasks), if found.
    FullItem(Box<Option<(ListId, TodoItem)>>),
    Members(Box<(ListId, Vec<Member>)>),
    Error(String),
}

pub type CommandTx = UnboundedSender<StoreCommand>;
pub type CommandRx = UnboundedReceiver<StoreCommand>;
pub type WorkerTx = UnboundedSender<WorkerMsg>;
pub type WorkerRx = UnboundedReceiver<WorkerMsg>;

#[allow(dead_code)] // implemented in Task C2
pub async fn run_store_worker(_store: Store, _cmd_rx: CommandRx, _out: WorkerTx) {}
