//! Off-loop store actor. Owns the `Store` (and thus the secret keys + Loro docs)
//! on its own tokio task so the UI event loop never blocks on db/crypto/Loro
//! work. The UI sends `StoreCommand`s and receives `WorkerMsg`s — chiefly
//! `ViewSnapshot`s of plain `Send` data it installs into the view-model.

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::{
    error::TodoersResult,
    model::{ListSummary, MetaList, SortMode, TodoItem, TodoItemInput, ViewTarget},
};
use todoers_types::{KeySlotDto, ListId, Member, MemberId, MetadataResponse, StoredUpdateDto};

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
    /// Server → local: verify/decrypt/merge a batch of pulled or streamed
    /// updates (from the sync engine).
    ApplyRemote {
        list_id: ListId,
        updates: Vec<StoredUpdateDto>,
    },
    /// Server → local: seed a list discovered during initial sync (membership,
    /// wrapped DEKs, metadata) so its updates can be decrypted.
    IngestRemoteList {
        meta: Box<MetadataResponse>,
        keys: Vec<KeySlotDto>,
    },
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

/// Run the store actor until the command channel closes. Holds the current
/// `(targets, sort)` and emits a fresh snapshot after every mutating command.
pub async fn run_store_worker(mut store: Store, mut cmd_rx: CommandRx, out: WorkerTx) {
    let mut targets: Vec<Option<ViewTarget>> = vec![None];
    let mut sort = SortMode::default();

    while let Some(cmd) = cmd_rx.recv().await {
        // Returns true if the command changed list/todo state (snapshot needed).
        let result: TodoersResult<bool> = async {
            match cmd {
                StoreCommand::SetView {
                    targets: t,
                    sort: s,
                } => {
                    targets = t;
                    sort = s;
                    Ok(true)
                }
                StoreCommand::CreateList { name } => {
                    store.create_list(&name).await?;
                    Ok(true)
                }
                StoreCommand::RenameList { list_id, name } => {
                    store.rename_list(&list_id, &name).await?;
                    Ok(true)
                }
                StoreCommand::DeleteList(list_id) => {
                    store.delete_list(&list_id).await?;
                    // Any pane showing the deleted list falls back to All Tasks.
                    let fallback = ViewTarget::Meta(MetaList::AllTasks);
                    for t in targets.iter_mut() {
                        if *t == Some(ViewTarget::List(list_id)) {
                            *t = Some(fallback);
                        }
                    }
                    Ok(true)
                }
                StoreCommand::AddTodo { list_id, input } => {
                    store.add_todo(&list_id, &input).await?;
                    Ok(true)
                }
                StoreCommand::EditTodo {
                    list_id,
                    item_id,
                    input,
                } => {
                    store.edit_todo(&list_id, &item_id, &input).await?;
                    Ok(true)
                }
                StoreCommand::ToggleDone { list_id, item_id } => {
                    store.toggle_done(&list_id, &item_id).await?;
                    Ok(true)
                }
                StoreCommand::DeleteTodo { list_id, item_id } => {
                    store.delete_todo(&list_id, &item_id).await?;
                    Ok(true)
                }
                StoreCommand::AddMember { list_id, member } => {
                    store.add_member_local(&list_id, member).await?;
                    Ok(true)
                }
                StoreCommand::RemoveMember { list_id, member_id } => {
                    store.remove_member_local(&list_id, member_id).await?;
                    Ok(true)
                }
                StoreCommand::FetchFullItem { list_id, item_id } => {
                    let item = store.full_item(&list_id, &item_id).await?;
                    let _ = out.send(WorkerMsg::FullItem(Box::new(item.map(|it| (list_id, it)))));
                    Ok(false)
                }
                StoreCommand::FetchMembers(list_id) => {
                    let members = store.members(&list_id).await?;
                    let _ = out.send(WorkerMsg::Members(Box::new((list_id, members))));
                    Ok(false)
                }
                StoreCommand::ApplyRemote { list_id, updates } => {
                    let mut changed = false;
                    for dto in updates {
                        changed |= store.apply_remote_update(&list_id, dto).await?;
                    }
                    Ok(changed)
                }
                StoreCommand::IngestRemoteList { meta, keys } => {
                    store.ingest_remote_list(*meta, keys).await?;
                    Ok(true)
                }
            }
        }
        .await;

        match result {
            Ok(true) => match store.snapshot_for(&targets, sort).await {
                Ok(snap) => {
                    let _ = out.send(WorkerMsg::Snapshot(Box::new(snap)));
                }
                Err(e) => {
                    let _ = out.send(WorkerMsg::Error(format!("refresh failed: {e:#}")));
                }
            },
            Ok(false) => {}
            Err(e) => {
                let _ = out.send(WorkerMsg::Error(format!("{e:#}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Pool, Sqlite};
    use tokio::sync::mpsc::unbounded_channel;

    use crate::auth::UnlockedKeys;
    use crate::crypto;
    use crate::db::Db;
    use crate::model::MetaList;
    use crate::session::Session;

    fn test_store(db: Pool<Sqlite>) -> Store {
        let db = Db::from_pool(db);
        let (identity_secret, identity_pub) = crypto::generate_identity();
        let (signing_seed, signing_pub) = crypto::generate_signing();
        let keys = UnlockedKeys {
            member_id: MemberId::from_identity_pub(&identity_pub),
            identity_secret,
            identity_pub,
            signing_seed,
            signing_pub,
            token: String::new(),
        };
        Store::new(db, Session::new(&keys))
    }

    #[sqlx::test(migrations = "../todoers-client/db/migrations")]
    async fn create_then_add_emits_snapshots(db: Pool<Sqlite>) {
        let store = test_store(db);
        let (cmd_tx, cmd_rx) = unbounded_channel();
        let (out_tx, mut out_rx) = unbounded_channel();
        let worker = tokio::spawn(run_store_worker(store, cmd_rx, out_tx));

        // Point pane 0 at All Tasks.
        cmd_tx
            .send(StoreCommand::SetView {
                targets: vec![Some(ViewTarget::Meta(MetaList::AllTasks))],
                sort: SortMode::default(),
            })
            .unwrap();
        // SetView snapshot: no lists yet.
        let WorkerMsg::Snapshot(s0) = out_rx.recv().await.unwrap() else {
            panic!("expected snapshot");
        };
        assert!(s0.lists.is_empty());

        cmd_tx
            .send(StoreCommand::CreateList {
                name: "Groceries".into(),
            })
            .unwrap();
        let WorkerMsg::Snapshot(s1) = out_rx.recv().await.unwrap() else {
            panic!("expected snapshot");
        };
        assert_eq!(s1.lists.len(), 1);
        assert_eq!(s1.lists[0].name, "Groceries");
        let list_id = s1.lists[0].id;

        cmd_tx
            .send(StoreCommand::AddTodo {
                list_id,
                input: TodoItemInput {
                    title: "milk".into(),
                    ..Default::default()
                },
            })
            .unwrap();
        let WorkerMsg::Snapshot(s2) = out_rx.recv().await.unwrap() else {
            panic!("expected snapshot");
        };
        // Pane 0 (All Tasks) now shows the new open todo.
        assert_eq!(s2.panes[0].len(), 1);
        assert_eq!(s2.panes[0][0].1.title, "milk");

        drop(cmd_tx);
        worker.await.unwrap();
    }
}
