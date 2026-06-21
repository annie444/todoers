//! The store facade: the single API the UI calls for list/todo operations.
//!
//! It ties together local persistence ([`crate::db`]), the CRDT documents
//! ([`crate::list_doc`]), the in-memory keys/DEKs ([`crate::session::Session`]),
//! and the crypto ([`crate::crypto`]). Every mutation follows one path:
//!
//! 1. apply the edit to the list's [`TodoDoc`];
//! 2. export just that delta, `produce_update` (encrypt-then-sign) it under the
//!    current DEK, and enqueue it in `outbound` for later upload;
//! 3. persist the new Loro snapshot and rebuild the SQLite read model.
//!
//! Keeping this dance in one audited place means UI components stay "dumb":
//! they render data and emit intent, never touching crypto or the wire format.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::Context;
use loro::VersionVector;
use ratatui::layout::Direction;
use time::OffsetDateTime;
use uuid::Uuid;

use todoers_types::{ListId, Member, MemberId, Role};

use crate::crypto;
use crate::db::Db;
use crate::list_doc::TodoDoc;
use crate::model::{ListSummary, MetaList, Priority, SortMode, TodoItem, TodoItemInput, ViewTarget};
use crate::session::Session;

/// Signed/AEAD byte-layout version for produced updates. Must match the
/// `signing_view`/`aead_aad` version on both ends (see [`crate::crypto`]).
const UPDATE_VERSION: u8 = 1;

/// One open pane: a view target plus its (sorted) items.
#[derive(Default, Clone)]
pub struct PaneData {
    /// The list/meta-list this pane shows (`None` before anything is opened).
    pub target: Option<ViewTarget>,
    /// The pane's items, sorted, each tagged with its owning list so commands
    /// work even in meta-list views (which span lists).
    pub items: Vec<(ListId, TodoItem)>,
}

/// The render-side snapshot the UI reads in `draw`. `App` refreshes it after
/// actions; the workspace component holds a clone of the [`SharedView`] handle.
/// Single-threaded (the run loop is driven by `block_on`), so `Rc<RefCell>` is
/// sound — no `Send` is required and net tasks never capture it.
pub struct ViewModel {
    /// Sidebar user lists (meta-lists are fixed and not stored here).
    pub lists: Vec<ListSummary>,
    /// Active sort applied to items + sidebar aggregates.
    pub sort: SortMode,
    /// Open panes (1 or 2). The workspace renders them side-by-side / stacked.
    pub panes: Vec<PaneData>,
    /// `None` = single pane; `Some(dir)` = two panes split along `dir`.
    pub split: Option<Direction>,
    /// Percent of the area given to the first pane when split (clamped 10..=90).
    pub ratio: u16,
}

impl Default for ViewModel {
    fn default() -> Self {
        Self {
            lists: Vec::new(),
            sort: SortMode::default(),
            panes: vec![PaneData {
                target: Some(ViewTarget::Meta(MetaList::AllTasks)),
                items: Vec::new(),
            }],
            split: None,
            ratio: 50,
        }
    }
}

/// Shared handle to the [`ViewModel`].
pub type SharedView = Rc<RefCell<ViewModel>>;

/// Owns the session and a cache of open CRDT documents.
pub struct Store {
    db: Db,
    session: Session,
    /// Open documents, keyed by list. Kept across edits so version vectors stay
    /// continuous and we avoid re-importing the snapshot every mutation.
    docs: HashMap<ListId, TodoDoc>,
}

impl Store {
    pub fn new(db: Db, session: Session) -> Self {
        Self {
            db,
            session,
            docs: HashMap::new(),
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    // ── lists ─────────────────────────────────────────────────────────────────

    /// Create a new owned list: mint a DEK (epoch 1) sealed to ourselves, write
    /// the list + self-membership rows, and seed a titled document.
    #[tracing::instrument(skip(self))]
    pub async fn create_list(&mut self, name: &str) -> anyhow::Result<ListId> {
        let list_id = ListId(*Uuid::new_v4().as_bytes());
        let epoch = 1;
        let dek = crypto::generate_dek();

        // The list row must exist before rows that FK-reference it (key_slots,
        // list_members, documents).
        self.db.upsert_list(list_id, Role::Owner, epoch, name).await?;

        // Our own wrapped DEK (the only key slot the client persists locally).
        let wrapped = crypto::seal_to(&dek, &self.session.identity_pub());
        self.db.save_key_slot(list_id, epoch, &wrapped).await?;
        self.session.insert_dek(list_id, epoch, dek);

        self.db
            .add_member_row(
                list_id,
                &Member {
                    id: self.session.member_id(),
                    identity_pub: self.session.identity_pub(),
                    signing_pub: self.session.signing_pub(),
                    role: Role::Owner,
                },
            )
            .await?;

        let doc = TodoDoc::new();
        let vv = doc.version();
        doc.set_title(name)?;
        self.docs.insert(list_id, doc);
        let doc = self.docs.get(&list_id).expect("just inserted");
        self.persist(list_id, doc, &vv).await?;
        Ok(list_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn rename_list(&mut self, list_id: ListId, name: &str) -> anyhow::Result<()> {
        self.db.rename_list(list_id, name).await?;
        self.edit_doc(list_id, |d| d.set_title(name)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_list(&mut self, list_id: ListId) -> anyhow::Result<()> {
        self.db.delete_list(list_id).await?;
        self.docs.remove(&list_id);
        Ok(())
    }

    /// Sidebar list summaries with aggregates (open count, nearest due, top
    /// priority) computed from the read model.
    #[tracing::instrument(skip(self))]
    pub async fn list_summaries(&self) -> anyhow::Result<Vec<ListSummary>> {
        let lists = self.db.list_lists().await?;
        let all = self.db.load_all_todo_items().await?;
        Ok(lists
            .into_iter()
            .map(|l| {
                let open: Vec<&TodoItem> = all
                    .iter()
                    .filter(|(lid, it)| *lid == l.list_id && !it.done)
                    .map(|(_, it)| it)
                    .collect();
                ListSummary {
                    id: l.list_id,
                    name: l.name,
                    role: l.role,
                    open_count: open.len(),
                    next_due: open.iter().filter_map(|i| i.due).min(),
                    top_priority: open
                        .iter()
                        .map(|i| i.priority)
                        .max()
                        .unwrap_or(Priority::None),
                }
            })
            .collect())
    }

    // ── todos ─────────────────────────────────────────────────────────────────

    #[tracing::instrument(skip(self, input))]
    pub async fn add_todo(
        &mut self,
        list_id: ListId,
        input: &TodoItemInput,
    ) -> anyhow::Result<String> {
        self.edit_doc(list_id, |d| d.add_item(input)).await
    }

    #[tracing::instrument(skip(self, input))]
    pub async fn edit_todo(
        &mut self,
        list_id: ListId,
        item_id: &str,
        input: &TodoItemInput,
    ) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.update_item(item_id, input))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn toggle_done(&mut self, list_id: ListId, item_id: &str) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.toggle_done(item_id)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_priority(
        &mut self,
        list_id: ListId,
        item_id: &str,
        priority: Priority,
    ) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.set_priority(item_id, priority))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_due(
        &mut self,
        list_id: ListId,
        item_id: &str,
        due: Option<OffsetDateTime>,
    ) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.set_due(item_id, due)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn move_todo(
        &mut self,
        list_id: ListId,
        from: usize,
        to: usize,
    ) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.move_item(from, to)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_todo(&mut self, list_id: ListId, item_id: &str) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.remove_item(item_id)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn add_tag(
        &mut self,
        list_id: ListId,
        item_id: &str,
        tag: &str,
    ) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.add_tag(item_id, tag)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn remove_tag(
        &mut self,
        list_id: ListId,
        item_id: &str,
        tag: &str,
    ) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.remove_tag(item_id, tag)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn add_subtask(
        &mut self,
        list_id: ListId,
        item_id: &str,
        title: &str,
    ) -> anyhow::Result<String> {
        self.edit_doc(list_id, |d| d.add_subtask(item_id, title))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn toggle_subtask(
        &mut self,
        list_id: ListId,
        item_id: &str,
        subtask_id: &str,
    ) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.toggle_subtask(item_id, subtask_id))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn remove_subtask(
        &mut self,
        list_id: ListId,
        item_id: &str,
        subtask_id: &str,
    ) -> anyhow::Result<()> {
        self.edit_doc(list_id, |d| d.remove_subtask(item_id, subtask_id))
            .await
    }

    // ── view-model refresh ─────────────────────────────────────────────────────

    /// Reload the sidebar summaries and every open pane's items into the shared
    /// [`ViewModel`].
    #[tracing::instrument(skip(self, view))]
    pub async fn refresh_view(&self, view: &SharedView) -> anyhow::Result<()> {
        // Snapshot inputs without holding the borrow across an await.
        let (targets, sort) = {
            let v = view.borrow();
            (
                v.panes.iter().map(|p| p.target).collect::<Vec<_>>(),
                v.sort,
            )
        };
        let mut summaries = self.list_summaries().await?;
        sort_summaries(&mut summaries, sort);
        let mut loaded = Vec::with_capacity(targets.len());
        for t in &targets {
            loaded.push(match t {
                Some(target) => self.load_view(*target, sort).await?,
                None => Vec::new(),
            });
        }
        let mut v = view.borrow_mut();
        v.lists = summaries;
        for (pane, items) in v.panes.iter_mut().zip(loaded) {
            pane.items = items;
        }
        Ok(())
    }

    /// Point a pane at a new view target and reload its items.
    #[tracing::instrument(skip(self, view))]
    pub async fn open_view(
        &self,
        view: &SharedView,
        target: ViewTarget,
        pane: usize,
    ) -> anyhow::Result<()> {
        if let Some(p) = view.borrow_mut().panes.get_mut(pane) {
            p.target = Some(target);
        }
        self.refresh_view(view).await
    }

    // ── reads ─────────────────────────────────────────────────────────────────

    /// Items for a view (a single list or a meta-list), sorted per `sort`.
    /// Meta-lists aggregate open items across all lists by due window.
    #[tracing::instrument(skip(self))]
    pub async fn load_view(
        &self,
        target: ViewTarget,
        sort: SortMode,
    ) -> anyhow::Result<Vec<(ListId, TodoItem)>> {
        let mut items: Vec<(ListId, TodoItem)> = match target {
            ViewTarget::List(id) => self
                .db
                .load_todo_items(id)
                .await?
                .into_iter()
                .map(|it| (id, it))
                .collect(),
            ViewTarget::Meta(meta) => {
                let now = OffsetDateTime::now_utc();
                self.db
                    .load_all_todo_items()
                    .await?
                    .into_iter()
                    .filter(|(_, it)| !it.done && in_meta(meta, it, now))
                    .collect()
            }
        };
        sort_items(&mut items, sort);
        Ok(items)
    }

    /// The full item (including subtasks) read straight from the document.
    #[tracing::instrument(skip(self))]
    pub async fn full_item(
        &mut self,
        list_id: ListId,
        item_id: &str,
    ) -> anyhow::Result<Option<TodoItem>> {
        self.ensure_doc(list_id).await?;
        let doc = self.docs.get(&list_id).expect("ensured");
        Ok(doc.items().into_iter().find(|i| i.id == item_id))
    }

    #[tracing::instrument(skip(self))]
    pub async fn members(&self, list_id: ListId) -> anyhow::Result<Vec<Member>> {
        self.db.list_members(list_id).await
    }

    // ── membership (local-side; server delivery is Phase 8) ────────────────────

    /// Add a collaborator locally: record their membership and seal the current
    /// DEK to them. The sealed DEK upload + server membership call land in the
    /// sync phase; here we keep the local mirror consistent.
    #[tracing::instrument(skip(self))]
    pub async fn add_member_local(&mut self, list_id: ListId, member: Member) -> anyhow::Result<()> {
        self.db.add_member_row(list_id, &member).await?;
        Ok(())
    }

    /// Remove a collaborator locally and **rotate**: a fresh DEK under a bumped
    /// epoch, sealed to ourselves (re-sealing to remaining members + server
    /// notification is Phase 8). Future updates write under the new epoch.
    #[tracing::instrument(skip(self))]
    pub async fn remove_member_local(
        &mut self,
        list_id: ListId,
        member_id: MemberId,
    ) -> anyhow::Result<()> {
        let current = self
            .db
            .list_epoch(list_id)
            .await?
            .context("remove_member: unknown list")?;
        let new_epoch = current + 1;
        let new_dek = crypto::generate_dek();
        let wrapped = crypto::seal_to(&new_dek, &self.session.identity_pub());
        self.db.save_key_slot(list_id, new_epoch, &wrapped).await?;
        self.session.insert_dek(list_id, new_epoch, new_dek);
        self.db.set_epoch(list_id, new_epoch).await?;
        self.db.remove_member_row(list_id, member_id).await?;
        Ok(())
    }

    // ── internals ──────────────────────────────────────────────────────────────

    /// Load a list's document into the cache if not already open.
    async fn ensure_doc(&mut self, list_id: ListId) -> anyhow::Result<()> {
        if self.docs.contains_key(&list_id) {
            return Ok(());
        }
        let doc = match self.db.load_document(list_id).await? {
            Some(snap) => TodoDoc::from_snapshot(&snap)?,
            None => TodoDoc::new(),
        };
        self.docs.insert(list_id, doc);
        Ok(())
    }

    /// Run a closure that mutates the document, then run the persist pipeline.
    async fn edit_doc<R>(
        &mut self,
        list_id: ListId,
        f: impl FnOnce(&TodoDoc) -> anyhow::Result<R>,
    ) -> anyhow::Result<R> {
        self.ensure_doc(list_id).await?;
        let doc = self.docs.get(&list_id).expect("ensured");
        let vv = doc.version();
        let out = f(doc)?;
        self.persist(list_id, doc, &vv).await?;
        Ok(out)
    }

    /// Encrypt+sign the delta since `vv_before`, enqueue it, then persist the
    /// snapshot and rebuild the read model.
    async fn persist(
        &self,
        list_id: ListId,
        doc: &TodoDoc,
        vv_before: &VersionVector,
    ) -> anyhow::Result<()> {
        let epoch = self
            .db
            .list_epoch(list_id)
            .await?
            .context("persist: unknown list")?;
        let dek = self
            .session
            .dek(list_id, epoch)
            .context("persist: no DEK for list/epoch")?;

        let update = doc.export_updates_from(vv_before)?;
        if !update.is_empty() {
            let payload = crypto::produce_update(
                UPDATE_VERSION,
                list_id,
                epoch,
                self.session.member_id(),
                &dek,
                &self.session.signing_key(),
                &update,
            )?;
            let bytes = serde_json::to_vec(&payload)?;
            self.db
                .enqueue_outbound(list_id, epoch, &bytes, &payload.signature)
                .await?;
        }

        let snap = doc.export_snapshot()?;
        self.db.save_document(list_id, &snap).await?;
        self.db.replace_todo_items(list_id, &doc.items()).await?;
        Ok(())
    }
}

/// Whether an item belongs in a meta-list view as of `now`.
fn in_meta(meta: MetaList, it: &TodoItem, now: OffsetDateTime) -> bool {
    meta.contains(it.due, now)
}

/// Sort sidebar list summaries by the active mode, using per-list aggregates for
/// due/priority (nearest due first; highest top-priority first).
fn sort_summaries(lists: &mut [ListSummary], sort: SortMode) {
    match sort {
        SortMode::Alphabetical => {
            lists.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        }
        SortMode::DueDate => lists.sort_by(|a, b| match (a.next_due, b.next_due) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        }),
        SortMode::Priority => {
            lists.sort_by(|a, b| b.top_priority.rank().cmp(&a.top_priority.rank()))
        }
    }
}

/// Sort items in place. Done-ness is not a sort key here (callers filter first
/// where they want to); `next()`-cycle order matches [`SortMode`].
fn sort_items(items: &mut [(ListId, TodoItem)], sort: SortMode) {
    match sort {
        SortMode::Alphabetical => {
            items.sort_by(|(_, a), (_, b)| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        }
        SortMode::DueDate => items.sort_by(|(_, a), (_, b)| match (a.due, b.due) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less, // dated before undated
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }),
        // Highest priority first.
        SortMode::Priority => {
            items.sort_by(|(_, a), (_, b)| b.priority.rank().cmp(&a.priority.rank()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Pool, Sqlite};
    use time::OffsetDateTime;
    use todoers_types::MemberId;

    use crate::auth::UnlockedKeys;

    /// Build a Store over a migrated test pool with a fresh random identity.
    fn store_with(db: Pool<Sqlite>) -> Store {
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

    fn input(title: &str) -> TodoItemInput {
        TodoItemInput {
            title: title.into(),
            ..Default::default()
        }
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn create_list_seeds_summary_and_outbound(db: Pool<Sqlite>) {
        let mut store = store_with(db);
        let id = store.create_list("Groceries").await.unwrap();

        let summaries = store.list_summaries().await.unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "Groceries");
        assert_eq!(summaries[0].role, Role::Owner);
        assert_eq!(summaries[0].open_count, 0);

        // The title edit produced one queued update.
        assert!(store.db.outbound_count(id).await.unwrap() >= 1);
        // We are recorded as the sole (owner) member.
        assert_eq!(store.members(id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn todo_crud_round_trips_through_read_model(db: Pool<Sqlite>) {
        let mut store = store_with(db);
        let list = store.create_list("L").await.unwrap();

        let a = store.add_todo(list, &input("buy milk")).await.unwrap();
        store.add_todo(list, &input("walk dog")).await.unwrap();

        let view = store
            .load_view(ViewTarget::List(list), SortMode::Alphabetical)
            .await
            .unwrap();
        assert_eq!(
            view.iter().map(|(_, i)| i.title.as_str()).collect::<Vec<_>>(),
            vec!["buy milk", "walk dog"]
        );

        store.toggle_done(list, &a).await.unwrap();
        let done = store
            .load_view(ViewTarget::List(list), SortMode::Alphabetical)
            .await
            .unwrap();
        assert!(done.iter().find(|(_, i)| i.id == a).unwrap().1.done);

        store
            .edit_todo(
                list,
                &a,
                &TodoItemInput {
                    title: "buy oat milk".into(),
                    priority: Priority::High,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let edited = store
            .load_view(ViewTarget::List(list), SortMode::Priority)
            .await
            .unwrap();
        assert_eq!(edited[0].1.title, "buy oat milk");
        assert_eq!(edited[0].1.priority, Priority::High);

        store.delete_todo(list, &a).await.unwrap();
        let after = store
            .load_view(ViewTarget::List(list), SortMode::Alphabetical)
            .await
            .unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].1.title, "walk dog");
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn meta_list_due_today_aggregates_across_lists(db: Pool<Sqlite>) {
        let mut store = store_with(db);
        let a = store.create_list("A").await.unwrap();
        let b = store.create_list("B").await.unwrap();

        let today = OffsetDateTime::now_utc();
        let next_month = today + time::Duration::days(40);

        store
            .add_todo(
                a,
                &TodoItemInput {
                    title: "due now".into(),
                    due: Some(today),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        store
            .add_todo(
                b,
                &TodoItemInput {
                    title: "later".into(),
                    due: Some(next_month),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let today_view = store
            .load_view(ViewTarget::Meta(MetaList::DueToday), SortMode::DueDate)
            .await
            .unwrap();
        assert_eq!(
            today_view
                .iter()
                .map(|(_, i)| i.title.as_str())
                .collect::<Vec<_>>(),
            vec!["due now"]
        );

        let all = store
            .load_view(ViewTarget::Meta(MetaList::AllTasks), SortMode::DueDate)
            .await
            .unwrap();
        assert_eq!(all.len(), 2, "AllTasks spans both lists");
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn data_survives_a_fresh_store(db: Pool<Sqlite>) {
        // First store creates and populates.
        let id;
        {
            let mut store = store_with(db.clone());
            id = store.create_list("Persistent").await.unwrap();
            store.add_todo(id, &input("remember me")).await.unwrap();
        }
        // A brand-new store over the same DB still reads the read model.
        let store2 = store_with(db);
        let view = store2
            .load_view(ViewTarget::List(id), SortMode::Alphabetical)
            .await
            .unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].1.title, "remember me");
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn remove_member_rotates_epoch(db: Pool<Sqlite>) {
        let mut store = store_with(db);
        let list = store.create_list("Shared").await.unwrap();
        assert_eq!(store.db.list_epoch(list).await.unwrap(), Some(1));

        // Add then remove a fabricated member; epoch should bump and a new DEK
        // for the new epoch must be available for subsequent writes.
        let other = Member {
            id: MemberId([42u8; 16]),
            identity_pub: crypto::generate_identity().1,
            signing_pub: crypto::generate_signing().1,
            role: Role::Member,
        };
        store.add_member_local(list, other.clone()).await.unwrap();
        assert_eq!(store.members(list).await.unwrap().len(), 2);

        store.remove_member_local(list, other.id).await.unwrap();
        assert_eq!(store.db.list_epoch(list).await.unwrap(), Some(2));
        assert_eq!(store.members(list).await.unwrap().len(), 1);

        // A write after rotation still succeeds (DEK for epoch 2 is present).
        store.add_todo(list, &input("post-rotation")).await.unwrap();
    }
}
