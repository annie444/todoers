//! # The store facade
//!
//! > The single API the UI calls for list/todo operations.
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

use std::collections::HashMap;
use std::sync::Arc;

use loro::VersionVector;
use old_rand_core::OsRng;
use time::OffsetDateTime;
use tracing::{debug, error};

use todoers_types::{
    Dek, Epoch, KeySlotDto, ListId, Member, MemberId, MetadataResponse, Role, StoredUpdateDto,
};

use crate::crypto;
use crate::db::Db;
use crate::error::{TodoersError, TodoersResult};
use crate::list_doc::TodoDoc;
use crate::model::{
    ListSummary, MetaList, Priority, SortMode, TodoItem, TodoItemInput, ViewTarget,
};
use crate::session::Session;
use crate::sync::{SyncCommand, SyncTx};
use crate::worker::ViewSnapshot;

/// Signed/AEAD byte-layout version for produced updates. Must match the
/// `signing_view`/`aead_aad` version on both ends (see [`todoers_client::crypto`]).
const UPDATE_VERSION: u8 = 1;

/// Owns the session and a cache of open CRDT documents.
pub struct Store {
    db: Arc<Db>,
    session: Session,
    /// Open documents, keyed by list. Kept across edits so version vectors stay
    /// continuous and we avoid re-importing the snapshot every mutation.
    docs: HashMap<ListId, TodoDoc>,
    /// Channel to the sync engine. The store produces all server-bound material
    /// (sealed DEKs, signed updates) and hands it here; the sync task does the
    /// I/O. `None` in tests / before the sync task is wired.
    sync_tx: Option<SyncTx>,
}

impl Store {
    #[tracing::instrument(skip(db, session))]
    pub fn new(db: Arc<Db>, session: Session) -> Self {
        Self {
            db,
            session,
            docs: HashMap::new(),
            sync_tx: None,
        }
    }

    /// Attach the sync engine so mutations are pushed to the server. Call once,
    /// right after the sync task is spawned.
    #[tracing::instrument(skip(self, tx))]
    pub fn set_sync_tx(&mut self, tx: SyncTx) {
        self.sync_tx = Some(tx);
    }

    /// Emit a sync command (no-op when offline / unwired).
    #[tracing::instrument(skip(self, cmd))]
    fn sync(&self, cmd: SyncCommand) {
        if let Some(tx) = &self.sync_tx {
            debug!(?cmd, "sync command sent");
            let _ = tx.send(cmd);
        } else {
            error!(?cmd, "no sync_tx; command dropped");
        }
    }

    pub fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    // ── lists ─────────────────────────────────────────────────────────────────

    /// Create a new owned list: mint a DEK (epoch 1) sealed to ourselves, write
    /// the list + self-membership rows, and seed a titled document.
    #[tracing::instrument(skip(self))]
    pub async fn create_list(&mut self, name: &str) -> TodoersResult<ListId> {
        let list_id = ListId::generate(&mut OsRng);
        let epoch = 1;
        let dek = Dek::generate(&mut OsRng);

        // The list row must exist before rows that FK-reference it (key_slots,
        // list_members, documents).
        self.db
            .upsert_list(&list_id, Role::Owner, epoch, name)
            .await?;

        // Our own wrapped DEK (the only key slot the client persists locally).
        let wrapped_dek = crypto::seal_to(&dek, &self.session.identity_pub());
        self.db.save_key_slot(&list_id, epoch, &wrapped_dek).await?;
        self.session.insert_dek(list_id, epoch, dek);

        // Create the list server-side under our client-minted id (local-first:
        // the row already exists locally even if this upload is deferred).
        self.sync(SyncCommand::CreateList {
            list_id,
            wrapped_dek,
        });

        self.db
            .add_member_row(
                &list_id,
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
        self.persist(&list_id, doc, &vv).await?;
        Ok(list_id)
    }

    #[tracing::instrument(skip(self))]
    pub async fn rename_list(&mut self, list_id: &ListId, name: &str) -> TodoersResult<()> {
        self.db.rename_list(list_id, name).await?;
        self.edit_doc(list_id, |d| d.set_title(name)).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_list(&mut self, list_id: &ListId) -> TodoersResult<()> {
        self.db.delete_list(list_id).await?;
        self.docs.remove(list_id);
        self.sync(SyncCommand::DeleteList(*list_id));
        Ok(())
    }

    /// Sidebar list summaries with aggregates (open count, nearest due, top
    /// priority) computed from the read model.
    #[tracing::instrument(skip(self))]
    pub async fn list_summaries(&self) -> TodoersResult<Vec<ListSummary>> {
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
                    name: l.name.unwrap_or_default(),
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
        list_id: &ListId,
        input: &TodoItemInput,
    ) -> TodoersResult<String> {
        self.edit_doc(list_id, |d| d.add_item(input)).await
    }

    #[tracing::instrument(skip(self, input))]
    pub async fn edit_todo(
        &mut self,
        list_id: &ListId,
        item_id: &str,
        input: &TodoItemInput,
    ) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.update_item(item_id, input))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn toggle_done(&mut self, list_id: &ListId, item_id: &str) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.toggle_done(item_id)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_priority(
        &mut self,
        list_id: &ListId,
        item_id: &str,
        priority: Priority,
    ) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.set_priority(item_id, priority))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn set_due(
        &mut self,
        list_id: &ListId,
        item_id: &str,
        due: Option<OffsetDateTime>,
    ) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.set_due(item_id, due)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn move_todo(
        &mut self,
        list_id: &ListId,
        from: usize,
        to: usize,
    ) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.move_item(from, to)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn delete_todo(&mut self, list_id: &ListId, item_id: &str) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.remove_item(item_id)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn add_tag(
        &mut self,
        list_id: &ListId,
        item_id: &str,
        tag: &str,
    ) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.add_tag(item_id, tag)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn remove_tag(
        &mut self,
        list_id: &ListId,
        item_id: &str,
        tag: &str,
    ) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.remove_tag(item_id, tag)).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn add_subtask(
        &mut self,
        list_id: &ListId,
        item_id: &str,
        title: &str,
    ) -> TodoersResult<String> {
        self.edit_doc(list_id, |d| d.add_subtask(item_id, title))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn toggle_subtask(
        &mut self,
        list_id: &ListId,
        item_id: &str,
        subtask_id: &str,
    ) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.toggle_subtask(item_id, subtask_id))
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn remove_subtask(
        &mut self,
        list_id: &ListId,
        item_id: &str,
        subtask_id: &str,
    ) -> TodoersResult<()> {
        self.edit_doc(list_id, |d| d.remove_subtask(item_id, subtask_id))
            .await
    }

    // ── view-model refresh ─────────────────────────────────────────────────────

    /// Compute a [`ViewSnapshot`](crate::store_worker::ViewSnapshot) for the given
    /// pane targets + sort. Returns plain `Send` data the off-loop store-worker
    /// hands back to the UI task to install into its `SharedView`.
    pub async fn snapshot_for(
        &self,
        targets: &[Option<ViewTarget>],
        sort: SortMode,
    ) -> TodoersResult<ViewSnapshot> {
        let mut lists = self.list_summaries().await?;
        sort_summaries(&mut lists, sort);
        let mut panes = Vec::with_capacity(targets.len());
        for t in targets {
            panes.push(match t {
                Some(target) => self.load_view(target, sort).await?,
                None => Vec::new(),
            });
        }
        Ok(ViewSnapshot { lists, panes })
    }

    // ── reads ─────────────────────────────────────────────────────────────────

    /// Items for a view (a single list or a meta-list), sorted per `sort`.
    /// Meta-lists aggregate open items across all lists by due window.
    #[tracing::instrument(skip(self))]
    pub async fn load_view(
        &self,
        target: &ViewTarget,
        sort: SortMode,
    ) -> TodoersResult<Vec<(ListId, TodoItem)>> {
        let mut items: Vec<(ListId, TodoItem)> = match target {
            ViewTarget::List(id) => self
                .db
                .load_todo_items(id)
                .await?
                .into_iter()
                .map(|it| (*id, it))
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
        list_id: &ListId,
        item_id: &str,
    ) -> TodoersResult<Option<TodoItem>> {
        self.ensure_doc(list_id).await?;
        let doc = self.docs.get(list_id).expect("ensured");
        Ok(doc.items().into_iter().find(|i| i.id == item_id))
    }

    #[tracing::instrument(skip(self))]
    pub async fn members(&self, list_id: &ListId) -> TodoersResult<Vec<Member>> {
        let mems = self.db.list_members(list_id).await?;
        Ok(mems)
    }

    // ── membership ─────────────────────────────────────────────────────────────

    /// Add a collaborator: record their membership, seal the *current* DEK to
    /// their identity_pub, and hand the seated request to the sync engine. No
    /// rotation — new members only ever see updates from now on.
    #[tracing::instrument(skip(self))]
    pub async fn add_member_local(
        &mut self,
        list_id: &ListId,
        member: Member,
    ) -> TodoersResult<()> {
        let epoch = self
            .db
            .list_epoch(list_id)
            .await?
            .ok_or(TodoersError::UnknownList)?;
        let dek = self
            .session
            .dek(*list_id, epoch)
            .ok_or(TodoersError::NoDek)?;
        let wrapped = crypto::seal_to(&dek, &member.identity_pub);

        self.db.add_member_row(list_id, &member).await?;
        self.sync(SyncCommand::AddMember {
            list_id: *list_id,
            body: Box::new(todoers_types::AddMemberRequest {
                list_id: *list_id,
                member_id: member.id,
                role: member.role,
                wrapped_dek: wrapped,
                epoch: epoch as i64,
            }),
        });
        Ok(())
    }

    /// Remove a collaborator and **rotate**: a fresh DEK under a bumped epoch,
    /// sealed individually to every *remaining* member (a sealed box opens only
    /// for its recipient), then hand the request to the sync engine. Future
    /// updates write under the new epoch.
    #[tracing::instrument(skip(self))]
    pub async fn remove_member_local(
        &mut self,
        list_id: &ListId,
        member_id: MemberId,
    ) -> TodoersResult<()> {
        let current = self
            .db
            .list_epoch(list_id)
            .await?
            .ok_or(TodoersError::UnknownList)?;
        let new_epoch = current + 1;
        let new_dek = Dek::generate(&mut OsRng);

        // The members who remain after this removal each need the new DEK sealed
        // to their own key. (We include ourselves; we are not the one removed.)
        let remaining: Vec<Member> = self
            .db
            .list_members(list_id)
            .await?
            .into_iter()
            .filter(|m| m.id != member_id)
            .collect();
        let new_slots: Vec<todoers_types::KeySlotEntry> = remaining
            .iter()
            .map(|m| todoers_types::KeySlotEntry {
                member_id: m.id,
                wrapped_dek: crypto::seal_to(&new_dek, &m.identity_pub),
            })
            .collect();

        // Persist our own new slot locally + rotate the in-memory DEK map.
        let my_wrapped = crypto::seal_to(&new_dek, &self.session.identity_pub());
        self.db
            .save_key_slot(list_id, new_epoch, &my_wrapped)
            .await?;
        self.session.insert_dek(*list_id, new_epoch, new_dek);
        self.db.set_epoch(list_id, new_epoch).await?;
        self.db.remove_member_row(list_id, &member_id).await?;

        self.sync(SyncCommand::RemoveMember {
            list_id: *list_id,
            body: Box::new(todoers_types::RemoveMemberRequest {
                list_id: *list_id,
                remove_member_id: member_id,
                epoch: current as i64,
                new_slots,
            }),
        });
        Ok(())
    }

    // ── inbound sync (server → local) ──────────────────────────────────────────

    /// Verify + decrypt one pulled/streamed update and merge it into the doc.
    /// Returns whether local state changed (so the worker knows to re-snapshot).
    /// Bad input from the untrusted relay is logged and skipped, never fatal.
    #[tracing::instrument(skip(self, dto))]
    pub async fn apply_remote_update(
        &mut self,
        list_id: &ListId,
        dto: StoredUpdateDto,
    ) -> TodoersResult<bool> {
        let epoch = dto.epoch as Epoch;
        let author = dto.author;

        // Our own appends come back on the WS/pull too — already merged, skip.
        if author == self.session.member_id() {
            self.db.set_applied_through_seq(list_id, dto.seq).await?;
            return Ok(false);
        }

        let Some(dek) = self.session.dek(*list_id, epoch) else {
            tracing::warn!(?list_id, epoch, "no DEK for update epoch; skipping");
            return Ok(false);
        };
        let Some(author_pub) = self
            .db
            .list_members(list_id)
            .await?
            .into_iter()
            .find(|m| m.id == author)
            .map(|m| m.signing_pub)
        else {
            tracing::warn!(?author, "unknown update author; skipping");
            return Ok(false);
        };

        let payload = todoers_types::UpdatePayload {
            version: UPDATE_VERSION,
            list_id: *list_id,
            epoch,
            author,
            nonce: dto.nonce,
            ciphertext: dto.ciphertext,
            signature: dto.signature,
        };

        let loro = match crypto::verify_and_decrypt(&payload, list_id, &author_pub, &dek) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = ?e, "update failed verify/decrypt; skipping");
                return Ok(false);
            }
        };

        self.ensure_doc(list_id).await?;
        let doc = self.docs.get(list_id).expect("ensured");
        doc.import(&loro)?;
        self.rebuild_read_model(list_id).await?;
        self.db.set_applied_through_seq(list_id, dto.seq).await?;
        Ok(true)
    }

    /// Seed a list discovered from the server: its membership directory, our
    /// cached wrapped DEKs, and metadata. Rehydrates the in-memory DEK map so
    /// subsequent `apply_remote_update`s can decrypt.
    #[tracing::instrument(skip(self, meta, keys))]
    pub async fn ingest_remote_list(
        &mut self,
        meta: MetadataResponse,
        keys: Vec<KeySlotDto>,
    ) -> TodoersResult<()> {
        let list_id = meta.list_id;
        let me = self.session.member_id();
        let my_role = meta
            .members
            .iter()
            .find(|m| m.member_id == me)
            .map(|m| m.role)
            .unwrap_or(Role::Member);

        self.db
            .upsert_list_meta(&list_id, my_role, meta.current_epoch as Epoch)
            .await?;

        for m in &meta.members {
            self.db
                .add_member_row(
                    &list_id,
                    &Member {
                        id: m.member_id,
                        identity_pub: m.identity_pub.clone(),
                        signing_pub: m.signing_pub.clone(),
                        role: m.role,
                    },
                )
                .await?;
        }
        for slot in &keys {
            self.db
                .save_key_slot(&list_id, slot.epoch, &slot.wrapped_dek)
                .await?;
        }
        // Load the (possibly new) wrapped DEKs into the in-memory map.
        self.session.rehydrate(&self.db).await?;
        Ok(())
    }

    /// Re-derive the SQLite read model + persist the snapshot from the live doc.
    /// The write half of `persist` without producing/enqueuing a new update —
    /// used after merging a *remote* change (which we must not re-sign/-upload).
    async fn rebuild_read_model(&self, list_id: &ListId) -> TodoersResult<()> {
        let doc = self.docs.get(list_id).ok_or(TodoersError::DocNotOpen)?;
        let snap = doc.export_snapshot()?;
        self.db.save_document(list_id, &snap).await?;
        self.db.replace_todo_items(list_id, &doc.items()).await?;
        Ok(())
    }

    // ── internals ──────────────────────────────────────────────────────────────

    /// Load a list's document into the cache if not already open.
    async fn ensure_doc(&mut self, list_id: &ListId) -> TodoersResult<()> {
        if self.docs.contains_key(list_id) {
            return Ok(());
        }
        let doc = match self.db.load_document(list_id).await? {
            Some(snap) => TodoDoc::from_snapshot(&snap)?,
            None => TodoDoc::new(),
        };
        self.docs.insert(*list_id, doc);
        Ok(())
    }

    /// Run a closure that mutates the document, then run the persist pipeline.
    #[tracing::instrument(skip(self, f))]
    async fn edit_doc<R, E>(
        &mut self,
        list_id: &ListId,
        f: impl FnOnce(&TodoDoc) -> Result<R, E>,
    ) -> TodoersResult<R>
    where
        E: std::error::Error + Send + Sync + 'static,
        TodoersError: From<E>,
    {
        self.ensure_doc(list_id).await?;
        let doc = self.docs.get(list_id).expect("ensured");
        let vv = doc.version();
        let out = f(doc)?;
        self.persist(list_id, doc, &vv).await?;
        Ok(out)
    }

    /// Encrypt+sign the delta since `vv_before`, enqueue it, then persist the
    /// snapshot and rebuild the read model.
    #[tracing::instrument(skip(self, doc, vv_before))]
    async fn persist(
        &self,
        list_id: &ListId,
        doc: &TodoDoc,
        vv_before: &VersionVector,
    ) -> TodoersResult<()> {
        let epoch = self
            .db
            .list_epoch(list_id)
            .await?
            .ok_or(TodoersError::UnknownList)?;
        let dek = self
            .session
            .dek(*list_id, epoch)
            .ok_or(TodoersError::NoDek)?;

        let update = doc.export_updates_from(vv_before)?;
        if !update.is_empty() {
            let payload = crypto::produce_update(
                UPDATE_VERSION,
                list_id,
                epoch,
                &self.session.member_id(),
                &dek,
                &self.session.signing_key(),
                &update,
            )?;
            let bytes = postcard::to_stdvec(&payload)?;
            self.db
                .enqueue_outbound(list_id, epoch, &bytes, &payload.signature)
                .await?;
            // Nudge the sync engine to drain the queue for this list.
            self.sync(SyncCommand::Push(*list_id));
        }

        let snap = doc.export_snapshot()?;
        self.db.save_document(list_id, &snap).await?;
        self.db.replace_todo_items(list_id, &doc.items()).await?;
        Ok(())
    }
}

/// Whether an item belongs in a meta-list view as of `now`.
fn in_meta(meta: &MetaList, it: &TodoItem, now: OffsetDateTime) -> bool {
    meta.contains(it.due, now)
}

/// Sort sidebar list summaries by the active mode, using per-list aggregates for
/// due/priority (nearest due first; highest top-priority first).
fn sort_summaries(lists: &mut [ListSummary], sort: SortMode) {
    match sort {
        SortMode::Alphabetical => lists.sort_by_key(|a| a.name.to_lowercase()),
        SortMode::DueDate => lists.sort_by(|a, b| match (a.next_due, b.next_due) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        }),
        SortMode::Priority => lists.sort_by_key(|a| std::cmp::Reverse(a.top_priority.rank())),
    }
}

/// Sort items in place. Done-ness is not a sort key here (callers filter first
/// where they want to); `next()`-cycle order matches [`SortMode`].
fn sort_items(items: &mut [(ListId, TodoItem)], sort: SortMode) {
    match sort {
        SortMode::Alphabetical => items.sort_by_key(|(_, a)| a.title.to_lowercase()),
        SortMode::DueDate => items.sort_by(|(_, a), (_, b)| match (a.due, b.due) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less, // dated before undated
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }),
        // Highest priority first.
        SortMode::Priority => items.sort_by_key(|(_, a)| std::cmp::Reverse(a.priority.rank())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Pool, Sqlite};
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
        Store::new(Arc::new(db), Session::new(&keys))
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
        assert!(store.db.outbound_count(&id).await.unwrap() >= 1);
        // We are recorded as the sole (owner) member.
        assert_eq!(store.members(&id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../todoers-client/db/migrations")]
    async fn todo_crud_round_trips_through_read_model(db: Pool<Sqlite>) {
        let mut store = store_with(db);
        let list = store.create_list("L").await.unwrap();

        let a = store.add_todo(&list, &input("buy milk")).await.unwrap();
        store.add_todo(&list, &input("walk dog")).await.unwrap();

        let view = store
            .load_view(&ViewTarget::List(list), SortMode::Alphabetical)
            .await
            .unwrap();
        assert_eq!(
            view.iter()
                .map(|(_, i)| i.title.as_str())
                .collect::<Vec<_>>(),
            vec!["buy milk", "walk dog"]
        );

        store.toggle_done(&list, &a).await.unwrap();
        let done = store
            .load_view(&ViewTarget::List(list), SortMode::Alphabetical)
            .await
            .unwrap();
        assert!(done.iter().find(|(_, i)| i.id == a).unwrap().1.done);

        store
            .edit_todo(
                &list,
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
            .load_view(&ViewTarget::List(list), SortMode::Priority)
            .await
            .unwrap();
        assert_eq!(edited[0].1.title, "buy oat milk");
        assert_eq!(edited[0].1.priority, Priority::High);

        store.delete_todo(&list, &a).await.unwrap();
        let after = store
            .load_view(&ViewTarget::List(list), SortMode::Alphabetical)
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
                &a,
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
                &b,
                &TodoItemInput {
                    title: "later".into(),
                    due: Some(next_month),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let today_view = store
            .load_view(&ViewTarget::Meta(MetaList::DueToday), SortMode::DueDate)
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
            .load_view(&ViewTarget::Meta(MetaList::AllTasks), SortMode::DueDate)
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
            store.add_todo(&id, &input("remember me")).await.unwrap();
        }
        // A brand-new store over the same DB still reads the read model.
        let store2 = store_with(db);
        let view = store2
            .load_view(&ViewTarget::List(id), SortMode::Alphabetical)
            .await
            .unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].1.title, "remember me");
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn remove_member_rotates_epoch(db: Pool<Sqlite>) {
        let mut store = store_with(db);
        let list = store.create_list("Shared").await.unwrap();
        assert_eq!(store.db.list_epoch(&list).await.unwrap(), Some(1));

        // Add then remove a fabricated member; epoch should bump and a new DEK
        // for the new epoch must be available for subsequent writes.
        let other = Member {
            id: MemberId::new([42u8; 16]),
            identity_pub: crypto::generate_identity().1,
            signing_pub: crypto::generate_signing().1,
            role: Role::Member,
        };
        store.add_member_local(&list, other.clone()).await.unwrap();
        assert_eq!(store.members(&list).await.unwrap().len(), 2);

        store.remove_member_local(&list, other.id).await.unwrap();
        assert_eq!(store.db.list_epoch(&list).await.unwrap(), Some(2));
        assert_eq!(store.members(&list).await.unwrap().len(), 1);

        // A write after rotation still succeeds (DEK for epoch 2 is present).
        store
            .add_todo(&list, &input("post-rotation"))
            .await
            .unwrap();
    }

    /// A migrated, single-connection in-memory pool for a second "device".
    async fn fresh_pool() -> Pool<Sqlite> {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("db/migrations").run(&pool).await.unwrap();
        pool
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn remote_updates_apply_on_a_second_device(db: Pool<Sqlite>) {
        // Author A produces updates on their device.
        let mut a = store_with(db);
        let list = a.create_list("Shared").await.unwrap();
        a.add_todo(&list, &input("buy milk")).await.unwrap();

        // The exact envelopes the server would relay, in edit order.
        let rows = a.db.take_outbound(&list, 100).await.unwrap();
        assert!(rows.len() >= 2, "expected title + add_todo updates");

        // Capture A's public identity + the list DEK to seed receiver B.
        let a_member = Member {
            id: a.session.member_id(),
            identity_pub: a.session.identity_pub(),
            signing_pub: a.session.signing_pub(),
            role: Role::Owner,
        };
        let epoch = a.db.list_epoch(&list).await.unwrap().unwrap();
        let dek = a.session.dek(list, epoch).unwrap();

        // Receiver B on a separate device/db: a member who holds the DEK and
        // knows A's signing key, but has never seen the list contents.
        let mut b = store_with(fresh_pool().await);
        b.db.upsert_list_meta(&list, Role::Member, epoch)
            .await
            .unwrap();
        b.db.add_member_row(&list, &a_member).await.unwrap();
        b.session_mut().insert_dek(list, epoch, dek);

        // Apply each relayed update in seq order; B should reconstruct the item.
        for (i, row) in rows.iter().enumerate() {
            let payload: todoers_types::UpdatePayload =
                postcard::from_bytes(&row.payload).unwrap();
            let dto = todoers_types::StoredUpdateDto {
                seq: (i + 1) as i64,
                epoch: payload.epoch,
                author: payload.author,
                nonce: payload.nonce,
                ciphertext: payload.ciphertext.clone(),
                signature: payload.signature,
            };
            b.apply_remote_update(&list, dto).await.unwrap();
        }

        let items = b.db.load_todo_items(&list).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "buy milk");
        assert_eq!(
            b.db.applied_through_seq(&list).await.unwrap(),
            rows.len() as i64
        );
    }

    #[sqlx::test(migrations = "db/migrations")]
    async fn remote_update_with_bad_signature_is_skipped(db: Pool<Sqlite>) {
        let mut a = store_with(db);
        let list = a.create_list("Shared").await.unwrap();
        a.add_todo(&list, &input("buy milk")).await.unwrap();
        let rows = a.db.take_outbound(&list, 100).await.unwrap();

        let a_member = Member {
            id: a.session.member_id(),
            identity_pub: a.session.identity_pub(),
            signing_pub: a.session.signing_pub(),
            role: Role::Owner,
        };
        let epoch = a.db.list_epoch(&list).await.unwrap().unwrap();
        let dek = a.session.dek(list, epoch).unwrap();

        let mut b = store_with(fresh_pool().await);
        b.db.upsert_list_meta(&list, Role::Member, epoch)
            .await
            .unwrap();
        b.db.add_member_row(&list, &a_member).await.unwrap();
        b.session_mut().insert_dek(list, epoch, dek);

        // Tamper with the signature: the blind relay can corrupt bytes, and a
        // forged update must be rejected (skipped), never merged or fatal.
        let payload: todoers_types::UpdatePayload =
            postcard::from_bytes(&rows[0].payload).unwrap();
        let mut bad_sig = payload.signature.to_vec();
        bad_sig[0] ^= 0xff;
        let bad_sig = bad_sig.try_into().unwrap();
        let dto = todoers_types::StoredUpdateDto {
            seq: 1,
            epoch: payload.epoch,
            author: payload.author,
            nonce: payload.nonce,
            ciphertext: payload.ciphertext.clone(),
            signature: bad_sig,
        };
        let changed = b.apply_remote_update(&list, dto).await.unwrap();
        assert!(!changed, "tampered update must not change state");
        assert!(b.db.load_todo_items(&list).await.unwrap().is_empty());
    }
}
