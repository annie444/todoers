//! The per-list CRDT document: a thin, typed wrapper over [`loro::LoroDoc`].
//!
//! Document shape:
//! ```text
//! root
//! ├── meta   : Map            { "title": String }
//! └── items  : MovableList     [ item, item, … ]   (order is the list order)
//!          └── item : Map      { id, title, notes, due?, priority, done,
//!                                tags: List<String>,
//!                                subtasks: MovableList<Map{ id, title, done }> }
//! ```
//!
//! Each item carries its own `id` (a UUID string) rather than relying on Loro's
//! internal container id, so the id survives the `get_deep_value()` projection
//! and stays stable across merges.
//!
//! **Reads** project the whole doc via `get_deep_value()` → JSON → structs.
//! **Writes** navigate Loro handles so every edit is a proper CRDT op (concurrent
//! edits to different items/subtasks merge instead of clobbering).

use std::borrow::Cow;

use anyhow::{Context, Result};
use loro::{
    ExportMode, LoroDoc, LoroList, LoroMap, LoroMovableList, ValueOrContainer, VersionVector,
};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::{Priority, Subtask, TodoItem, TodoItemInput};

const META: &str = "meta";
const ITEMS: &str = "items";
const TITLE: &str = "title";
const TAGS: &str = "tags";
const SUBTASKS: &str = "subtasks";

/// A list's materialized CRDT document.
pub struct TodoDoc {
    doc: LoroDoc,
}

impl Default for TodoDoc {
    fn default() -> Self {
        Self::new()
    }
}

impl TodoDoc {
    /// A fresh, empty document with a random peer id.
    pub fn new() -> Self {
        Self { doc: LoroDoc::new() }
    }

    /// Rehydrate from a snapshot produced by [`TodoDoc::export_snapshot`].
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        let doc = LoroDoc::new();
        doc.import(bytes).context("import loro snapshot")?;
        Ok(Self { doc })
    }

    /// Full snapshot (state + history) for local persistence / server compaction.
    pub fn export_snapshot(&self) -> Result<Vec<u8>> {
        self.doc.commit();
        self.doc
            .export(ExportMode::Snapshot)
            .context("export loro snapshot")
    }

    /// Incremental update bytes for everything after `from` — the unit that gets
    /// encrypted+signed and appended to the server log.
    pub fn export_updates_from(&self, from: &VersionVector) -> Result<Vec<u8>> {
        self.doc.commit();
        self.doc
            .export(ExportMode::Updates {
                from: Cow::Borrowed(from),
            })
            .context("export loro updates")
    }

    /// All updates from the beginning (convenience for first sync / tests).
    pub fn export_all_updates(&self) -> Result<Vec<u8>> {
        self.export_updates_from(&VersionVector::default())
    }

    /// Merge a peer's snapshot or update bytes into this doc (order-independent).
    pub fn import(&self, bytes: &[u8]) -> Result<()> {
        self.doc.import(bytes).context("import loro update")?;
        Ok(())
    }

    /// Current version vector — the baseline to pass to a later
    /// [`TodoDoc::export_updates_from`].
    pub fn version(&self) -> VersionVector {
        self.doc.oplog_vv()
    }

    // ── list metadata ────────────────────────────────────────────────────────

    pub fn title(&self) -> String {
        map_str(&self.doc.get_map(META), TITLE).unwrap_or_default()
    }

    pub fn set_title(&self, title: &str) -> Result<()> {
        self.doc.get_map(META).insert(TITLE, title)?;
        self.doc.commit();
        Ok(())
    }

    // ── items ────────────────────────────────────────────────────────────────

    fn items_list(&self) -> LoroMovableList {
        self.doc.get_movable_list(ITEMS)
    }

    /// Append a new item; returns its generated id.
    pub fn add_item(&self, input: &TodoItemInput) -> Result<String> {
        let items = self.items_list();
        let id = Uuid::new_v4().to_string();
        let map = items.insert_container(items.len(), LoroMap::new())?;
        map.insert("id", id.as_str())?;
        map.insert("title", input.title.as_str())?;
        map.insert("notes", input.notes.as_str())?;
        map.insert("priority", input.priority.rank())?;
        map.insert("done", false)?;
        if let Some(due) = input.due {
            map.insert("due", due.unix_timestamp())?;
        }
        let tags = map.get_or_create_container(TAGS, LoroList::new())?;
        for t in &input.tags {
            tags.push(t.as_str())?;
        }
        self.doc.commit();
        Ok(id)
    }

    /// Overwrite the editable scalar fields + tags of an existing item.
    pub fn update_item(&self, id: &str, input: &TodoItemInput) -> Result<()> {
        let map = self.item_map(id).context("update_item: unknown id")?;
        map.insert("title", input.title.as_str())?;
        map.insert("notes", input.notes.as_str())?;
        map.insert("priority", input.priority.rank())?;
        match input.due {
            Some(due) => map.insert("due", due.unix_timestamp())?,
            None => {
                let _ = map.delete("due");
            }
        }
        let tags = map.get_or_create_container(TAGS, LoroList::new())?;
        if tags.len() > 0 {
            tags.delete(0, tags.len())?;
        }
        for t in &input.tags {
            tags.push(t.as_str())?;
        }
        self.doc.commit();
        Ok(())
    }

    pub fn toggle_done(&self, id: &str) -> Result<()> {
        let map = self.item_map(id).context("toggle_done: unknown id")?;
        let now = map
            .get("done")
            .and_then(|v| v.into_value().ok())
            .and_then(|v| v.into_bool().ok())
            .unwrap_or(false);
        map.insert("done", !now)?;
        self.doc.commit();
        Ok(())
    }

    pub fn set_priority(&self, id: &str, priority: Priority) -> Result<()> {
        let map = self.item_map(id).context("set_priority: unknown id")?;
        map.insert("priority", priority.rank())?;
        self.doc.commit();
        Ok(())
    }

    pub fn set_due(&self, id: &str, due: Option<OffsetDateTime>) -> Result<()> {
        let map = self.item_map(id).context("set_due: unknown id")?;
        match due {
            Some(d) => map.insert("due", d.unix_timestamp())?,
            None => {
                let _ = map.delete("due");
            }
        }
        self.doc.commit();
        Ok(())
    }

    /// Move the item at `from` to index `to` (MovableList reorder).
    pub fn move_item(&self, from: usize, to: usize) -> Result<()> {
        self.items_list().mov(from, to)?;
        self.doc.commit();
        Ok(())
    }

    pub fn remove_item(&self, id: &str) -> Result<()> {
        let idx = self.item_index(id).context("remove_item: unknown id")?;
        self.items_list().delete(idx, 1)?;
        self.doc.commit();
        Ok(())
    }

    // ── tags ─────────────────────────────────────────────────────────────────

    pub fn add_tag(&self, id: &str, tag: &str) -> Result<()> {
        let map = self.item_map(id).context("add_tag: unknown id")?;
        let tags = map.get_or_create_container(TAGS, LoroList::new())?;
        tags.push(tag)?;
        self.doc.commit();
        Ok(())
    }

    pub fn remove_tag(&self, id: &str, tag: &str) -> Result<()> {
        let map = self.item_map(id).context("remove_tag: unknown id")?;
        let tags = map.get_or_create_container(TAGS, LoroList::new())?;
        for i in 0..tags.len() {
            let matches = tags
                .get(i)
                .and_then(|v| v.into_value().ok())
                .and_then(|v| v.into_string().ok())
                .is_some_and(|s| *s == *tag);
            if matches {
                tags.delete(i, 1)?;
                break;
            }
        }
        self.doc.commit();
        Ok(())
    }

    // ── subtasks ──────────────────────────────────────────────────────────────

    pub fn add_subtask(&self, item_id: &str, title: &str) -> Result<String> {
        let map = self.item_map(item_id).context("add_subtask: unknown id")?;
        let subs = map.get_or_create_container(SUBTASKS, LoroMovableList::new())?;
        let sid = Uuid::new_v4().to_string();
        let sub = subs.insert_container(subs.len(), LoroMap::new())?;
        sub.insert("id", sid.as_str())?;
        sub.insert("title", title)?;
        sub.insert("done", false)?;
        self.doc.commit();
        Ok(sid)
    }

    pub fn toggle_subtask(&self, item_id: &str, subtask_id: &str) -> Result<()> {
        let map = self.item_map(item_id).context("toggle_subtask: unknown item")?;
        let subs = map.get_or_create_container(SUBTASKS, LoroMovableList::new())?;
        for i in 0..subs.len() {
            let Some(sub) = movable_map_at(&subs, i) else {
                continue;
            };
            if map_str(&sub, "id").as_deref() == Some(subtask_id) {
                let now = sub
                    .get("done")
                    .and_then(|v| v.into_value().ok())
                    .and_then(|v| v.into_bool().ok())
                    .unwrap_or(false);
                sub.insert("done", !now)?;
                break;
            }
        }
        self.doc.commit();
        Ok(())
    }

    pub fn remove_subtask(&self, item_id: &str, subtask_id: &str) -> Result<()> {
        let map = self.item_map(item_id).context("remove_subtask: unknown item")?;
        let subs = map.get_or_create_container(SUBTASKS, LoroMovableList::new())?;
        for i in 0..subs.len() {
            let matches = movable_map_at(&subs, i)
                .and_then(|m| map_str(&m, "id"))
                .as_deref()
                == Some(subtask_id);
            if matches {
                subs.delete(i, 1)?;
                break;
            }
        }
        self.doc.commit();
        Ok(())
    }

    // ── projection ────────────────────────────────────────────────────────────

    /// Project the document into plain [`TodoItem`]s in list order. This is what
    /// rebuilds the SQLite read model and feeds the UI.
    pub fn items(&self) -> Vec<TodoItem> {
        let json = serde_json::to_value(self.items_list().get_deep_value())
            .unwrap_or(serde_json::Value::Null);
        let raw: Vec<RawItem> = serde_json::from_value(json).unwrap_or_default();
        raw.into_iter()
            .enumerate()
            .map(|(i, r)| r.into_item(i))
            .collect()
    }

    // ── handle navigation helpers ──────────────────────────────────────────────

    fn item_index(&self, id: &str) -> Option<usize> {
        let items = self.items_list();
        (0..items.len()).find(|&i| {
            movable_map_at(&items, i)
                .and_then(|m| map_str(&m, "id"))
                .as_deref()
                == Some(id)
        })
    }

    fn item_map(&self, id: &str) -> Option<LoroMap> {
        let items = self.items_list();
        let idx = self.item_index(id)?;
        movable_map_at(&items, idx)
    }
}

/// Get the `LoroMap` container at `idx` of a movable list, if it is one.
fn movable_map_at(list: &LoroMovableList, idx: usize) -> Option<LoroMap> {
    list.get(idx)?.into_container().ok()?.into_map().ok()
}

/// Read a string-valued key off a map.
fn map_str(map: &LoroMap, key: &str) -> Option<String> {
    match map.get(key)? {
        ValueOrContainer::Value(v) => v.into_string().ok().map(|s| (*s).clone()),
        ValueOrContainer::Container(_) => None,
    }
}

// ── JSON projection structs ───────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct RawItem {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    due: Option<i64>,
    #[serde(default)]
    priority: i64,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    subtasks: Vec<RawSub>,
}

#[derive(Deserialize, Default)]
struct RawSub {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    done: bool,
}

impl RawItem {
    fn into_item(self, position: usize) -> TodoItem {
        TodoItem {
            id: self.id,
            title: self.title,
            notes: self.notes,
            due: self
                .due
                .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok()),
            priority: Priority::from_rank(self.priority),
            done: self.done,
            tags: self.tags,
            subtasks: self
                .subtasks
                .into_iter()
                .map(|s| Subtask {
                    id: s.id,
                    title: s.title,
                    done: s.done,
                })
                .collect(),
            // Read-model sort key; the authoritative order is the MovableList.
            order_key: format!("{position:08}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn input(title: &str) -> TodoItemInput {
        TodoItemInput {
            title: title.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_doc_has_no_items_and_blank_title() {
        let doc = TodoDoc::new();
        assert_eq!(doc.title(), "");
        assert!(doc.items().is_empty());
    }

    #[test]
    fn add_and_read_back_full_item() {
        let doc = TodoDoc::new();
        doc.set_title("Groceries").unwrap();
        let id = doc
            .add_item(&TodoItemInput {
                title: "Milk".into(),
                notes: "2%".into(),
                due: Some(datetime!(2026-06-20 09:00:00 UTC)),
                priority: Priority::High,
                tags: vec!["dairy".into(), "fridge".into()],
            })
            .unwrap();

        assert_eq!(doc.title(), "Groceries");
        let items = doc.items();
        assert_eq!(items.len(), 1);
        let it = &items[0];
        assert_eq!(it.id, id);
        assert_eq!(it.title, "Milk");
        assert_eq!(it.notes, "2%");
        assert_eq!(it.priority, Priority::High);
        assert!(!it.done);
        assert_eq!(it.due, Some(datetime!(2026-06-20 09:00:00 UTC)));
        assert_eq!(it.tags, vec!["dairy", "fridge"]);
    }

    #[test]
    fn toggle_priority_due_and_update() {
        let doc = TodoDoc::new();
        let id = doc.add_item(&input("Task")).unwrap();

        doc.toggle_done(&id).unwrap();
        assert!(doc.items()[0].done);
        doc.toggle_done(&id).unwrap();
        assert!(!doc.items()[0].done);

        doc.set_priority(&id, Priority::Med).unwrap();
        assert_eq!(doc.items()[0].priority, Priority::Med);

        doc.set_due(&id, Some(datetime!(2026-07-01 00:00:00 UTC)))
            .unwrap();
        assert_eq!(doc.items()[0].due, Some(datetime!(2026-07-01 00:00:00 UTC)));
        doc.set_due(&id, None).unwrap();
        assert_eq!(doc.items()[0].due, None);

        doc.update_item(
            &id,
            &TodoItemInput {
                title: "Renamed".into(),
                notes: "new notes".into(),
                priority: Priority::Low,
                tags: vec!["x".into()],
                due: None,
            },
        )
        .unwrap();
        let it = &doc.items()[0];
        assert_eq!(it.title, "Renamed");
        assert_eq!(it.notes, "new notes");
        assert_eq!(it.priority, Priority::Low);
        assert_eq!(it.tags, vec!["x"]);
    }

    #[test]
    fn tags_add_and_remove() {
        let doc = TodoDoc::new();
        let id = doc.add_item(&input("t")).unwrap();
        doc.add_tag(&id, "a").unwrap();
        doc.add_tag(&id, "b").unwrap();
        assert_eq!(doc.items()[0].tags, vec!["a", "b"]);
        doc.remove_tag(&id, "a").unwrap();
        assert_eq!(doc.items()[0].tags, vec!["b"]);
    }

    #[test]
    fn subtasks_add_toggle_remove() {
        let doc = TodoDoc::new();
        let id = doc.add_item(&input("parent")).unwrap();
        let s1 = doc.add_subtask(&id, "step 1").unwrap();
        let _s2 = doc.add_subtask(&id, "step 2").unwrap();

        let subs = &doc.items()[0].subtasks;
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].title, "step 1");
        assert!(!subs[0].done);

        doc.toggle_subtask(&id, &s1).unwrap();
        assert!(doc.items()[0].subtasks[0].done);

        doc.remove_subtask(&id, &s1).unwrap();
        let subs = &doc.items()[0].subtasks;
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].title, "step 2");
    }

    #[test]
    fn move_and_remove_reorder() {
        let doc = TodoDoc::new();
        let a = doc.add_item(&input("a")).unwrap();
        let _b = doc.add_item(&input("b")).unwrap();
        let _c = doc.add_item(&input("c")).unwrap();

        // a,b,c -> move a to end -> b,c,a
        doc.move_item(0, 2).unwrap();
        let titles: Vec<_> = doc.items().into_iter().map(|i| i.title).collect();
        assert_eq!(titles, vec!["b", "c", "a"]);

        doc.remove_item(&a).unwrap();
        let titles: Vec<_> = doc.items().into_iter().map(|i| i.title).collect();
        assert_eq!(titles, vec!["b", "c"]);
    }

    #[test]
    fn snapshot_round_trips() {
        let doc = TodoDoc::new();
        doc.set_title("L").unwrap();
        doc.add_item(&input("one")).unwrap();
        doc.add_item(&input("two")).unwrap();

        let snap = doc.export_snapshot().unwrap();
        let restored = TodoDoc::from_snapshot(&snap).unwrap();
        assert_eq!(restored.title(), "L");
        let titles: Vec<_> = restored.items().into_iter().map(|i| i.title).collect();
        assert_eq!(titles, vec!["one", "two"]);
    }

    #[test]
    fn concurrent_updates_merge() {
        // Two replicas of the same list start from a shared base, edit
        // independently, then exchange updates — both converge with both items.
        let base = TodoDoc::new();
        base.set_title("shared").unwrap();
        let snap = base.export_snapshot().unwrap();

        let alice = TodoDoc::from_snapshot(&snap).unwrap();
        let bob = TodoDoc::from_snapshot(&snap).unwrap();

        let a_vv = alice.version();
        let b_vv = bob.version();
        alice.add_item(&input("from-alice")).unwrap();
        bob.add_item(&input("from-bob")).unwrap();

        let a_delta = alice.export_updates_from(&a_vv).unwrap();
        let b_delta = bob.export_updates_from(&b_vv).unwrap();
        alice.import(&b_delta).unwrap();
        bob.import(&a_delta).unwrap();

        let mut a_titles: Vec<_> = alice.items().into_iter().map(|i| i.title).collect();
        let mut b_titles: Vec<_> = bob.items().into_iter().map(|i| i.title).collect();
        a_titles.sort();
        b_titles.sort();
        assert_eq!(a_titles, vec!["from-alice", "from-bob"]);
        assert_eq!(a_titles, b_titles, "replicas converge");
    }
}
