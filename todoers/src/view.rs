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
use std::rc::Rc;

use ratatui::layout::Direction;

use todoers_client::model::{ListSummary, MetaList, SortMode, TodoItem, ViewTarget};
use todoers_types::ListId;

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
