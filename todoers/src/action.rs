use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use todoers_client::auth::UnlockedKeys;
use todoers_client::model::{TodoItemInput, ViewTarget};
use todoers_types::{ListId, Member, MemberId};

use crate::app::Mode;

/// What a [`Action::ConfirmDelete`] is about to delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeleteTarget {
    List(ListId),
    Todo { list_id: ListId, item_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Tick,
    Render,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    ClearScreen,
    Error(String),
    HelpModal,
    /// Open the "Login or Register?" chooser shown when there is no local account.
    AuthChooser,
    RegisterModal,
    LoginModal,
    /// Dismiss the currently open modal overlay (see `App::modal`).
    CloseModal,
    /// Emitted by a form body (`Register`/`Login`) when the user presses Enter on
    /// the last field: the enclosing `Modal` intercepts it to move focus from the
    /// fields onto its Submit button. It never reaches `App`.
    FocusButtons,
    /// Emitted by a form modal's Submit button. Forwarded down to the form body,
    /// which validates and (on success) emits `Register`/`Login`.
    SubmitForm,
    SetMode(Mode),
    StartCapture,
    StopCapture,
    /// Submit a completed registration form. The password is class-3 material:
    /// never log this variant verbatim (see `Display` below and `App::handle_actions`).
    UnlockModal,
    /// Attempt a password-less unlock from the on-disk device cache (decrypt with
    /// the configured local AGE/SSH key, then device-login for a fresh token).
    /// Falls back to `UnlockModal` on any failure.
    DeviceUnlock,
    Unlock {
        password: Zeroizing<String>,
    },
    Register {
        username: String,
        password: Zeroizing<String>,
    },
    Login {
        username: String,
        password: Zeroizing<String>,
    },
    Keys(Zeroizing<UnlockedKeys>),
    ToggleSidebar,
    /// Open a list or meta-list in pane `pane` (loads its items into the view).
    OpenView {
        target: ViewTarget,
        pane: usize,
    },
    /// Reload the sidebar list summaries (and the current view) from the store.
    RefreshLists,

    // ── list/todo CRUD (Phase 4) ────────────────────────────────────────────
    /// Open the "new list" form modal.
    NewListModal,
    /// Create a list with the given name (emitted by the list form).
    CreateList {
        name: String,
    },
    /// Open the rename form for an existing list, pre-filled with its name.
    RenameListModal {
        list_id: ListId,
        name: String,
    },
    /// Rename a list (emitted by the list form in rename mode).
    RenameList {
        list_id: ListId,
        name: String,
    },
    /// Open the "add todo" form for a list.
    AddTodoModal(ListId),
    /// Open the "edit todo" form for an item (App loads the full item first).
    EditTodoModal {
        list_id: ListId,
        item_id: String,
    },
    /// Create (`item_id` None) or update (`item_id` Some) a todo from the form.
    SaveTodo {
        list_id: ListId,
        item_id: Option<String>,
        input: TodoItemInput,
    },
    /// Toggle an item's done state in place.
    ToggleDone {
        list_id: ListId,
        item_id: String,
    },
    /// Open a confirm dialog before a destructive delete.
    ConfirmDelete(DeleteTarget),
    /// Delete a whole list (after confirmation).
    DeleteList(ListId),
    /// Delete a single todo (after confirmation).
    DeleteTodo {
        list_id: ListId,
        item_id: String,
    },

    // ── sharing / membership (Phase 5) ──────────────────────────────────────
    /// Open the "share list" form (add a member by username).
    ShareModal(ListId),
    /// Resolve a username to keys and add them to a list (emitted by the form).
    ShareList {
        list_id: ListId,
        username: String,
    },
    /// A resolved collaborator to seal the DEK to (from the pubkey lookup task).
    AddResolvedMember {
        list_id: ListId,
        member: Member,
    },
    /// Open the members list for a list (view + unshare).
    MembersModal(ListId),
    /// Remove a member, rotating the list's DEK/epoch locally.
    Unshare {
        list_id: ListId,
        member_id: MemberId,
    },

    /// Cycle the active sort mode (tasks in the pane + sidebar aggregates).
    CycleSort,

    /// The store-worker returned a full item; open the edit modal from
    /// `pending_edit`. Deferred so the modal opens where `tui` is available.
    OpenEditReady,
    /// The store-worker returned members; open the members modal from
    /// `pending_members`.
    OpenMembersReady,
}

impl std::fmt::Display for Action {
    #[tracing::instrument(name = "Action::fmt", skip(self, f))]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Tick => write!(f, "Tick"),
            Action::Render => write!(f, "Render"),
            Action::Resize(width, height) => write!(f, "Resize to {} x {}", width, height),
            Action::Suspend => write!(f, "Suspend"),
            Action::Resume => write!(f, "Resume"),
            Action::Quit => write!(f, "Quit"),
            Action::ClearScreen => write!(f, "Clear screen"),
            Action::Error(msg) => write!(f, "Error {}", msg),
            Action::HelpModal => write!(f, "Help"),
            Action::AuthChooser => write!(f, "Auth chooser"),
            Action::RegisterModal => write!(f, "Register"),
            Action::LoginModal => write!(f, "Login"),
            Action::CloseModal => write!(f, "Close modal"),
            Action::FocusButtons => write!(f, "Focus buttons"),
            Action::SubmitForm => write!(f, "Submit form"),
            Action::SetMode(mode) => write!(f, "Go {}", mode),
            Action::StartCapture => write!(f, "Start key capture"),
            Action::StopCapture => write!(f, "Stop key capture"),
            Action::UnlockModal => write!(f, "Unlock todoers"),
            Action::DeviceUnlock => write!(f, "Device unlock"),
            Action::Unlock { .. } => write!(f, "Unlock keys"),
            Action::ToggleSidebar => write!(f, "Toggle sidebar"),
            Action::Register { username, .. } => write!(f, "Register {}", username),
            Action::Login { username, .. } => write!(f, "Login {}", username),
            Action::Keys(_) => write!(f, "Cryptographic keys"),
            Action::OpenView { target, pane } => write!(f, "Open view {target:?} in pane {pane}"),
            Action::RefreshLists => write!(f, "Refresh lists"),
            Action::NewListModal => write!(f, "New list"),
            Action::CreateList { name } => write!(f, "Create list {name}"),
            Action::RenameListModal { name, .. } => write!(f, "Rename list {name}"),
            Action::RenameList { name, .. } => write!(f, "Rename list {name}"),
            Action::AddTodoModal(_) => write!(f, "Add todo"),
            Action::EditTodoModal { item_id, .. } => write!(f, "Edit todo {item_id}"),
            Action::SaveTodo { input, .. } => write!(f, "Save todo {}", input.title),
            Action::ToggleDone { item_id, .. } => write!(f, "Toggle done {item_id}"),
            Action::ConfirmDelete(target) => write!(f, "Confirm delete {target:?}"),
            Action::DeleteList(_) => write!(f, "Delete list"),
            Action::DeleteTodo { item_id, .. } => write!(f, "Delete todo {item_id}"),
            Action::ShareModal(_) => write!(f, "Share list"),
            Action::ShareList { username, .. } => write!(f, "Share with {username}"),
            Action::AddResolvedMember { .. } => write!(f, "Add resolved member"),
            Action::MembersModal(_) => write!(f, "List members"),
            Action::Unshare { .. } => write!(f, "Unshare"),
            Action::CycleSort => write!(f, "Cycle sort"),
            Action::OpenEditReady => write!(f, "Open edit (ready)"),
            Action::OpenMembersReady => write!(f, "Open members (ready)"),
        }
    }
}
