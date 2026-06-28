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

/// The single message enum: the only way state changes propagate through the app.
///
/// Each variant's doc describes exactly what `App::dispatch_action` does when it is
/// dispatched — what state it mutates, what it forwards to components, and what
/// off-loop work it spawns. After the per-variant handling, *every* action is also
/// forwarded to either the open modal or the active mode component (never both), and
/// to the error bar (and the FPS counter under the `fps` feature).
///
/// **Secrets:** `Register`, `Login`, `Unlock` carry the password and `Keys` carries
/// the unlocked secret keys. They are redacted in `Display` and excluded from the
/// `debug!` in `dispatch_action` — never log them verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Periodic heartbeat (~4 Hz). Clears the app's pending multi-key chord buffer;
    /// forwarded on so the active component drops its own half-typed chord and the
    /// error bar dismisses an expired banner. (The auth gate runs on the
    /// `Event::Tick` that produces this action — see `App::on_event`.)
    Tick,
    /// Request a redraw. Coalesced in `handle_actions`: however many are queued in a
    /// turn collapse into a single `render` call at the end of that turn.
    Render,
    /// Terminal resized to `(w, h)`: resize the backend and redraw immediately.
    Resize(u16, u16),
    /// Set `should_suspend`; the run loop then suspends the TUI (SIGTSTP) and queues
    /// `Resume` + `ClearScreen` for when it foregrounds again.
    Suspend,
    /// Clear `should_suspend` (the loop re-enters the alternate screen).
    Resume,
    /// Set `should_quit`; the loop does a best-effort server logout, aborts the
    /// store/sync background tasks, and exits.
    Quit,
    /// Clear the terminal. Also makes the error bar archive and clear its banner.
    ClearScreen,
    /// Show a transient error banner: forwarded to the error bar, which logs it and
    /// displays it for ~5s.
    Error(String),
    /// Open a message modal with the current mode's keybinding cheatsheet.
    HelpModal,
    /// Open the "Login or Register?" chooser shown when there is no local account.
    /// This is the auth gate (nothing useful sits behind it), so Esc/Cancel quits.
    /// Resets mode to `Home`, rebuilds the footer, and clears capture.
    AuthChooser,
    /// Open the registration form modal. Sets mode to `Register`, rebuilds the
    /// footer, and starts capture on the form's first field.
    RegisterModal,
    /// Open the login form modal. Sets mode to `Login`, rebuilds the footer, and
    /// starts capture on the form's first field.
    LoginModal,
    /// Dismiss the open modal overlay, clear capture, and switch back to `prev_mode`.
    CloseModal,
    /// Emitted by a form body (`Register`/`Login`) when the user presses Enter on
    /// the last field: the enclosing `Modal` intercepts it to move focus from the
    /// fields onto its Submit button. It never reaches `App`.
    FocusButtons,
    /// Emitted by a form modal's Submit button. Forwarded down to the form body,
    /// which validates and (on success) emits `Register`/`Login`.
    SubmitForm,
    /// Switch the active mode (`handle_switch_mode`): record `prev_mode`, rebuild the
    /// footer, re-init the new component, and start capture if it captures input.
    SetMode(Mode),
    /// Set `capturing`: suppress the app's keybinding dispatch for every key except a
    /// global Ctrl/Alt chord, so keystrokes reach the focused text input.
    StartCapture,
    /// Clear `capturing`: resume normal app keybinding dispatch.
    StopCapture,
    /// Open the password-unlock modal — used when a local account exists but no keys
    /// are in memory (e.g. first launch after a reinstall). Sets mode to `Home` and
    /// starts capture; Esc/Cancel returns to the auth chooser.
    UnlockModal,
    /// Attempt a password-less unlock from the on-disk device cache (decrypt with
    /// the configured local AGE/SSH key, then device-login for a fresh token), off
    /// the UI loop. On success emits `Keys` + `SetMode(Home)`; on any failure emits
    /// `Error` and falls back to `UnlockModal`.
    DeviceUnlock,
    /// Unlock using the local account's username + this password (delegates to
    /// `App::login`). Errors if there is no local account. **Carries the password.**
    Unlock {
        password: Zeroizing<String>,
    },
    /// Run the OPAQUE registration off the UI loop; on success saves the account and
    /// emits `StopCapture` + `CloseModal` + `SetMode(Home)`, else `Error`.
    /// **Carries the password.**
    Register {
        username: String,
        password: Zeroizing<String>,
    },
    /// Run the OPAQUE login off the UI loop (`App::login`); on success emits `Keys` +
    /// `StopCapture` + `CloseModal` + `SetMode(Home)`, else `Error`.
    /// **Carries the password.**
    Login {
        username: String,
        password: Zeroizing<String>,
    },
    /// Install the unlocked secret keys into `acct_keys`. **Carries class-3 key
    /// material** — the next tick's auth gate stands up the data layer from it.
    Keys(Zeroizing<UnlockedKeys>),
    /// Forwarded to `Home`, which toggles sidebar visibility (and moves focus to the
    /// pane when the sidebar is hidden).
    ToggleSidebar,
    /// Point pane `pane` at `target` in the view-model, then ask the worker to
    /// recompute that pane and snapshot it back (`send_set_view`).
    OpenView {
        target: ViewTarget,
        pane: usize,
    },
    /// Re-send the current view spec to the worker so it re-snapshots every pane.
    /// Emitted after a pane-count change (split/close) so new panes get filled.
    RefreshLists,

    // ── list/todo CRUD (Phase 4) ────────────────────────────────────────────
    /// Open the "new list" form modal.
    NewListModal,
    /// Send `CreateList` to the worker, then close the modal.
    CreateList {
        name: String,
    },
    /// Open the rename form for an existing list, pre-filled with its name.
    RenameListModal {
        list_id: ListId,
        name: String,
    },
    /// Send `RenameList` to the worker, then close the modal.
    RenameList {
        list_id: ListId,
        name: String,
    },
    /// Open the "add todo" form modal for a list.
    AddTodoModal(ListId),
    /// Ask the worker to fetch the full item (with subtasks); the edit modal opens
    /// later when the reply arrives as `OpenEditReady`.
    EditTodoModal {
        list_id: ListId,
        item_id: String,
    },
    /// Send `AddTodo` (`item_id` None) or `EditTodo` (`item_id` Some) to the worker,
    /// then close the modal.
    SaveTodo {
        list_id: ListId,
        item_id: Option<String>,
        input: TodoItemInput,
    },
    /// Send `ToggleDone` to the worker — toggles an item's done state in place, no
    /// modal involved.
    ToggleDone {
        list_id: ListId,
        item_id: String,
    },
    /// Open a confirm dialog before a destructive delete; its Delete button emits
    /// `DeleteList`/`DeleteTodo`, Cancel/Esc closes.
    ConfirmDelete(DeleteTarget),
    /// Send `DeleteList` to the worker, locally repoint any pane showing that list to
    /// `AllTasks`, re-snapshot, and close the modal.
    DeleteList(ListId),
    /// Send `DeleteTodo` to the worker, then close the modal.
    DeleteTodo {
        list_id: ListId,
        item_id: String,
    },

    // ── sharing / membership (Phase 5) ──────────────────────────────────────
    /// Open the "share list" form (add a member by username).
    ShareModal(ListId),
    /// Resolve a username to keys off the UI loop; on success emits
    /// `AddResolvedMember`, else `Error`.
    ShareList {
        list_id: ListId,
        username: String,
    },
    /// Send `AddMember` to the worker (seals the current DEK to the new member), then
    /// close the modal. Emitted by the pubkey-lookup task.
    AddResolvedMember {
        list_id: ListId,
        member: Member,
    },
    /// Ask the worker to fetch the member list; the members modal opens later when
    /// the reply arrives as `OpenMembersReady`.
    MembersModal(ListId),
    /// Send `RemoveMember` to the worker (rotates the list's DEK/epoch), then close
    /// the modal.
    Unshare {
        list_id: ListId,
        member_id: MemberId,
    },

    /// Advance the active sort mode in the view-model, then re-snapshot every pane.
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
