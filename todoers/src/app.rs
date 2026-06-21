use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crossterm::event::{KeyEvent, KeyModifiers};
use nohash_hasher::BuildNoHashHasher;
use ratatui::prelude::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::Paragraph;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::action::{Action, DeleteTarget};
use crate::auth::{AccountRow, UnlockedKeys};
#[cfg(debug_assertions)]
use crate::components::FpsCounter;
use crate::components::{
    Button, Captures, Component, EditorMode, ErrorBar, Help, Home, Keys, ListForm, Login, Members,
    Modal, Prompt, Register, ShareForm, TodoForm, Unlock,
};
use crate::config::Config;
use crate::db::Db;
use crate::model::{MetaList, ViewTarget};
use crate::session::Session;
use crate::store::{SharedView, Store, ViewModel};
use crate::store_worker::{CommandTx, StoreCommand, WorkerMsg, WorkerRx, run_store_worker};
use crate::tui::{Event, Tui};

pub struct App {
    config: Config,
    db: Db,
    account: Option<Zeroizing<AccountRow>>,
    modes: HashMap<Mode, Box<dyn Component>, BuildNoHashHasher<u8>>,
    should_quit: bool,
    should_suspend: bool,
    /// True while a text input is capturing keystrokes. While set, the app
    /// suppresses its own keybinding dispatch for every key except a hard-quit
    /// allowlist (see [`is_global_chord`]) so typed characters reach the input
    /// instead of triggering actions.
    capturing: bool,
    prev_mode: Mode,
    mode: Mode,
    /// When set, a modal overlay is drawn on top of the active mode and captures
    /// input. Mode-agnostic: not part of the `modes` map (see `components::Modal`).
    modal: Option<Modal>,
    last_tick_key_events: Vec<KeyEvent>,
    action_tx: mpsc::UnboundedSender<Action>,
    action_rx: mpsc::UnboundedReceiver<Action>,
    keys: Keys,
    errorbar: ErrorBar,
    acct_keys: Option<Zeroizing<UnlockedKeys>>,
    account_verified: bool,
    /// Ensures the password-less device-unlock path is attempted at most once per
    /// run (otherwise every tick would re-spawn the unlock task).
    device_unlock_attempted: bool,
    /// Channel to the off-loop store-worker task, built once keys are unlocked.
    /// The worker owns the [`Store`] (and thus the secret keys + Loro docs); the
    /// UI sends [`StoreCommand`]s and never touches db/crypto/Loro inline.
    cmd_tx: Option<CommandTx>,
    /// Replies from the worker (chiefly [`ViewSnapshot`](crate::store_worker::ViewSnapshot)s).
    worker_rx: Option<WorkerRx>,
    /// Stashed while waiting on the worker so the modal can be opened on the next
    /// `dispatch_action` pass (which has `tui`). See [`Self::handle_worker_msg`].
    pending_edit: Option<(todoers_types::ListId, crate::model::TodoItem)>,
    pending_members: Option<(
        todoers_types::ListId,
        Vec<todoers_types::Member>,
        todoers_types::MemberId,
    )>,
    /// Render-side snapshot shared with the workspace component.
    view: SharedView,
    #[cfg(debug_assertions)]
    fps: FpsCounter,
}

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Home,
    Register,
    Login,
}

impl std::fmt::Display for Mode {
    #[tracing::instrument(name = "Mode::fmt", skip(self, f))]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Home => write!(f, "Home"),
            Mode::Register => write!(f, "Register"),
            Mode::Login => write!(f, "Login"),
        }
    }
}

impl Captures for Mode {
    #[tracing::instrument(skip(self))]
    fn captures_input(&self) -> bool {
        match self {
            Self::Home => false,
            Self::Register => true,
            Mode::Login => true,
        }
    }
}

/// The hard-quit allowlist: keys that reach app-level keybinding dispatch even
/// while a modal is open or a text field is capturing. Defined as *any chord
/// holding Ctrl or Alt* — a user can't type those into a field, so they are
/// always safe to treat as commands. This naturally covers the configured
/// `Ctrl-C`/`Ctrl-D` (quit), `Ctrl-Z` (suspend) and `Ctrl-L`/`Ctrl-R` (form
/// switch), while leaving bare keys (`?`, letters, `Esc`, `Tab`, `Enter`) for
/// the focused form/modal to consume.
#[tracing::instrument]
fn is_global_chord(key: &KeyEvent) -> bool {
    key.modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

/// Drain everything currently queued on an mpsc receiver without awaiting. Used
/// by `handle_actions` to process the whole backlog in one loop turn (and coalesce
/// renders), rather than one action per turn.
fn drain<T>(rx: &mut mpsc::UnboundedReceiver<T>) -> Vec<T> {
    let mut out = Vec::new();
    while let Ok(v) = rx.try_recv() {
        out.push(v);
    }
    out
}

/// Receive from the worker channel when one exists. Before login (`None`) this
/// future never resolves, so the `select!` falls through to terminal events.
async fn recv_opt(rx: &mut Option<WorkerRx>) -> Option<WorkerMsg> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// Convert a `users/{username}/pubkeys` response into a [`Member`] to seal a list
/// DEK to. Rejects keys of the wrong length rather than panicking.
fn resolved_member(dto: todoers_types::UserPubkeysDto) -> anyhow::Result<todoers_types::Member> {
    use todoers_types::{Ed25519Pub, Member, MemberId, Role, X25519Pub};
    let identity_pub: [u8; 32] = dto
        .identity_pub
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad identity key length"))?;
    let signing_pub: [u8; 32] = dto
        .signing_pub
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad signing key length"))?;
    Ok(Member {
        id: MemberId(*dto.member_id.as_bytes()),
        identity_pub: X25519Pub(identity_pub),
        signing_pub: Ed25519Pub(signing_pub),
        role: Role::Member,
    })
}

impl App {
    #[tracing::instrument(skip(config, db))]
    pub async fn new(
        config: Config,
        db: Db,
        account: Option<Zeroizing<AccountRow>>,
        acct_keys: Option<Zeroizing<UnlockedKeys>>,
    ) -> anyhow::Result<Self> {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let view: SharedView = Rc::new(RefCell::new(ViewModel::default()));
        let mut modes: HashMap<Mode, Box<dyn Component>, BuildNoHashHasher<u8>> =
            HashMap::with_capacity_and_hasher(1, BuildNoHashHasher::default());
        modes.insert(Mode::Home, Box::new(Home::new(view.clone())));
        Ok(Self {
            modes,
            mode: Mode::default(),
            prev_mode: Mode::default(),
            should_quit: false,
            should_suspend: false,
            capturing: false,
            modal: None,
            config,
            db,
            last_tick_key_events: Vec::new(),
            action_tx,
            action_rx,
            keys: Keys::new(Mode::default()),
            acct_keys,
            account,
            errorbar: ErrorBar::new(),
            account_verified: false,
            device_unlock_attempted: false,
            cmd_tx: None,
            worker_rx: None,
            pending_edit: None,
            pending_members: None,
            view,
            #[cfg(debug_assertions)]
            fps: FpsCounter::new(),
        })
    }

    /// Build the data layer once keys are unlocked: a [`Session`] (with its DEK
    /// map rehydrated from the cached key slots) wrapped in a [`Store`], then
    /// load the sidebar + initial view. Idempotent — no-op if already built or
    /// if keys aren't available yet.
    #[tracing::instrument(skip(self))]
    async fn init_session(&mut self) -> anyhow::Result<()> {
        if self.cmd_tx.is_some() {
            return Ok(());
        }
        let Some(keys) = self.acct_keys.as_ref() else {
            return Ok(());
        };
        let mut session = Session::new(keys);
        session.rehydrate(&self.db).await?;
        let store = Store::new(self.db.clone(), session);

        // The store owns `Send` state (keys + Loro docs), so it can run on its
        // own task; the UI talks to it only over channels and never blocks.
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        tokio::spawn(run_store_worker(store, cmd_rx, out_tx));
        self.cmd_tx = Some(cmd_tx);
        self.worker_rx = Some(out_rx);

        // Prime the worker with the initial pane targets + sort from the view-model.
        self.send_set_view();
        Ok(())
    }

    /// Tell the worker which targets/sort to render. Call after any layout/sort
    /// change so it recomputes and snapshots back.
    fn send_set_view(&self) {
        if let Some(tx) = &self.cmd_tx {
            let v = self.view.borrow();
            let targets = v.panes.iter().map(|p| p.target).collect();
            let _ = tx.send(StoreCommand::SetView {
                targets,
                sort: v.sort,
            });
        }
    }

    /// Send a command to the worker (no-op before login).
    fn store_cmd(&self, cmd: StoreCommand) {
        if let Some(tx) = &self.cmd_tx {
            let _ = tx.send(cmd);
        }
    }

    /// The current member id ("me"), derived from the account/keys since the
    /// worker now owns the session.
    fn session_member_id(&self) -> todoers_types::MemberId {
        self.account
            .as_ref()
            .map(|a| a.member_id)
            .or_else(|| self.acct_keys.as_ref().map(|k| k.member_id))
            .unwrap_or_default()
    }

    #[tracing::instrument(skip(self))]
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut tui = Tui::new()?.mouse(true).paste(true);
        tui.enter()?;
        let component = if let Some(comp) = self.modes.get_mut(&self.mode) {
            comp
        } else if let Some(comp) = self.modes.get_mut(&self.prev_mode) {
            comp
        } else {
            self.modes.get_mut(&Mode::default()).unwrap()
        };

        component.register_action_handler(self.action_tx.clone())?;
        component.register_config_handler(self.config.clone())?;
        component.init(tui.size()?)?;
        // Populate the keybinding footer for the starting mode (a bare
        // `Keys::new` in `App::new` has no config and renders empty).
        self.refresh_keys()?;

        let action_tx = self.action_tx.clone();
        loop {
            // Drive the UI from two sources at once: terminal events and replies
            // from the store-worker. Neither blocks the other, so a long store
            // mutation can't freeze input/render.
            tokio::select! {
                Some(event) = tui.next_event() => {
                    self.on_event(event).await?;
                }
                Some(msg) = recv_opt(&mut self.worker_rx) => {
                    self.handle_worker_msg(msg)?;
                }
            }
            self.handle_actions(&mut tui)?;
            if self.should_suspend {
                tui.suspend()?;
                action_tx.send(Action::Resume)?;
                action_tx.send(Action::ClearScreen)?;
                tui.enter()?;
            } else if self.should_quit {
                tui.stop()?;
                break;
            }
        }
        tui.exit()?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn on_event(&mut self, event: Event) -> anyhow::Result<()> {
        let action_tx = self.action_tx.clone();
        match event {
            Event::Quit => action_tx.send(Action::Quit)?,
            Event::Tick => {
                // No local account → prompt the user to log in or register,
                // unless a modal (the chooser or a form) is already up. Keep
                // ticking regardless so capture/multi-key state stays fresh.
                if !self.account_verified && self.modal.is_none() {
                    if self.account.is_none()
                        && self.acct_keys.is_none()
                        && self.load_account().await?
                    {
                        action_tx.send(Action::AuthChooser)?;
                    } else if self.account.is_some() && self.acct_keys.is_none() {
                        // We have a local account but no in-memory keys (fresh
                        // launch). If this device is set up for password-less
                        // unlock, try the device cache first (once); otherwise — or
                        // if that fails — fall back to the password prompt.
                        if self.config.config.device_unlock.enabled && !self.device_unlock_attempted
                        {
                            self.device_unlock_attempted = true;
                            action_tx.send(Action::DeviceUnlock)?;
                        } else if !self.device_unlock_attempted {
                            action_tx.send(Action::UnlockModal)?;
                        }
                    } else if self.account.is_some() && self.acct_keys.is_some() {
                        // Keys are in memory — stand up the data layer and load
                        // the workspace before marking the account verified.
                        self.init_session().await?;
                        self.account_verified = true;
                    }
                }
                action_tx.send(Action::Tick)?;
            }
            Event::Render => action_tx.send(Action::Render)?,
            Event::Resize(x, y) => action_tx.send(Action::Resize(x, y))?,
            // While a modal is open it owns the keyboard, so skip the app's
            // per-mode keybinding dispatch (the modal handles Esc/Tab/Enter) —
            // except for global chords (Ctrl/Alt), which always dispatch so the
            // user can quit/suspend/switch forms from inside an overlay.
            Event::Key(key) if self.modal.is_none() || is_global_chord(&key) => {
                self.handle_key_event(key)?
            }
            _ => {}
        }
        // Route input to the modal when one is open; otherwise to the active
        // mode component. This keeps the background mode from reacting to keys
        // or clicks meant for the overlay.
        if let Some(modal) = self.modal.as_mut() {
            if let Some(action) = modal.handle_events(Some(event.clone()))? {
                action_tx.send(action)?;
            }
        } else {
            let component = if let Some(comp) = self.modes.get_mut(&self.mode) {
                comp
            } else if let Some(comp) = self.modes.get_mut(&self.prev_mode) {
                comp
            } else {
                self.modes.get_mut(&Mode::default()).unwrap()
            };
            if let Some(action) = component.handle_events(Some(event.clone()))? {
                action_tx.send(action)?;
            }
        }
        Ok(())
    }

    /// Ensure the local account is cached. Returns `true` when there is no local
    /// account on disk — the caller should then prompt the user to log in or
    /// register (see [`Action::AuthChooser`]).
    #[tracing::instrument(skip(self))]
    async fn load_account(&mut self) -> anyhow::Result<bool> {
        if self.account.is_some() {
            return Ok(false);
        }
        if let Some(account) = self.db.load_account().await? {
            self.account = Some(account);
            Ok(false)
        } else {
            Ok(true)
        }
    }

    #[tracing::instrument(skip(self))]
    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<()> {
        // While a text field is capturing, only global chords (Ctrl/Alt) act as
        // commands; every other key falls through to the focused input so it can
        // be typed instead of triggering a keybinding.
        if self.capturing && !is_global_chord(&key) {
            return Ok(());
        }
        let action_tx = self.action_tx.clone();
        let Some(keymap) = self.config.keybindings.0.get(&self.mode) else {
            warn!(
                "No keybindings found for mode {}, skipping key event handling",
                self.mode
            );
            return Ok(());
        };
        match keymap.get(&vec![key]) {
            Some(action) => {
                info!("Got action: {action:?}");
                action_tx.send(action.clone().into())?;
            }
            _ => {
                // If the key was not handled as a single key action,
                // then consider it for multi-key combinations.
                self.last_tick_key_events.push(key);

                // Check for multi-key combinations
                if let Some(action) = keymap.get(&self.last_tick_key_events) {
                    info!("Got action: {action:?}");
                    action_tx.send(action.clone().into())?;
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, tui))]
    fn handle_actions(&mut self, tui: &mut Tui) -> anyhow::Result<()> {
        let mut should_render = false;
        for action in drain(&mut self.action_rx) {
            // Coalesce renders: note the request and draw once after draining the
            // whole backlog, so a burst of actions costs at most one frame.
            if matches!(action, Action::Render) {
                should_render = true;
                continue;
            }
            self.dispatch_action(action, tui)?;
        }
        if should_render {
            self.render(tui)?;
        }
        Ok(())
    }

    /// Install a worker reply. Snapshots refresh the view-model and request a
    /// render; request/reply messages stash data and emit a "ready" action so
    /// `dispatch_action` (which has `tui`) can open the modal next pass.
    fn handle_worker_msg(&mut self, msg: WorkerMsg) -> anyhow::Result<()> {
        match msg {
            WorkerMsg::Snapshot(snap) => {
                let mut v = self.view.borrow_mut();
                v.lists = snap.lists;
                // Install items per pane by index; keep UI layout (split/ratio)
                // intact. `zip` truncates, so a stale snapshot can only
                // under-fill, never panic.
                for (pane, items) in v.panes.iter_mut().zip(snap.panes) {
                    pane.items = items;
                }
                drop(v);
                self.action_tx.send(Action::Render)?;
            }
            WorkerMsg::FullItem(boxed) => {
                if let Some((list_id, item)) = *boxed {
                    self.pending_edit = Some((list_id, item));
                    self.action_tx.send(Action::OpenEditReady)?;
                }
            }
            WorkerMsg::Members(boxed) => {
                let (list_id, members) = *boxed;
                let me = self.session_member_id();
                self.pending_members = Some((list_id, members, me));
                self.action_tx.send(Action::OpenMembersReady)?;
            }
            WorkerMsg::Error(e) => {
                self.errorbar.show_error(e, Duration::from_secs(5));
            }
        }
        Ok(())
    }

    fn dispatch_action(&mut self, action: Action, tui: &mut Tui) -> anyhow::Result<()> {
        // Never debug-print `Register` verbatim: it carries the password.
        if !matches!(
            action,
            Action::Tick
                | Action::Render
                | Action::Register { .. }
                | Action::Login { .. }
                | Action::Keys(_)
        ) {
            debug!("{action:?}");
        }
        match action {
            Action::Tick => {
                self.last_tick_key_events.drain(..);
            }
            Action::ToggleSidebar => {}
            Action::Quit => self.should_quit = true,
            Action::Suspend => self.should_suspend = true,
            Action::Resume => self.should_suspend = false,
            Action::ClearScreen => tui.terminal.clear()?,
            Action::Resize(w, h) => self.handle_resize(tui, w, h)?,
            // Coalesced in `handle_actions`; unreachable here but kept so
            // the match stays exhaustive over `Action`.
            Action::Render => {}
            Action::SetMode(mode) => self.handle_switch_mode(mode, tui)?,
            Action::StartCapture => self.capturing = true,
            Action::StopCapture => self.capturing = false,
            // Submit rides the message bus down into the open form modal's
            // body (forwarded below); no app-level state changes here.
            Action::SubmitForm => {}
            // Normally consumed by the `Modal` to shift focus onto its
            // buttons; if it reaches the app it's a harmless no-op.
            Action::FocusButtons => {}
            Action::Keys(ref keys) => {
                info!("Received cryptographic keys");
                self.acct_keys = Some(keys.to_owned());
            }
            Action::UnlockModal => {
                // The user has a local account but no keys (e.g. first launch
                // after a reinstall). Prompt for the password to unlock the
                // escrowed keys from the server.
                let mut modal = Modal::form("Unlock", Box::new(Unlock::new()), Action::AuthChooser);
                modal.register_action_handler(self.action_tx.clone())?;
                modal.register_config_handler(self.config.clone())?;
                modal.init(tui.size()?)?;
                self.prev_mode = self.mode;
                self.mode = Mode::Home;
                self.refresh_keys()?;
                self.modal = Some(modal);
                // Focus the password field (capturing on, Vim Normal mode),
                // matching the login/register modals.
                self.action_tx.send(Action::StartCapture)?;
            }
            Action::DeviceUnlock => {
                // Password-less unlock: decrypt the on-disk cache with the
                // configured local AGE/SSH key, then device-login for a
                // fresh token. On any failure, fall back to the password
                // prompt. Runs off the UI loop; result returns as actions.
                let tx = self.action_tx.clone();
                let db = self.db.clone();
                let base_url = self.config.config.server_url.clone();
                let du = self.config.config.device_unlock.clone();
                tokio::spawn(async move {
                    let attempt = async {
                        let (device_id, blob) = db
                            .load_device_cache()
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("no device cache on this device"))?;
                        let identity = du.identity.clone().ok_or_else(|| {
                            anyhow::anyhow!("no device-unlock identity configured")
                        })?;
                        crate::net::unlock_via_device(&base_url, &identity, device_id, blob).await
                    }
                    .await;
                    match attempt {
                        Ok(keys) => {
                            let _ = tx.send(Action::Keys(keys));
                            let _ = tx.send(Action::SetMode(Mode::Home));
                        }
                        Err(e) => {
                            error!(?e, "device unlock failed; prompting for password");
                            let _ = tx.send(Action::Error(format!("Device unlock failed: {e:#}")));
                            let _ = tx.send(Action::UnlockModal);
                        }
                    }
                });
            }
            Action::Register {
                ref username,
                ref password,
            } => {
                // Drive the networked OPAQUE registration off the UI loop;
                // results come back as actions (Error, or StopCapture+SetMode).
                let tx = self.action_tx.clone();
                let db = self.db.clone();
                let base_url = self.config.config.server_url.clone();
                let username = username.clone();
                let password = password.clone();
                tokio::spawn(async move {
                    match crate::net::register(&base_url, &username, &password).await {
                        Ok(account) => match db.save_account(&account).await {
                            Ok(()) => {
                                let _ = tx.send(Action::StopCapture);
                                let _ = tx.send(Action::CloseModal);
                                let _ = tx.send(Action::SetMode(Mode::Home));
                            }
                            Err(e) => {
                                let _ =
                                    tx.send(Action::Error(format!("Could not save account: {e}")));
                            }
                        },
                        Err(e) => {
                            let _ = tx.send(Action::Error(format!("Registration failed: {e}")));
                        }
                    }
                });
            }
            Action::Login {
                ref username,
                ref password,
            } => {
                self.login(username.clone(), password.clone());
            }
            Action::Unlock { ref password } => {
                if let Some(account) = self.account.clone() {
                    self.login(account.username.clone(), password.clone());
                } else {
                    error!("Attempted to unlock without a local account");
                    self.errorbar.show_error(
                        "No local account found; please register or log in.".to_string(),
                        Duration::from_secs(5),
                    );
                }
            }
            Action::Error(ref err) => {
                error!("Error action received: {err}");
                self.errorbar
                    .show_error(err.clone(), Duration::from_secs(5));
            }
            Action::HelpModal => {
                // Build a help overlay for the *current* mode's bindings.
                // The modal itself stays mode-agnostic; we hand the body
                // the active mode so its cheatsheet is relevant.
                let mut modal = Modal::message("Help", Box::new(Help::new(self.mode)));
                modal.register_action_handler(self.action_tx.clone())?;
                modal.register_config_handler(self.config.clone())?;
                modal.init(tui.size()?)?;
                self.modal = Some(modal);
            }
            Action::AuthChooser => {
                // Shown when there is no local account: choose Login or
                // Register. This is the auth gate — nothing useful sits
                // behind it — so Esc/Cancel quits the app.
                let mut modal = Modal::new(
                    "Welcome",
                    Box::new(Prompt::new(
                        "You're not signed in. Log in to an existing account, \
                                 or register a new one.",
                    )),
                    vec![
                        Button::new("Login", Action::LoginModal),
                        Button::new("Register", Action::RegisterModal),
                    ],
                    Action::Quit,
                );
                modal.register_action_handler(self.action_tx.clone())?;
                modal.register_config_handler(self.config.clone())?;
                modal.init(tui.size()?)?;
                self.prev_mode = self.mode;
                self.mode = Mode::Home;
                self.refresh_keys()?;
                self.capturing = false;
                self.modal = Some(modal);
            }
            Action::RegisterModal => {
                // The registration form lives in a modal overlay with
                // Submit/Cancel buttons; Cancel (and Esc) returns to the
                // auth chooser. Track the matching mode so per-mode
                // keybindings (e.g. Ctrl-L to switch to login) resolve, then
                // StartCapture to focus the form's first field.
                let mut modal =
                    Modal::form("Register", Box::new(Register::new()), Action::AuthChooser);
                modal.register_action_handler(self.action_tx.clone())?;
                modal.register_config_handler(self.config.clone())?;
                modal.init(tui.size()?)?;
                self.mode = Mode::Register;
                self.refresh_keys()?;
                self.modal = Some(modal);
                self.action_tx.send(Action::StartCapture)?;
            }
            Action::LoginModal => {
                // The login form lives in a modal overlay with Submit/Cancel
                // buttons; Cancel (and Esc) returns to the auth chooser.
                // Track the matching mode so per-mode keybindings (e.g.
                // Ctrl-R to switch to register) resolve, then StartCapture
                // to focus the form's first field.
                let mut modal = Modal::form("Login", Box::new(Login::new()), Action::AuthChooser);
                modal.register_action_handler(self.action_tx.clone())?;
                modal.register_config_handler(self.config.clone())?;
                modal.init(tui.size()?)?;
                self.mode = Mode::Login;
                self.refresh_keys()?;
                self.modal = Some(modal);
                self.action_tx.send(Action::StartCapture)?;
            }
            Action::CloseModal => {
                self.modal = None;
                self.capturing = false;
                self.handle_switch_mode(self.prev_mode, tui)?;
            }
            Action::OpenView { target, pane } => {
                if let Some(p) = self.view.borrow_mut().panes.get_mut(pane) {
                    p.target = Some(target);
                }
                // Worker recomputes that pane and snapshots back.
                self.send_set_view();
            }
            Action::RefreshLists => self.send_set_view(),
            Action::NewListModal => {
                self.open_form_modal("New List", Box::new(ListForm::create()), tui)?;
            }
            Action::RenameListModal { list_id, ref name } => {
                self.open_form_modal(
                    "Rename List",
                    Box::new(ListForm::rename(list_id, name)),
                    tui,
                )?;
            }
            Action::AddTodoModal(list_id) => {
                self.open_form_modal("Add Todo", Box::new(TodoForm::add(list_id)), tui)?;
            }
            Action::EditTodoModal {
                list_id,
                ref item_id,
            } => {
                // The worker fetches the full item (with subtasks); the modal
                // opens when `WorkerMsg::FullItem` arrives → `Action::OpenEditReady`.
                self.store_cmd(StoreCommand::FetchFullItem {
                    list_id,
                    item_id: item_id.clone(),
                });
            }
            Action::CreateList { ref name } => {
                self.store_cmd(StoreCommand::CreateList { name: name.clone() });
                self.action_tx.send(Action::CloseModal)?;
            }
            Action::RenameList { list_id, ref name } => {
                self.store_cmd(StoreCommand::RenameList {
                    list_id,
                    name: name.clone(),
                });
                self.action_tx.send(Action::CloseModal)?;
            }
            Action::SaveTodo {
                list_id,
                ref item_id,
                ref input,
            } => {
                match item_id {
                    Some(id) => self.store_cmd(StoreCommand::EditTodo {
                        list_id,
                        item_id: id.clone(),
                        input: input.clone(),
                    }),
                    None => self.store_cmd(StoreCommand::AddTodo {
                        list_id,
                        input: input.clone(),
                    }),
                }
                self.action_tx.send(Action::CloseModal)?;
            }
            Action::ToggleDone {
                list_id,
                ref item_id,
            } => {
                self.store_cmd(StoreCommand::ToggleDone {
                    list_id,
                    item_id: item_id.clone(),
                });
            }
            Action::ConfirmDelete(ref target) => {
                let (msg, del) = match target.clone() {
                    DeleteTarget::List(id) => (
                        "Delete this list and all of its todos? This cannot be undone.".to_string(),
                        Action::DeleteList(id),
                    ),
                    DeleteTarget::Todo { list_id, item_id } => (
                        "Delete this todo?".to_string(),
                        Action::DeleteTodo { list_id, item_id },
                    ),
                };
                let mut modal = Modal::new(
                    "Confirm Delete",
                    Box::new(Prompt::new(msg)),
                    vec![
                        Button::new("Delete", del),
                        Button::new("Cancel", Action::CloseModal),
                    ],
                    Action::CloseModal,
                );
                modal.register_action_handler(self.action_tx.clone())?;
                modal.register_config_handler(self.config.clone())?;
                modal.init(tui.size()?)?;
                self.modal = Some(modal);
            }
            Action::DeleteList(list_id) => {
                self.store_cmd(StoreCommand::DeleteList(list_id));
                // Mirror the worker's fallback locally so the pane target matches.
                {
                    let deleted = ViewTarget::List(list_id);
                    let fallback = ViewTarget::Meta(MetaList::AllTasks);
                    let mut v = self.view.borrow_mut();
                    for pane in &mut v.panes {
                        if pane.target == Some(deleted) {
                            pane.target = Some(fallback);
                        }
                    }
                }
                self.send_set_view();
                self.action_tx.send(Action::CloseModal)?;
            }
            Action::DeleteTodo {
                list_id,
                ref item_id,
            } => {
                self.store_cmd(StoreCommand::DeleteTodo {
                    list_id,
                    item_id: item_id.clone(),
                });
                self.action_tx.send(Action::CloseModal)?;
            }
            Action::ShareModal(list_id) => {
                self.open_form_modal("Share List", Box::new(ShareForm::new(list_id)), tui)?;
            }
            Action::ShareList {
                list_id,
                ref username,
            } => {
                // Resolving a username to keys is the one networked step;
                // run it off the loop and feed the member back as an action.
                let tx = self.action_tx.clone();
                let base_url = self.config.config.server_url.clone();
                // The worker owns the session now; the bearer token also lives in
                // the unlocked account keys.
                let token = self
                    .acct_keys
                    .as_ref()
                    .map(|k| k.token.clone())
                    .unwrap_or_default();
                let username = username.clone();
                tokio::spawn(async move {
                    match crate::net::lookup_pubkeys(&base_url, &token, &username).await {
                        Ok(dto) => match resolved_member(dto) {
                            Ok(member) => {
                                let _ = tx.send(Action::AddResolvedMember { list_id, member });
                            }
                            Err(e) => {
                                let _ =
                                    tx.send(Action::Error(format!("Invalid keys for user: {e}")));
                            }
                        },
                        Err(e) => {
                            let _ = tx.send(Action::Error(format!("Share failed: {e:#}")));
                        }
                    }
                });
            }
            Action::AddResolvedMember {
                list_id,
                ref member,
            } => {
                self.store_cmd(StoreCommand::AddMember {
                    list_id,
                    member: member.clone(),
                });
                self.action_tx.send(Action::CloseModal)?;
            }
            Action::MembersModal(list_id) => {
                // The worker fetches members; the modal opens on
                // `WorkerMsg::Members` → `Action::OpenMembersReady`.
                self.store_cmd(StoreCommand::FetchMembers(list_id));
            }
            Action::Unshare { list_id, member_id } => {
                self.store_cmd(StoreCommand::RemoveMember { list_id, member_id });
                self.action_tx.send(Action::CloseModal)?;
            }
            Action::CycleSort => {
                {
                    let mut v = self.view.borrow_mut();
                    v.sort = v.sort.next();
                }
                self.send_set_view();
            }
            Action::OpenEditReady => {
                if let Some((list_id, item)) = self.pending_edit.take() {
                    self.open_form_modal(
                        "Edit Todo",
                        Box::new(TodoForm::edit(list_id, &item)),
                        tui,
                    )?;
                }
            }
            Action::OpenMembersReady => {
                if let Some((list_id, members, me)) = self.pending_members.take() {
                    let mut modal =
                        Modal::message("Members", Box::new(Members::new(list_id, members, me)));
                    modal.register_action_handler(self.action_tx.clone())?;
                    modal.register_config_handler(self.config.clone())?;
                    modal.init(tui.size()?)?;
                    self.modal = Some(modal);
                }
            }
        }
        // Forward the action to the modal while it is open, otherwise to
        // the active mode component — never both, so the background mode
        // stays inert behind the overlay.
        if let Some(modal) = self.modal.as_mut() {
            if let Some(action) = modal.update(action.clone())? {
                self.action_tx.send(action)?
            };
        } else {
            let component = if let Some(comp) = self.modes.get_mut(&self.mode) {
                comp
            } else if let Some(comp) = self.modes.get_mut(&self.prev_mode) {
                comp
            } else {
                self.modes.get_mut(&Mode::default()).unwrap()
            };
            if let Some(action) = component.update(action.clone())? {
                #[cfg(debug_assertions)]
                self.action_tx.send(action.clone())?;
                #[cfg(not(debug_assertions))]
                self.action_tx.send(action)?;
            };
        }
        #[cfg(debug_assertions)]
        self.fps.update(action)?;
        Ok(())
    }

    /// Open a capturing form modal whose Cancel/Esc returns to the workspace.
    fn open_form_modal(
        &mut self,
        title: &str,
        body: Box<dyn Component>,
        tui: &mut Tui,
    ) -> anyhow::Result<()> {
        let mut modal = Modal::form(title, body, Action::CloseModal);
        modal.register_action_handler(self.action_tx.clone())?;
        modal.register_config_handler(self.config.clone())?;
        modal.init(tui.size()?)?;
        self.modal = Some(modal);
        self.action_tx.send(Action::StartCapture)?;
        Ok(())
    }

    #[tracing::instrument(skip(self, tui))]
    fn handle_resize(&mut self, tui: &mut Tui, w: u16, h: u16) -> anyhow::Result<()> {
        tui.resize(Rect::new(0, 0, w, h))?;
        self.render(tui)?;
        Ok(())
    }

    /// Rebuild the keybinding footer for `mode`, wiring it to the live config and
    /// action channel. A bare `Keys::new(mode)` has an empty key map and renders
    /// nothing — the footer only populates in `register_config_handler`.
    fn refresh_keys(&mut self) -> anyhow::Result<()> {
        let mut keys = Keys::new(self.mode);
        keys.register_action_handler(self.action_tx.clone())?;
        keys.register_config_handler(self.config.clone())?;
        self.keys = keys;
        Ok(())
    }

    /// The Vim editing sub-mode of the currently focused field, if any — a focused
    /// modal body takes precedence over the background mode component. Drives the
    /// status-footer mode indicator.
    fn active_editor_mode(&self) -> Option<EditorMode> {
        if let Some(modal) = self.modal.as_ref() {
            return modal.editor_mode();
        }
        self.modes
            .get(&self.mode)
            .or_else(|| self.modes.get(&self.prev_mode))
            .or_else(|| self.modes.get(&Mode::default()))
            .and_then(|comp| comp.editor_mode())
    }

    #[tracing::instrument(skip(self, tui))]
    fn handle_switch_mode(&mut self, mode: Mode, tui: &mut Tui) -> anyhow::Result<()> {
        self.prev_mode = self.mode;
        self.mode = mode;
        self.refresh_keys()?;
        let component = if let Some(comp) = self.modes.get_mut(&self.mode) {
            comp
        } else if let Some(comp) = self.modes.get_mut(&self.prev_mode) {
            comp
        } else {
            self.modes.get_mut(&Mode::default()).unwrap()
        };
        component.register_action_handler(self.action_tx.clone())?;
        component.register_config_handler(self.config.clone())?;
        component.init(tui.size()?)?;
        if component.captures_input() {
            self.action_tx.send(Action::StartCapture)?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, tui))]
    fn render(&mut self, tui: &mut Tui) -> anyhow::Result<()> {
        // Resolve the Vim mode indicator before the draw closure borrows `self`.
        let editor_mode = self.active_editor_mode();
        tui.draw(|frame| {
            let [body, errorbar, footer] = Layout::vertical([
                Constraint::Fill(1),
                self.errorbar.placement(),
                self.keys.placement(),
            ])
            .areas(frame.area());
            #[cfg(debug_assertions)]
            {
                use crate::components::FpsCounter;
                let [_, fpsvert] =
                    Layout::vertical([Constraint::Fill(1), Constraint::Length(15)]).areas(body);
                let [_] = Layout::horizontal([Constraint::Fill(1), Constraint::Length(10)])
                    .areas(fpsvert);
            }
            let component = if let Some(comp) = self.modes.get_mut(&self.mode) {
                comp
            } else if let Some(comp) = self.modes.get_mut(&self.prev_mode) {
                comp
            } else {
                self.modes.get_mut(&Mode::default()).unwrap()
            };
            if let Err(err) = component.draw(frame, body) {
                let _ = self
                    .action_tx
                    .send(Action::Error(format!("Failed to draw screen: {:?}", err)));
            }
            // Draw the modal last so it overlays the active mode. The modal
            // centers itself and `Clear`s its region, so the screen behind it
            // remains visible as a backdrop.
            if let Some(modal) = self.modal.as_mut()
                && let Err(err) = modal.draw(frame, body)
            {
                let _ = self
                    .action_tx
                    .send(Action::Error(format!("Failed to draw modal: {:?}", err)));
            }

            if let Err(err) = self.errorbar.draw(frame, errorbar) {
                let _ = self.action_tx.send(Action::Error(format!(
                    "Failed to draw error bar: {:?}",
                    err
                )));
            }

            if let Err(err) = self.keys.draw(frame, footer) {
                let _ = self.action_tx.send(Action::Error(format!(
                    "Failed to draw key bindings: {:?}",
                    err
                )));
            }

            // Lualine-style Vim mode indicator: classic `-- MODE --`, dimmed, on
            // the right of the footer's top rule line. Only shown for Vim fields.
            if let Some(mode) = editor_mode {
                let label = format!("-- {} --", mode.label());
                let w = (label.chars().count() as u16).min(footer.width);
                let rect = Rect::new(footer.right().saturating_sub(w), footer.y, w, 1);
                frame.render_widget(
                    Paragraph::new(label).style(Style::default().fg(Color::DarkGray)),
                    rect,
                );
            }
        })?;
        Ok(())
    }

    pub fn login(&self, username: String, password: Zeroizing<String>) {
        // Drive the networked OPAQUE login off the UI loop; results
        // come back as actions (Error, or Keys+StopCapture+SetMode).
        let tx = self.action_tx.clone();
        let base_url = self.config.config.server_url.clone();
        let db = self.db.clone();
        let du = self.config.config.device_unlock.clone();
        let username = username.clone();
        let password = password.clone();
        tokio::spawn(async move {
            // Online login needs NO local account — it recovers the
            // keys from the server escrow. A local account (if any)
            // is only the offline fallback inside `net::login`.
            let account = match db.load_account().await {
                Ok(a) => a,
                Err(e) => {
                    let _ = tx.send(Action::Error(format!("Database error: {e}")));
                    return;
                }
            };
            let keys =
                match crate::net::login(&base_url, &username, &password, account.as_ref()).await {
                    Ok(keys) => keys,
                    Err(e) => {
                        let _ = tx.send(Action::Error(format!("Login failed: {e}")));
                        return;
                    }
                };
            // First login on this device → persist a local account so
            // future launches recognize us and offline unlock works.
            // Argon2id is CPU-bound, so wrap off the async worker.
            if account.is_none() {
                let uname = username.clone();
                let pw = password.clone();
                let keys_for_acct = Zeroizing::new((*keys).clone());
                let built = tokio::task::spawn_blocking(move || {
                    crate::auth::build_local_account(&uname, &pw, &keys_for_acct)
                })
                .await;
                match built {
                    Ok(Ok(new_acct)) => {
                        if let Err(e) = db.save_account(&new_acct).await {
                            let _ = tx.send(Action::Error(format!(
                                "Logged in, but could not save account: {e}"
                            )));
                        }
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Action::Error(format!(
                            "Logged in, but could not seal local account: {e}"
                        )));
                    }
                    Err(e) => {
                        let _ = tx.send(Action::Error(format!(
                            "Logged in, but account task panicked: {e}"
                        )));
                    }
                }
            }
            // If password-less unlock is enabled and this device isn't enrolled
            // yet, seal the keys to the configured local AGE/SSH key and register a
            // trusted key with the server. Best-effort: a failure here doesn't
            // block the login — the user can still unlock with their password.
            if du.enabled && !keys.token.is_empty() {
                let already_enrolled = matches!(db.load_device_cache().await, Ok(Some(_)));
                if !already_enrolled {
                    match du.recipient.as_deref() {
                        Some(recipient) => match crate::net::enroll_this_device(
                            &base_url,
                            &keys.token,
                            recipient,
                            &keys,
                            &username,
                        )
                        .await
                        {
                            Ok((device_id, blob)) => {
                                if let Err(e) = db.save_device_cache(&device_id, &blob).await {
                                    let _ = tx.send(Action::Error(format!(
                                        "Logged in, but could not save device cache: {e:#}"
                                    )));
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Action::Error(format!(
                                    "Logged in, but device enrollment failed: {e:#}"
                                )));
                            }
                        },
                        None => {
                            let _ = tx.send(Action::Error(
                                "device_unlock.enabled is set but recipient is missing".to_string(),
                            ));
                        }
                    }
                }
            }
            let _ = tx.send(Action::Keys(keys));
            let _ = tx.send(Action::StopCapture);
            let _ = tx.send(Action::CloseModal);
            let _ = tx.send(Action::SetMode(Mode::Home));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{drain, is_global_chord};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// `handle_actions` relies on `drain` pulling the *entire* backlog in one pass
    /// (the RC2 fix); a single `try_recv` would leave later actions queued.
    #[test]
    fn drain_collects_everything_queued() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        tx.send(3).unwrap();
        assert_eq!(drain(&mut rx), vec![1, 2, 3]);
    }

    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    /// Ctrl/Alt chords are global (dispatch over modals and capture); bare keys
    /// the user could type into a field are not.
    #[test]
    fn global_chords_are_ctrl_or_alt() {
        assert!(is_global_chord(&key(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        )));
        assert!(is_global_chord(&key(
            KeyCode::Char('z'),
            KeyModifiers::CONTROL
        )));
        assert!(is_global_chord(&key(KeyCode::Char('x'), KeyModifiers::ALT)));

        assert!(!is_global_chord(&key(
            KeyCode::Char('?'),
            KeyModifiers::empty()
        )));
        assert!(!is_global_chord(&key(
            KeyCode::Char('a'),
            KeyModifiers::empty()
        )));
        assert!(!is_global_chord(&key(KeyCode::Tab, KeyModifiers::empty())));
        assert!(!is_global_chord(&key(KeyCode::Esc, KeyModifiers::empty())));
        // Shift alone (e.g. an uppercase letter) is still typeable, not global.
        assert!(!is_global_chord(&key(
            KeyCode::Char('A'),
            KeyModifiers::SHIFT
        )));
    }
}
