use std::collections::HashMap;

use crossterm::event::{KeyEvent, KeyModifiers};
use nohash_hasher::BuildNoHashHasher;
use ratatui::prelude::{Constraint, Layout, Rect};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::action::Action;
use crate::auth::{AccountRow, UnlockedKeys};
use crate::components::{
    Button, Captures, Component, ErrorBar, Help, Home, Keys, Login, Modal, Prompt, Register, Unlock,
};
use crate::config::Config;
use crate::db::Db;
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

impl App {
    #[tracing::instrument(skip(config, db))]
    pub async fn new(
        config: Config,
        db: Db,
        account: Option<Zeroizing<AccountRow>>,
        acct_keys: Option<Zeroizing<UnlockedKeys>>,
    ) -> anyhow::Result<Self> {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let mut modes: HashMap<Mode, Box<dyn Component>, BuildNoHashHasher<u8>> =
            HashMap::with_capacity_and_hasher(1, BuildNoHashHasher::default());
        modes.insert(Mode::Home, Box::new(Home::new()));
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
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut tui = Tui::new()?.mouse(true);
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
            self.handle_events(&mut tui).await?;
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

    #[tracing::instrument(skip(self, tui))]
    async fn handle_events(&mut self, tui: &mut Tui) -> anyhow::Result<()> {
        let Some(event) = tui.next_event().await else {
            return Ok(());
        };
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
                        // This should also be unreachable: if we have an account, we should have keys. Log a warning and prompt for auth just in case.
                        warn!(
                            "Have local account but no cryptographic keys; this should not happen. Prompting for authentication."
                        );
                        action_tx.send(Action::UnlockModal)?;
                    } else if self.account.is_some() && self.acct_keys.is_some() {
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
                action_tx.send(action.clone())?;
            }
            _ => {
                // If the key was not handled as a single key action,
                // then consider it for multi-key combinations.
                self.last_tick_key_events.push(key);

                // Check for multi-key combinations
                if let Some(action) = keymap.get(&self.last_tick_key_events) {
                    info!("Got action: {action:?}");
                    action_tx.send(action.clone())?;
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, tui))]
    fn handle_actions(&mut self, tui: &mut Tui) -> anyhow::Result<()> {
        match self.action_rx.try_recv() {
            Ok(action) => {
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
                    Action::Quit => self.should_quit = true,
                    Action::Suspend => self.should_suspend = true,
                    Action::Resume => self.should_suspend = false,
                    Action::ClearScreen => tui.terminal.clear()?,
                    Action::Resize(w, h) => self.handle_resize(tui, w, h)?,
                    Action::Render => self.render(tui)?,
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
                    Action::SubmitInput(ref text) => {
                        info!("Submitted input: {text}");
                        self.capturing = false;
                    }
                    Action::UnlockModal => {
                        // The user has a local account but no keys (e.g. first launch
                        // after a reinstall). Prompt for the password to unlock the
                        // escrowed keys from the server.
                        let mut modal =
                            Modal::form("Unlock", Box::new(Unlock::new()), Action::AuthChooser);
                        modal.register_action_handler(self.action_tx.clone())?;
                        modal.register_config_handler(self.config.clone())?;
                        modal.init(tui.size()?)?;
                        self.prev_mode = self.mode;
                        self.mode = Mode::Home;
                        self.refresh_keys()?;
                        self.capturing = false;
                        self.modal = Some(modal);
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
                                        let _ = tx.send(Action::Error(format!(
                                            "Could not save account: {e}"
                                        )));
                                    }
                                },
                                Err(e) => {
                                    let _ =
                                        tx.send(Action::Error(format!("Registration failed: {e}")));
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
                        let mut modal =
                            Modal::form("Login", Box::new(Login::new()), Action::AuthChooser);
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
                        self.action_tx.send(action)?
                    };
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
            Err(mpsc::error::TryRecvError::Disconnected) => {
                // If the sender has been dropped, we can choose to quit the app or handle it as needed.
                self.should_quit = true;
            }
        }
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
        tui.draw(|frame| {
            let [body, errorbar, footer] = Layout::vertical([
                Constraint::Fill(1),
                self.errorbar.placement(),
                self.keys.placement(),
            ])
            .areas(frame.area());
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
        })?;
        Ok(())
    }

    pub fn login(&self, username: String, password: Zeroizing<String>) {
        // Drive the networked OPAQUE login off the UI loop; results
        // come back as actions (Error, or Keys+StopCapture+SetMode).
        let tx = self.action_tx.clone();
        let base_url = self.config.config.server_url.clone();
        let db = self.db.clone();
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
            let _ = tx.send(Action::Keys(keys));
            let _ = tx.send(Action::StopCapture);
            let _ = tx.send(Action::CloseModal);
            let _ = tx.send(Action::SetMode(Mode::Home));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::is_global_chord;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

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
