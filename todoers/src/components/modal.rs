use crossterm::event::{KeyCode, KeyEvent, MouseEvent};
use indexmap::IndexMap;
use ratatui::layout::Flex;
use ratatui::{prelude::*, widgets::*};
use serde::Deserialize;
use tokio::sync::mpsc::UnboundedSender;

use super::{Button, Captures, Component};
use crate::action::Action;
use crate::config::{Config, KeyContext, compile_keymap, parse_command, resolve};
use crate::tui::Event;

/// A modal's button-row operations, bound via `[keybindings.modal]`. `Esc` is
/// always a safe cancel (handled before these), but extra keys can be bound to
/// `cancel`/`activate`/focus movement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModalCmd {
    FocusNext,
    FocusPrev,
    Activate,
    Cancel,
}

/// A centered overlay dialog that floats on top of whatever mode is running.
///
/// The modal is **mode-agnostic**: it is not registered in the `App`'s mode map
/// and knows nothing about the screen beneath it. `App` owns it as an
/// `Option<Modal>`, routes events to it while it is open, and draws it last so
/// it overlays the active mode (the modal `Clear`s its own region first).
///
/// It is composed of a title, an arbitrary `body` component, and a row of
/// [`Button`]s. Keyboard focus cycles between the buttons; the focused button
/// decides what activating it emits (e.g. [`Action::CloseModal`]).
pub struct Modal {
    title: String,
    body: Box<dyn Component>,
    buttons: Vec<Button>,
    /// Index into `buttons` of the currently focused button.
    focused: usize,
    /// True while keyboard focus is inside an interactive `body` (a form) rather
    /// than on the button row. Only meaningful when `body.captures_input()`.
    focus_body: bool,
    /// What `Esc` (or, for forms, the Cancel button) emits. Lets the same modal
    /// mean "quit" for the auth gate or "back to the chooser" for a form.
    esc_action: Action,
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    /// Compiled `[keybindings.modal]` map + the multi-key sequence buffer.
    keymap: IndexMap<Vec<KeyEvent>, ModalCmd>,
    pending: Vec<KeyEvent>,
    /// One fixed-width slot per button, built once at construction so the
    /// per-frame `draw` doesn't reallocate it on every render.
    button_constraints: Vec<Constraint>,
}

impl Modal {
    /// Build a modal with explicit buttons and an `esc_action` (what `Esc`
    /// emits). Focus starts inside the body when it is interactive (a form), so
    /// its first field is active; otherwise it starts on the first button.
    #[tracing::instrument(skip(body, buttons))]
    pub fn new(
        title: impl Into<String> + std::fmt::Debug,
        body: Box<dyn Component>,
        buttons: Vec<Button>,
        esc_action: Action,
    ) -> Self {
        let focus_body = body.captures_input();
        let button_constraints = vec![Constraint::Length(12); buttons.len()];
        let mut modal = Self {
            title: title.into(),
            body,
            buttons,
            focused: 0,
            focus_body,
            esc_action,
            command_tx: None,
            config: Config::default(),
            keymap: IndexMap::new(),
            pending: Vec::new(),
            button_constraints,
        };
        modal.sync_focus();
        modal
    }

    /// An informational dialog with a single **Close** button (emits
    /// [`Action::CloseModal`]). Used by the help overlay. `Esc` also closes it.
    #[tracing::instrument(skip(body))]
    pub fn message(title: impl Into<String> + std::fmt::Debug, body: Box<dyn Component>) -> Self {
        Self::new(
            title,
            body,
            vec![Button::new("Close", Action::CloseModal)],
            Action::CloseModal,
        )
    }

    /// A form dialog: a **Submit** button (emits [`Action::SubmitForm`], which is
    /// forwarded into the form body) and a **Cancel** button (emits
    /// `cancel_action`). `Esc` mirrors Cancel.
    #[tracing::instrument(skip(body))]
    pub fn form(
        title: impl Into<String> + std::fmt::Debug,
        body: Box<dyn Component>,
        cancel_action: Action,
    ) -> Self {
        Self::new(
            title,
            body,
            vec![
                Button::new("Submit", Action::SubmitForm),
                Button::new("Cancel", cancel_action.clone()),
            ],
            cancel_action,
        )
    }

    /// A confirmation dialog: **Yes** emits `yes_action`, **No** dismisses the
    /// modal ([`Action::CloseModal`]). Built for reuse beyond the help page.
    #[allow(dead_code)]
    #[tracing::instrument(skip(body))]
    pub fn confirm(
        title: impl Into<String> + std::fmt::Debug,
        body: Box<dyn Component>,
        yes_action: Action,
    ) -> Self {
        Self::new(
            title,
            body,
            vec![
                Button::new("Yes", yes_action),
                Button::new("No", Action::CloseModal),
            ],
            Action::CloseModal,
        )
    }

    /// Push focus state down into the buttons so at most one is highlighted —
    /// none while focus is inside the body.
    #[tracing::instrument(skip(self))]
    fn sync_focus(&mut self) {
        for (i, button) in self.buttons.iter_mut().enumerate() {
            button.set_focused(!self.focus_body && i == self.focused);
        }
    }

    #[tracing::instrument(skip(self))]
    fn focus_next(&mut self) {
        if !self.buttons.is_empty() {
            self.focused = (self.focused + 1) % self.buttons.len();
            self.sync_focus();
        }
    }

    #[tracing::instrument(skip(self))]
    fn focus_prev(&mut self) {
        if !self.buttons.is_empty() {
            self.focused = (self.focused + self.buttons.len() - 1) % self.buttons.len();
            self.sync_focus();
        }
    }
}

impl Captures for Modal {}

impl Component for Modal {
    #[tracing::instrument(skip(self))]
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.body.register_action_handler(tx.clone())?;
        for button in self.buttons.iter_mut() {
            button.register_action_handler(tx.clone())?;
        }
        self.command_tx = Some(tx);
        Ok(())
    }

    #[tracing::instrument(skip(self, config))]
    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        self.body.register_config_handler(config.clone())?;
        for button in self.buttons.iter_mut() {
            button.register_config_handler(config.clone())?;
        }
        self.keymap = compile_keymap(
            config.keybindings.context(KeyContext::Modal),
            parse_command::<ModalCmd>,
        );
        self.config = config;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn init(&mut self, area: Size) -> anyhow::Result<()> {
        self.body.init(area)?;
        for button in self.buttons.iter_mut() {
            button.init(area)?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn editor_mode(&self) -> Option<super::EditorMode> {
        if self.focus_body && self.body.captures_input() {
            self.body.editor_mode()
        } else {
            None
        }
    }

    #[tracing::instrument(skip(self))]
    fn handle_events(&mut self, event: Option<Event>) -> anyhow::Result<Option<Action>> {
        // Bracketed paste arrives as a single `Event::Paste`, which the default
        // `handle_events` silently drops. Route it to a focused interactive body so
        // its text field receives the pasted text; keys/mouse keep normal routing.
        if let Some(Event::Paste(_)) = event
            && self.focus_body
            && self.body.captures_input()
        {
            return self.body.handle_events(event);
        }
        match event {
            Some(Event::Key(key)) => self.handle_key_event(key),
            Some(Event::Mouse(mouse)) => self.handle_mouse_event(mouse),
            _ => Ok(None),
        }
    }

    #[tracing::instrument(skip(self))]
    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        // Esc dismisses the modal. Where that leads depends on the modal (quit
        // for the auth gate, back-to-chooser for a form, close for an info box).
        // Exception: a focused Vim field mid-edit consumes Esc (Insert→Normal) and
        // the dialog stays open — only a field already in Normal mode lets Esc through.
        // Hardcoded (not bindable) so Esc is always a safe way out of any modal.
        if key.code == KeyCode::Esc {
            if self.focus_body && self.body.captures_input() && self.body.consumes_escape() {
                return self.body.handle_key_event(key);
            }
            return Ok(Some(self.esc_action.clone()));
        }

        // Zone 1 — focus is inside an interactive form body. The form owns
        // field navigation/typing (via its own `[keybindings.form]` map). When it
        // returns `FocusButtons` (submit on the last field) we move focus onto the
        // button row and blur the fields, rather than letting the signal escape.
        if self.focus_body && self.body.captures_input() {
            return match self.body.handle_key_event(key)? {
                Some(Action::FocusButtons) => {
                    self.focus_body = false;
                    self.focused = 0;
                    self.body.update(Action::StopCapture)?;
                    self.sync_focus();
                    Ok(None)
                }
                other => Ok(other),
            };
        }

        // Zone 2 — the button row has focus; navigation/activation is configurable.
        if let Some(cmd) = resolve(&self.keymap, &mut self.pending, key) {
            match cmd {
                ModalCmd::FocusNext => self.focus_next(),
                ModalCmd::FocusPrev => {
                    // Focusing past the first button drops back into the form (if
                    // any), re-focusing its first field so the user can keep editing.
                    if self.focused == 0 && self.body.captures_input() {
                        self.focus_body = true;
                        self.body.update(Action::StartCapture)?;
                        self.sync_focus();
                    } else {
                        self.focus_prev();
                    }
                }
                ModalCmd::Activate => {
                    if let Some(button) = self.buttons.get(self.focused) {
                        return Ok(Some(button.action()));
                    }
                }
                ModalCmd::Cancel => return Ok(Some(self.esc_action.clone())),
            }
            return Ok(None);
        }
        // A non-interactive body (e.g. help) may still react to a key; a form
        // body is skipped here so a stray key doesn't re-trigger the form behind
        // the buttons.
        if !self.body.captures_input()
            && let Some(action) = self.body.handle_key_event(key)?
        {
            return Ok(Some(action));
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn handle_mouse_event(&mut self, mouse: MouseEvent) -> anyhow::Result<Option<Action>> {
        if let Some(action) = self.body.handle_mouse_event(mouse)? {
            return Ok(Some(action));
        }
        // A click lands by hit-testing each button's last drawn area, so any
        // button can be clicked regardless of which one currently has focus.
        for button in self.buttons.iter_mut() {
            if let Some(action) = button.handle_mouse_event(mouse)? {
                return Ok(Some(action));
            }
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        if let Some(action) = self.body.update(action.clone())? {
            return Ok(Some(action));
        }
        for button in self.buttons.iter_mut() {
            if let Some(action) = button.update(action.clone())? {
                return Ok(Some(action));
            }
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        // Center a dialog box: 60% width, height sized to body + buttons + borders.
        let button_row = 3u16; // bordered single-row buttons
        let body_h = match self.body.placement() {
            Constraint::Length(n) => n,
            _ => 6,
        };
        let dialog_h = body_h + button_row + 2; // +2 for the outer block borders
        let [area] = Layout::vertical([Constraint::Length(dialog_h)])
            .flex(Flex::Center)
            .areas(area);
        let [area] = Layout::horizontal([Constraint::Percentage(60)])
            .flex(Flex::Center)
            .areas(area);

        // Blank the region so the screen underneath does not bleed through.
        frame.render_widget(Clear, area);

        let block = Block::bordered()
            .title(self.title.as_str())
            .border_style(Style::default().fg(Color::Yellow));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [body_area, buttons_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(button_row)]).areas(inner);

        self.body.draw(frame, body_area)?;

        if !self.buttons.is_empty() {
            // Evenly space fixed-width buttons across the button row.
            let slots = Layout::horizontal(self.button_constraints.iter().copied())
                .flex(Flex::SpaceAround)
                .split(buttons_area);
            for (button, slot) in self.buttons.iter_mut().zip(slots.iter()) {
                button.draw(frame, *slot)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::Register;
    use crossterm::event::KeyModifiers;
    use pretty_assertions::assert_eq;
    use tokio::sync::mpsc;
    use zeroize::Zeroizing;

    fn ch(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty())
    }

    fn code(k: KeyCode) -> KeyEvent {
        KeyEvent::new(k, KeyModifiers::empty())
    }

    fn type_str(modal: &mut Modal, s: &str) {
        for c in s.chars() {
            modal.handle_key_event(ch(c)).unwrap();
        }
    }

    /// Driving a form body through the modal exactly as `App` does: StartCapture
    /// focuses the first field, typed keys reach the focused field, Tab navigates
    /// fields (not the modal's buttons), Enter on the last field moves focus onto
    /// the Submit button, and activating Submit emits `SubmitForm` — which, once
    /// forwarded back into the body, produces the `Register` action.
    #[test]
    fn enter_highlights_submit_then_submits() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut modal = Modal::form("Register", Box::new(Register::new()), Action::AuthChooser);
        modal.register_action_handler(tx).unwrap();
        modal.register_config_handler(Config::defaults()).unwrap();
        // App sends StartCapture when the form modal opens.
        modal.update(Action::StartCapture).unwrap();

        type_str(&mut modal, "alice");
        modal.handle_key_event(code(KeyCode::Tab)).unwrap();
        type_str(&mut modal, "hunter2");
        modal.handle_key_event(code(KeyCode::Tab)).unwrap();
        type_str(&mut modal, "hunter2");

        // Enter on the last field highlights Submit instead of submitting.
        assert_eq!(modal.handle_key_event(code(KeyCode::Enter)).unwrap(), None);
        assert!(rx.try_recv().is_err(), "must not submit yet");

        // Activating Submit emits SubmitForm; App forwards it back into the body.
        assert_eq!(
            modal.handle_key_event(code(KeyCode::Enter)).unwrap(),
            Some(Action::SubmitForm)
        );
        modal.update(Action::SubmitForm).unwrap();

        match rx.try_recv() {
            Ok(Action::Register { username, password }) => {
                assert_eq!(username, "alice");
                assert_eq!(password, Zeroizing::new("hunter2".to_string()));
            }
            other => panic!("expected Register, got {other:?}"),
        }
    }

    /// A bracketed paste routes through the modal into the focused form field, so
    /// submitting carries the pasted text (regression: paste was silently dropped).
    #[test]
    fn paste_routes_through_modal_into_form() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut modal = Modal::form("Register", Box::new(Register::new()), Action::AuthChooser);
        modal.register_action_handler(tx).unwrap();
        modal.register_config_handler(Config::defaults()).unwrap();
        modal.update(Action::StartCapture).unwrap();

        // Paste the username, then type the two password fields and submit.
        modal
            .handle_events(Some(Event::Paste("alice".to_string())))
            .unwrap();
        modal.handle_key_event(code(KeyCode::Tab)).unwrap();
        type_str(&mut modal, "hunter2");
        modal.handle_key_event(code(KeyCode::Tab)).unwrap();
        type_str(&mut modal, "hunter2");
        modal.update(Action::SubmitForm).unwrap();

        match rx.try_recv() {
            Ok(Action::Register { username, password }) => {
                assert_eq!(username, "alice");
                assert_eq!(password, Zeroizing::new("hunter2".to_string()));
            }
            other => panic!("expected Register, got {other:?}"),
        }
    }

    /// Esc emits the modal's `esc_action` — for a form, the cancel action.
    #[test]
    fn esc_emits_the_esc_action() {
        let mut form = Modal::form("Register", Box::new(Register::new()), Action::AuthChooser);
        assert_eq!(
            form.handle_key_event(code(KeyCode::Esc)).unwrap(),
            Some(Action::AuthChooser)
        );

        let mut info = Modal::message("Help", Box::new(Register::new()));
        assert_eq!(
            info.handle_key_event(code(KeyCode::Esc)).unwrap(),
            Some(Action::CloseModal)
        );
    }
}
