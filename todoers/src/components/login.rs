use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use tokio::sync::mpsc::UnboundedSender;
use zeroize::Zeroizing;

use super::{Captures, Component, FormAction, FormKeys, TextInput};
use crate::action::Action;
use crate::config::Config;
use crate::tui::Event;

/// Field indices into [`Login::fields`].
const USERNAME: usize = 0;
const PASSWORD: usize = 1;

/// A login form: a username and a password input plus a key-hint footer.
///
/// `Login` owns focus. Exactly one field captures keystrokes at a time;
/// Tab/Shift+Tab and the arrow keys move focus, Enter advances (and, from the
/// last field, hands focus to the modal's Submit button), and Esc clears any
/// inline error. On submit it emits a single [`Action::Login`] carrying the
/// credentials, which `App` turns into the networked OPAQUE login flow.
pub struct Login {
    fields: [TextInput; 2],
    focused: usize,
    /// Inline validation/network error shown beneath the fields.
    error: Option<String>,
    /// True while a registration request is in flight.
    busy: bool,
    command_tx: Option<UnboundedSender<Action>>,
    keys: FormKeys,
}

impl Captures for Login {
    #[tracing::instrument(skip(self))]
    fn captures_input(&self) -> bool {
        true
    }
}

impl Login {
    #[tracing::instrument]
    pub fn new() -> Self {
        Self {
            fields: [
                TextInput::new().label("Username"),
                TextInput::new().label("Password").masked(),
            ],
            focused: USERNAME,
            error: None,
            busy: false,
            command_tx: None,
            keys: FormKeys::default(),
        }
    }

    /// Focus `idx`, blurring whatever was focused before, and clear any error.
    #[tracing::instrument(skip(self))]
    fn set_focus(&mut self, idx: usize) {
        self.fields[self.focused].blur();
        self.focused = idx;
        self.fields[self.focused].focus();
        self.error = None;
    }

    #[tracing::instrument(skip(self))]
    fn focus_next(&mut self) {
        let n = self.fields.len();
        self.set_focus((self.focused + 1) % n);
    }

    #[tracing::instrument(skip(self))]
    fn focus_prev(&mut self) {
        let n = self.fields.len();
        self.set_focus((self.focused + n - 1) % n);
    }

    /// Reset focus to the first field (used when the screen begins capturing).
    #[tracing::instrument(skip(self))]
    fn reset(&mut self) {
        self.focused = USERNAME;
        for (i, field) in self.fields.iter_mut().enumerate() {
            if i == USERNAME {
                field.focus();
            } else {
                field.blur();
            }
        }
        self.error = None;
        self.busy = false;
    }

    /// Validate the form and, if it passes, emit [`Action::Login`].
    #[tracing::instrument(skip(self))]
    fn submit(&mut self) {
        let username = self.fields[USERNAME].value().trim().to_string();
        let password = Zeroizing::new(self.fields[PASSWORD].value().to_string());

        if username.is_empty() {
            self.error = Some("Username is required".to_string());
            return;
        }
        if password.is_empty() {
            self.error = Some("Password is required".to_string());
            return;
        }

        self.error = None;
        self.busy = true;
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(Action::Login { username, password });
        }
    }
}

impl Component for Login {
    #[tracing::instrument(skip(self))]
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.command_tx = Some(tx.clone());
        for field in &mut self.fields {
            field.register_action_handler(tx.clone())?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self, config))]
    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        for field in &mut self.fields {
            field.register_config_handler(config.clone())?;
        }
        self.keys.configure(&config);
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn init(&mut self, area: Size) -> anyhow::Result<()> {
        for field in &mut self.fields {
            field.init(area)?;
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn handle_events(&mut self, event: Option<Event>) -> anyhow::Result<Option<Action>> {
        // Bracketed paste arrives as a single `Event::Paste`, which the default
        // `handle_events` drops. Forward it to the focused field.
        if let Some(Event::Paste(_)) = event {
            return self.fields[self.focused].handle_events(event);
        }
        match event {
            Some(Event::Key(key)) => self.handle_key_event(key),
            Some(Event::Mouse(mouse)) => self.handle_mouse_event(mouse),
            _ => Ok(None),
        }
    }

    #[tracing::instrument(skip(self))]
    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        match self.keys.classify(key) {
            FormAction::Next => {
                self.focus_next();
                Ok(None)
            }
            FormAction::Prev => {
                self.focus_prev();
                Ok(None)
            }
            FormAction::Submit => {
                if self.focused < PASSWORD {
                    self.focus_next();
                    Ok(None)
                } else {
                    // On the last field, hand focus to the modal's Submit button
                    // rather than submitting; the form is submitted when Submit
                    // is activated (see `Action::SubmitForm` in `update`).
                    Ok(Some(Action::FocusButtons))
                }
            }
            // Everything else (Esc to leave a Vim field, chars, Backspace,
            // Left/Right/Home/End, Delete) edits only the focused field.
            FormAction::PassToField => self.fields[self.focused].handle_key_event(key),
        }
    }

    #[tracing::instrument(skip(self))]
    fn consumes_escape(&self) -> bool {
        self.fields[self.focused].consumes_escape()
    }

    #[tracing::instrument(skip(self))]
    fn editor_mode(&self) -> Option<super::EditorMode> {
        self.fields[self.focused].editor_mode()
    }

    #[tracing::instrument(skip(self))]
    fn handle_mouse_event(&mut self, _mouse: MouseEvent) -> anyhow::Result<Option<Action>> {
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn placement(&self) -> Constraint {
        Constraint::Length(9)
    }

    #[tracing::instrument(skip(self))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        match &action {
            // The app broadcasts a single StartCapture on entry; we translate it
            // into focusing the first field rather than letting every field capture.
            Action::StartCapture => {
                self.reset();
                return Ok(None);
            }
            Action::StopCapture => {
                for field in &mut self.fields {
                    field.blur();
                }
                return Ok(None);
            }
            // The modal's Submit button asks the form to validate and submit.
            Action::SubmitForm => {
                self.submit();
                return Ok(None);
            }
            // Surface a failed login (sent by the app's spawned task) inline.
            Action::Error(msg) => {
                self.error = Some(msg.clone());
                self.busy = false;
                return Ok(None);
            }
            _ => {}
        }
        for field in &mut self.fields {
            if let Some(action) = field.update(action.clone())? {
                return Ok(Some(action));
            }
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        let [user, pass, status] = Layout::vertical([
            self.fields[USERNAME].placement(),
            self.fields[PASSWORD].placement(),
            Constraint::Length(1),
        ])
        .areas(area);

        self.fields[USERNAME].draw(frame, user)?;
        self.fields[PASSWORD].draw(frame, pass)?;

        let status_line = if self.busy {
            Line::from("Signing in…").style(Style::default().fg(Color::Yellow))
        } else if let Some(err) = &self.error {
            Line::from(err.as_str()).style(Style::default().fg(Color::Red))
        } else {
            Line::from("Tab/↑↓ move · Enter next · Esc clear")
                .style(Style::default().fg(Color::DarkGray))
        };
        frame.render_widget(
            Paragraph::new(status_line).alignment(Alignment::Center),
            status,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use pretty_assertions::assert_eq;
    use tokio::sync::mpsc;

    fn ch(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty())
    }

    fn code(k: KeyCode) -> KeyEvent {
        KeyEvent::new(k, KeyModifiers::empty())
    }

    fn typed(screen: &mut Login, s: &str) {
        for c in s.chars() {
            screen.handle_key_event(ch(c)).unwrap();
        }
    }

    /// Keystrokes reach only the focused field, and Tab advances focus.
    #[test]
    fn typing_only_affects_focused_field() {
        let mut screen = Login::new();
        screen.register_config_handler(Config::defaults()).unwrap();
        screen.update(Action::StartCapture).unwrap();

        typed(&mut screen, "alice");
        assert_eq!(screen.fields[USERNAME].value(), "alice");
        assert_eq!(screen.fields[PASSWORD].value(), "");

        screen.handle_key_event(code(KeyCode::Tab)).unwrap();
        typed(&mut screen, "hunter2");
        assert_eq!(screen.fields[USERNAME].value(), "alice");
        assert_eq!(screen.fields[PASSWORD].value(), "hunter2");
    }

    /// Enter on the password field hands focus to the buttons without submitting;
    /// `SubmitForm` emits exactly one `Login` carrying the credentials.
    #[test]
    fn submit_emits_login() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut screen = Login::new();
        screen.register_action_handler(tx).unwrap();
        screen.register_config_handler(Config::defaults()).unwrap();
        screen.update(Action::StartCapture).unwrap();

        typed(&mut screen, "alice");
        screen.handle_key_event(code(KeyCode::Tab)).unwrap();
        typed(&mut screen, "hunter2");
        assert_eq!(
            screen.handle_key_event(code(KeyCode::Enter)).unwrap(),
            Some(Action::FocusButtons)
        );
        assert!(rx.try_recv().is_err());

        screen.update(Action::SubmitForm).unwrap();
        match rx.try_recv() {
            Ok(Action::Login { username, password }) => {
                assert_eq!(username, "alice");
                assert_eq!(password, Zeroizing::new("hunter2".to_string()));
            }
            other => panic!("expected Login, got {other:?}"),
        }
        assert!(screen.busy);
        assert!(screen.error.is_none());
    }

    /// A missing password sets an inline error and emits nothing on submit.
    #[test]
    fn empty_password_blocks_submit() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut screen = Login::new();
        screen.register_action_handler(tx).unwrap();
        screen.update(Action::StartCapture).unwrap();

        typed(&mut screen, "alice");
        screen.update(Action::SubmitForm).unwrap();

        assert!(rx.try_recv().is_err());
        assert_eq!(screen.error.as_deref(), Some("Password is required"));
        assert!(!screen.busy);
    }
}
