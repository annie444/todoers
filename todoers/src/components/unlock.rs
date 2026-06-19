use crossterm::event::{KeyCode, KeyEvent, MouseEvent};
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use tokio::sync::mpsc::UnboundedSender;
use zeroize::Zeroizing;

use super::{Captures, Component, TextInput};
use crate::action::Action;
use crate::config::Config;

/// Field indices into [`Register::fields`].

/// A registration form: three text inputs plus a key-hint footer.
///
/// `Register` owns focus. Exactly one field captures keystrokes at a time;
/// Tab/Shift+Tab and the arrow keys move focus, Enter advances (and submits from
/// the last field), and Esc clears any inline error. On a valid submit it emits a
/// single [`Action::Register`] carrying the credentials, which `App` turns into the
/// networked OPAQUE registration flow.
pub struct Unlock {
    password: TextInput,
    /// Inline validation/network error shown beneath the fields.
    error: Option<String>,
    /// True while a registration request is in flight.
    busy: bool,
    focused: bool,
    command_tx: Option<UnboundedSender<Action>>,
}

impl Captures for Unlock {
    #[tracing::instrument(skip(self))]
    fn captures_input(&self) -> bool {
        true
    }
}

impl Unlock {
    #[tracing::instrument]
    pub fn new() -> Self {
        Self {
            password: TextInput::new().label("Password").masked(),
            error: None,
            busy: false,
            focused: false,
            command_tx: None,
        }
    }

    /// Focus `idx`, blurring whatever was focused before, and clear any error.
    #[tracing::instrument(skip(self))]
    fn set_focus(&mut self) {
        self.password.focus();
        self.focused = true;
        self.error = None;
    }

    #[tracing::instrument(skip(self))]
    fn focus_next(&mut self) {
        self.set_focus();
        self.focused = true;
    }

    #[tracing::instrument(skip(self))]
    fn focus_prev(&mut self) {
        self.set_focus();
        self.focused = true;
    }

    /// Reset focus to the first field (used when the screen begins capturing).
    #[tracing::instrument(skip(self))]
    fn reset(&mut self) {
        self.set_focus();
        self.focused = true;
        self.error = None;
        self.busy = false;
    }

    /// Validate the form and, if it passes, emit [`Action::Register`].
    #[tracing::instrument(skip(self))]
    fn submit(&mut self) {
        let password = self.password.value().to_string();

        if password.is_empty() {
            self.error = Some("Password is required".to_string());
            return;
        }

        self.focused = false;
        self.error = None;
        self.busy = true;
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(Action::Unlock {
                password: Zeroizing::new(password),
            });
        }
    }
}

impl Component for Unlock {
    #[tracing::instrument(skip(self))]
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.command_tx = Some(tx.clone());
        self.password.register_action_handler(tx)?;
        Ok(())
    }

    #[tracing::instrument(skip(self, config))]
    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        self.password.register_config_handler(config)?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn init(&mut self, area: Size) -> anyhow::Result<()> {
        self.password.init(area)?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                self.focus_next();
                Ok(None)
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus_prev();
                Ok(None)
            }
            KeyCode::Enter => {
                if !self.focused {
                    self.focus_next();
                    Ok(None)
                } else {
                    // On the last field, hand focus to the modal's Submit button
                    // rather than submitting; the form is submitted when Submit
                    // is activated (see `Action::SubmitForm` in `update`).
                    Ok(Some(Action::FocusButtons))
                }
            }
            KeyCode::Esc => {
                self.error = None;
                Ok(None)
            }
            // Everything else (chars, Backspace, Left/Right/Home/End, Delete) edits
            // only the focused field.
            _ => self.password.handle_key_event(key),
        }
    }

    #[tracing::instrument(skip(self))]
    fn handle_mouse_event(&mut self, _mouse: MouseEvent) -> anyhow::Result<Option<Action>> {
        Ok(None)
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
                self.password.blur();
                return Ok(None);
            }
            // The modal's Submit button asks the form to validate and submit.
            Action::SubmitForm => {
                self.submit();
                return Ok(None);
            }
            // Surface a failed registration (sent by the app's spawned task) inline.
            Action::Error(msg) => {
                self.error = Some(msg.clone());
                self.busy = false;
                return Ok(None);
            }
            _ => {}
        }
        if let Some(action) = self.password.update(action.clone())? {
            return Ok(Some(action));
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn placement(&self) -> Constraint {
        Constraint::Length(13)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        let [pass, status] =
            Layout::vertical([self.password.placement(), Constraint::Length(1)]).areas(area);

        self.password.draw(frame, pass)?;

        let status_line = if self.busy {
            Line::from("Unlocking…").style(Style::default().fg(Color::Yellow))
        } else if let Some(err) = &self.error {
            Line::from(err.as_str()).style(Style::default().fg(Color::Red))
        } else {
            Line::from("Tab/↑↓ move · Enter submit · Esc clear")
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

    fn typed(screen: &mut Unlock, s: &str) {
        for c in s.chars() {
            screen.handle_key_event(ch(c)).unwrap();
        }
    }

    /// Keystrokes reach only the focused field, and Tab advances focus.
    #[test]
    fn typing_only_affects_focused_field() {
        let mut screen = Unlock::new();
        screen.update(Action::StartCapture).unwrap();

        screen.handle_key_event(code(KeyCode::Tab)).unwrap();
        typed(&mut screen, "hunter2");
        assert_eq!(screen.password.value(), "hunter2");
    }

    /// Enter on the last field moves focus to the buttons (FocusButtons) without
    /// submitting; submitting happens on `SubmitForm` and emits exactly one
    /// `Register` carrying the credentials.
    #[test]
    fn valid_submit_emits_unlock() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut screen = Unlock::new();
        screen.register_action_handler(tx).unwrap();
        screen.update(Action::StartCapture).unwrap();

        typed(&mut screen, "hunter2");

        // Enter on the last field highlights Submit; it must not submit yet.
        assert_eq!(
            screen.handle_key_event(code(KeyCode::Enter)).unwrap(),
            Some(Action::FocusButtons)
        );
        assert!(rx.try_recv().is_err());

        // Activating Submit drives the actual submission.
        screen.update(Action::SubmitForm).unwrap();
        match rx.try_recv() {
            Ok(Action::Unlock { password }) => {
                assert_eq!(password, Zeroizing::new("hunter2".to_string()));
            }
            other => panic!("expected Register, got {other:?}"),
        }
        assert!(screen.busy);
        assert!(screen.error.is_none());
    }
}
