use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;

use super::{Captures, Component};
use crate::action::Action;
use crate::config::Config;

/// A focusable, clickable push button.
///
/// Each button owns the [`Action`] it emits when activated, so a container (the
/// [`Modal`](super::Modal)) only has to manage *which* button has focus — the
/// button itself decides what activating it means. Activation happens on
/// Enter/Space while focused, or on a left mouse click within its drawn area.
pub struct Button {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    /// Text shown inside the bordered box.
    label: String,
    /// Action emitted when the button is activated.
    action: Action,
    /// Whether this button currently has keyboard focus.
    focused: bool,
    /// The rectangle this button last drew into, used for mouse hit-testing.
    /// Mouse events carry absolute terminal coordinates, so we compare them
    /// against the most recent draw rect rather than any layout we recompute.
    last_area: Rect,
}

impl Button {
    #[tracing::instrument]
    pub fn new(label: impl Into<String> + std::fmt::Debug, action: Action) -> Self {
        Self {
            command_tx: None,
            config: Config::default(),
            label: label.into(),
            action,
            focused: false,
            last_area: Rect::default(),
        }
    }

    /// Set focus to an explicit state (used by the modal when cycling focus).
    #[tracing::instrument(skip(self))]
    pub fn set_focused(&mut self, focused: bool) {
        self.focused = focused;
    }

    /// Whether a mouse position falls inside the button's last drawn area.
    #[tracing::instrument(skip(self))]
    fn hit(&self, column: u16, row: u16) -> bool {
        self.last_area.contains(Position::new(column, row))
    }
}

impl Captures for Button {}

impl Component for Button {
    #[tracing::instrument(skip(self, tx))]
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.command_tx = Some(tx);
        Ok(())
    }

    #[tracing::instrument(skip(self, config))]
    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        self.config = config;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        if !self.focused {
            return Ok(None);
        }
        Ok(match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => Some(self.action.clone()),
            _ => None,
        })
    }

    #[tracing::instrument(skip(self))]
    fn handle_mouse_event(&mut self, mouse: MouseEvent) -> anyhow::Result<Option<Action>> {
        if let MouseEventKind::Down(MouseButton::Left) = mouse.kind
            && self.hit(mouse.column, mouse.row)
        {
            return Ok(Some(self.action.clone()));
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn placement(&self) -> Constraint {
        // A bordered single row of text.
        Constraint::Length(3)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        self.last_area = area;
        let border_style = if self.focused {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        let label_style = if self.focused {
            Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default()
        };
        let block = Block::bordered().border_style(border_style);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new(Text::styled(self.label.as_str(), label_style))
                .alignment(HorizontalAlignment::Center),
            inner,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use pretty_assertions::assert_eq;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn focused_enter_emits_action() {
        let mut b = Button::new("Close", Action::CloseModal);
        b.set_focused(true);
        assert_eq!(
            b.handle_key_event(key(KeyCode::Enter)).unwrap(),
            Some(Action::CloseModal)
        );
        assert_eq!(
            b.handle_key_event(key(KeyCode::Char(' '))).unwrap(),
            Some(Action::CloseModal)
        );
    }

    #[test]
    fn unfocused_button_ignores_keys() {
        let mut b = Button::new("Close", Action::CloseModal);
        assert_eq!(b.handle_key_event(key(KeyCode::Enter)).unwrap(), None);
    }

    #[test]
    fn focused_button_ignores_unrelated_keys() {
        let mut b = Button::new("Close", Action::CloseModal);
        b.set_focused(true);
        assert_eq!(b.handle_key_event(key(KeyCode::Char('x'))).unwrap(), None);
    }

    #[test]
    fn click_inside_emits_action() {
        let mut b = Button::new("Close", Action::CloseModal);
        b.last_area = Rect::new(5, 5, 10, 3);
        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 7,
            row: 6,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(
            b.handle_mouse_event(mouse).unwrap(),
            Some(Action::CloseModal)
        );
    }

    #[test]
    fn click_outside_is_ignored() {
        let mut b = Button::new("Close", Action::CloseModal);
        b.last_area = Rect::new(5, 5, 10, 3);
        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 100,
            row: 100,
            modifiers: KeyModifiers::NONE,
        };
        assert_eq!(b.handle_mouse_event(mouse).unwrap(), None);
    }
}
