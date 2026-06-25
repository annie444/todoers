use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use tokio::sync::mpsc::UnboundedSender;

use todoers_types::ListId;

use super::{Captures, Component, FormAction, FormKeys, TextInput};
use crate::action::Action;
use crate::config::Config;
use crate::tui::Event;

/// Whether the form creates a new list or renames an existing one.
enum ListOp {
    Create,
    Rename(ListId),
}

/// A one-field form for creating or renaming a list. Lives inside a
/// [`Modal::form`](super::Modal); on submit it emits [`Action::CreateList`] or
/// [`Action::RenameList`], which `App` fulfills.
pub struct ListForm {
    field: TextInput,
    op: ListOp,
    error: Option<String>,
    command_tx: Option<UnboundedSender<Action>>,
    keys: FormKeys,
}

impl Captures for ListForm {
    fn captures_input(&self) -> bool {
        true
    }
}

impl ListForm {
    pub fn create() -> Self {
        Self {
            field: TextInput::new().label("List name"),
            op: ListOp::Create,
            error: None,
            command_tx: None,
            keys: FormKeys::default(),
        }
    }

    pub fn rename(list_id: ListId, current: &str) -> Self {
        let mut field = TextInput::new().label("List name");
        field.set_value(current);
        Self {
            field,
            op: ListOp::Rename(list_id),
            error: None,
            command_tx: None,
            keys: FormKeys::default(),
        }
    }

    fn submit(&mut self) {
        let name = self.field.value().trim().to_string();
        if name.is_empty() {
            self.error = Some("Name is required".to_string());
            return;
        }
        self.error = None;
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(match self.op {
                ListOp::Create => Action::CreateList { name },
                ListOp::Rename(list_id) => Action::RenameList { list_id, name },
            });
        }
    }
}

impl Component for ListForm {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.command_tx = Some(tx.clone());
        self.field.register_action_handler(tx)?;
        Ok(())
    }

    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        self.field.register_config_handler(config.clone())?;
        self.keys.configure(&config);
        Ok(())
    }

    fn init(&mut self, area: Size) -> anyhow::Result<()> {
        self.field.init(area)
    }

    fn handle_events(&mut self, event: Option<Event>) -> anyhow::Result<Option<Action>> {
        if let Some(Event::Paste(_)) = event {
            return self.field.handle_events(event);
        }
        match event {
            Some(Event::Key(key)) => self.handle_key_event(key),
            Some(Event::Mouse(mouse)) => self.handle_mouse_event(mouse),
            _ => Ok(None),
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        match self.keys.classify(key) {
            // Single field: field movement is a no-op; submit hands focus to the
            // modal's Submit button.
            FormAction::Next | FormAction::Prev => Ok(None),
            FormAction::Submit => Ok(Some(Action::FocusButtons)),
            FormAction::PassToField => self.field.handle_key_event(key),
        }
    }

    fn consumes_escape(&self) -> bool {
        self.field.consumes_escape()
    }

    fn editor_mode(&self) -> Option<super::EditorMode> {
        self.field.editor_mode()
    }

    fn handle_mouse_event(&mut self, _mouse: MouseEvent) -> anyhow::Result<Option<Action>> {
        Ok(None)
    }

    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        match &action {
            Action::StartCapture => {
                self.field.focus();
                return Ok(None);
            }
            Action::StopCapture => {
                self.field.blur();
                return Ok(None);
            }
            Action::SubmitForm => {
                self.submit();
                return Ok(None);
            }
            Action::Error(msg) => {
                self.error = Some(msg.clone());
                return Ok(None);
            }
            _ => {}
        }
        self.field.update(action)
    }

    fn placement(&self) -> Constraint {
        Constraint::Length(5)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        let [field, status] =
            Layout::vertical([self.field.placement(), Constraint::Length(1)]).areas(area);
        self.field.draw(frame, field)?;
        let line = match &self.error {
            Some(err) => Line::from(err.as_str()).style(Style::default().fg(Color::Red)),
            None => Line::from("Enter to submit · Esc to cancel")
                .style(Style::default().fg(Color::DarkGray)),
        };
        frame.render_widget(Paragraph::new(line).alignment(Alignment::Center), status);
        Ok(())
    }
}
