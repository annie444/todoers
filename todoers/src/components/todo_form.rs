use crossterm::event::{KeyCode, KeyEvent, MouseEvent};
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use time::OffsetDateTime;
use time::macros::format_description;
use tokio::sync::mpsc::UnboundedSender;

use todoers_types::ListId;

use super::{Captures, Component, TextInput};
use crate::action::Action;
use crate::config::Config;
use crate::model::{Priority, TodoItem, TodoItemInput};
use crate::tui::Event;

const TITLE: usize = 0;
const NOTES: usize = 1;
const DUE: usize = 2;
const TAGS: usize = 3;
/// Pseudo-field index for the priority cycler (not a text input).
const PRIORITY: usize = 4;
const FIELD_COUNT: usize = 5;

const DATE_FMT: &[time::format_description::BorrowedFormatItem] =
    format_description!("[year]-[month]-[day]");

/// Add/edit form for a todo item. Fields: title, notes, due (YYYY-MM-DD),
/// tags (comma-separated), and a priority cycler. Emits [`Action::SaveTodo`]
/// (with `item_id` set when editing).
pub struct TodoForm {
    list_id: ListId,
    item_id: Option<String>,
    fields: [TextInput; 4],
    priority: Priority,
    focused: usize,
    error: Option<String>,
    command_tx: Option<UnboundedSender<Action>>,
}

impl Captures for TodoForm {
    fn captures_input(&self) -> bool {
        true
    }
}

impl TodoForm {
    fn blank(list_id: ListId, item_id: Option<String>) -> Self {
        Self {
            list_id,
            item_id,
            fields: [
                TextInput::new().label("Title"),
                TextInput::new().label("Notes"),
                TextInput::new().label("Due (YYYY-MM-DD)"),
                TextInput::new().label("Tags (comma-separated)"),
            ],
            priority: Priority::None,
            focused: TITLE,
            error: None,
            command_tx: None,
        }
    }

    pub fn add(list_id: ListId) -> Self {
        Self::blank(list_id, None)
    }

    pub fn edit(list_id: ListId, item: &TodoItem) -> Self {
        let mut form = Self::blank(list_id, Some(item.id.clone()));
        form.fields[TITLE].set_value(&item.title);
        form.fields[NOTES].set_value(&item.notes);
        if let Some(due) = item.due {
            form.fields[DUE].set_value(&due.format(DATE_FMT).unwrap_or_default());
        }
        form.fields[TAGS].set_value(&item.tags.join(", "));
        form.priority = item.priority;
        form
    }

    fn set_focus(&mut self, idx: usize) {
        if self.focused < self.fields.len() {
            self.fields[self.focused].blur();
        }
        self.focused = idx;
        if self.focused < self.fields.len() {
            self.fields[self.focused].focus();
        }
        self.error = None;
    }

    fn focus_next(&mut self) {
        self.set_focus((self.focused + 1) % FIELD_COUNT);
    }

    fn focus_prev(&mut self) {
        self.set_focus((self.focused + FIELD_COUNT - 1) % FIELD_COUNT);
    }

    fn reset(&mut self) {
        self.focused = TITLE;
        for (i, f) in self.fields.iter_mut().enumerate() {
            if i == TITLE {
                f.focus();
            } else {
                f.blur();
            }
        }
        self.error = None;
    }

    /// Parse the due field: empty → None; otherwise `YYYY-MM-DD` at midnight UTC.
    fn parse_due(&self) -> Result<Option<OffsetDateTime>, String> {
        let raw = self.fields[DUE].value();
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        let date = time::Date::parse(raw, DATE_FMT)
            .map_err(|_| "Due date must be YYYY-MM-DD".to_string())?;
        Ok(Some(date.midnight().assume_utc()))
    }

    fn submit(&mut self) {
        let title = self.fields[TITLE].value().trim().to_string();
        if title.is_empty() {
            self.error = Some("Title is required".to_string());
            return;
        }
        let due = match self.parse_due() {
            Ok(d) => d,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let tags: Vec<String> = self.fields[TAGS]
            .value()
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        let input = TodoItemInput {
            title,
            notes: self.fields[NOTES].value().trim().to_string(),
            due,
            priority: self.priority,
            tags,
        };
        self.error = None;
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(Action::SaveTodo {
                list_id: self.list_id,
                item_id: self.item_id.clone(),
                input,
            });
        }
    }
}

impl Component for TodoForm {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.command_tx = Some(tx.clone());
        for f in &mut self.fields {
            f.register_action_handler(tx.clone())?;
        }
        Ok(())
    }

    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        for f in &mut self.fields {
            f.register_config_handler(config.clone())?;
        }
        Ok(())
    }

    fn init(&mut self, area: Size) -> anyhow::Result<()> {
        for f in &mut self.fields {
            f.init(area)?;
        }
        Ok(())
    }

    fn handle_events(&mut self, event: Option<Event>) -> anyhow::Result<Option<Action>> {
        if let Some(Event::Paste(_)) = event
            && self.focused < self.fields.len()
        {
            return self.fields[self.focused].handle_events(event);
        }
        match event {
            Some(Event::Key(key)) => self.handle_key_event(key),
            Some(Event::Mouse(mouse)) => self.handle_mouse_event(mouse),
            _ => Ok(None),
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        // The priority pseudo-field: cycle with space/←/→/h/l; Tab/↑↓ still move.
        if self.focused == PRIORITY {
            match key.code {
                KeyCode::Tab | KeyCode::Down => self.focus_next(),
                KeyCode::BackTab | KeyCode::Up => self.focus_prev(),
                KeyCode::Char(' ')
                | KeyCode::Right
                | KeyCode::Char('l')
                | KeyCode::Left
                | KeyCode::Char('h') => self.priority = self.priority.next(),
                KeyCode::Enter => return Ok(Some(Action::FocusButtons)),
                KeyCode::Esc => self.error = None,
                _ => {}
            }
            return Ok(None);
        }

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
                if self.focused < TAGS {
                    self.focus_next();
                    Ok(None)
                } else {
                    // Last text field → move to priority, then buttons.
                    Ok(Some(Action::FocusButtons))
                }
            }
            KeyCode::Esc if self.fields[self.focused].consumes_escape() => {
                self.fields[self.focused].handle_key_event(key)
            }
            KeyCode::Esc => {
                self.error = None;
                Ok(None)
            }
            _ => self.fields[self.focused].handle_key_event(key),
        }
    }

    fn consumes_escape(&self) -> bool {
        self.focused < self.fields.len() && self.fields[self.focused].consumes_escape()
    }

    fn editor_mode(&self) -> Option<super::EditorMode> {
        if self.focused < self.fields.len() {
            self.fields[self.focused].editor_mode()
        } else {
            None
        }
    }

    fn handle_mouse_event(&mut self, _mouse: MouseEvent) -> anyhow::Result<Option<Action>> {
        Ok(None)
    }

    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        match &action {
            Action::StartCapture => {
                self.reset();
                return Ok(None);
            }
            Action::StopCapture => {
                for f in &mut self.fields {
                    f.blur();
                }
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
        for f in &mut self.fields {
            if let Some(a) = f.update(action.clone())? {
                return Ok(Some(a));
            }
        }
        Ok(None)
    }

    fn placement(&self) -> Constraint {
        // 4 text fields (3 rows each) + priority line + status line.
        Constraint::Length(4 * 3 + 2)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        let [title, notes, due, tags, prio, status] = Layout::vertical([
            self.fields[TITLE].placement(),
            self.fields[NOTES].placement(),
            self.fields[DUE].placement(),
            self.fields[TAGS].placement(),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(area);

        self.fields[TITLE].draw(frame, title)?;
        self.fields[NOTES].draw(frame, notes)?;
        self.fields[DUE].draw(frame, due)?;
        self.fields[TAGS].draw(frame, tags)?;

        let prio_focused = self.focused == PRIORITY;
        let prio_style = if prio_focused {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        frame.render_widget(
            Paragraph::new(Line::from(format!(
                " Priority: {}  (space to cycle) ",
                self.priority.label()
            )))
            .style(prio_style),
            prio,
        );

        let line = match &self.error {
            Some(err) => Line::from(err.as_str()).style(Style::default().fg(Color::Red)),
            None => Line::from("Tab/↑↓ move · Enter next/submit · Esc cancel")
                .style(Style::default().fg(Color::DarkGray)),
        };
        frame.render_widget(Paragraph::new(line).alignment(Alignment::Center), status);
        Ok(())
    }
}
