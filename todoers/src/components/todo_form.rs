use crossterm::event::{KeyCode, KeyEvent, MouseEvent};
use ratatui::prelude::*;
use ratatui::widgets::calendar::{CalendarEventStore, Monthly};
use ratatui::widgets::{Block, List, ListItem, ListState, Paragraph};
use time::{Date, Duration, Month, OffsetDateTime};
use tokio::sync::mpsc::UnboundedSender;

use todoers_client::model::{Priority, TodoItem, TodoItemInput};
use todoers_types::ListId;

use super::form_keys::FormCmd;
use super::{Captures, Component, FormKeys, TextInput};
use crate::action::Action;
use crate::config::Config;
use crate::tui::Event;

const TITLE: usize = 0;
const NOTES: usize = 1;
const TAGS: usize = 2;
/// Pseudo-field index for the due-date calendar (not a text input).
const DUE: usize = 3;
/// Pseudo-field index for the priority list (not a text input).
const PRIORITY: usize = 4;
const FIELD_COUNT: usize = 5;

/// The four priority list rows, in rank order (`Priority::rank()` is the row index).
const PRIORITIES: [Priority; 4] = [Priority::None, Priority::Low, Priority::Med, Priority::High];

/// Rendered height of the bordered calendar block: month + weekday headers, up to
/// six week rows, and the top/bottom border.
const CAL_HEIGHT: u16 = 1 + 1 + 6 + 2;
/// Rendered height of the bordered priority list: four rows plus the border.
const PRIO_HEIGHT: u16 = PRIORITIES.len() as u16 + 2;

/// How a single navigation key moves the calendar cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CursorMove {
    PrevDay,
    NextDay,
    PrevWeek,
    NextWeek,
    PrevMonth,
    NextMonth,
}

/// Add/edit form for a todo item. Fields: title, notes, tags (comma-separated)
/// text inputs, a `Monthly` calendar for the due date, and a `List` for the
/// priority. Emits [`Action::SaveTodo`] (with `item_id` set when editing).
pub struct TodoForm {
    list_id: ListId,
    item_id: Option<String>,
    fields: [TextInput; 3],
    /// The day the calendar cursor sits on. Always a valid date; only becomes the
    /// item's due date when `due_enabled` is true.
    due_cursor: Date,
    /// Whether a due date is set. Toggled with Space while the calendar is focused;
    /// when false the item has no due date.
    due_enabled: bool,
    priority: Priority,
    focused: usize,
    error: Option<String>,
    command_tx: Option<UnboundedSender<Action>>,
    keys: FormKeys,
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
                TextInput::new().label("Tags (comma-separated)"),
            ],
            due_cursor: OffsetDateTime::now_utc().date(),
            due_enabled: false,
            priority: Priority::None,
            focused: TITLE,
            error: None,
            command_tx: None,
            keys: FormKeys::default(),
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
            form.due_cursor = due.date();
            form.due_enabled = true;
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

    /// Move the calendar cursor. Day/week steps are plain date arithmetic; month
    /// steps clamp the day to the target month's length (e.g. Jan 31 → Feb 28/29).
    fn move_cursor(&mut self, mv: CursorMove) {
        self.due_cursor = match mv {
            CursorMove::PrevDay => self.due_cursor.saturating_add(Duration::days(-1)),
            CursorMove::NextDay => self.due_cursor.saturating_add(Duration::days(1)),
            CursorMove::PrevWeek => self.due_cursor.saturating_add(Duration::days(-7)),
            CursorMove::NextWeek => self.due_cursor.saturating_add(Duration::days(7)),
            CursorMove::PrevMonth => Self::shift_month(self.due_cursor, -1),
            CursorMove::NextMonth => Self::shift_month(self.due_cursor, 1),
        };
    }

    /// Shift `date` by `delta` whole months, clamping the day-of-month to the
    /// length of the resulting month so short months never overflow.
    fn shift_month(date: Date, delta: i32) -> Date {
        let total = date.year() * 12 + (u8::from(date.month()) as i32 - 1) + delta;
        let year = total.div_euclid(12);
        let month = Month::try_from((total.rem_euclid(12) + 1) as u8).unwrap_or(Month::January);
        let day = date.day().min(month.length(year));
        Date::from_calendar_date(year, month, day).unwrap_or(date)
    }

    fn submit(&mut self) {
        let title = self.fields[TITLE].value().trim().to_string();
        if title.is_empty() {
            self.error = Some("Title is required".to_string());
            return;
        }
        // The calendar can only produce a valid date, so there is nothing to
        // reject: an unset due date is `None`, otherwise the cursor at midnight UTC.
        let due = self
            .due_enabled
            .then(|| self.due_cursor.midnight().assume_utc());
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

    /// Context-sensitive footer help for the focused field.
    fn help_text(&self) -> &'static str {
        match self.focused {
            DUE => "←→ day · ↑↓ week · PgUp/Dn month · Space toggle due · Tab move · Esc cancel",
            PRIORITY => "←→ / space change priority · Tab move · Enter submit · Esc cancel",
            _ => "Tab/↑↓ move · Enter next · Esc cancel",
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
        self.keys.configure(&config);
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
        // The due calendar intercepts the arrow/page keys for cursor movement and
        // Space for the on/off toggle; only the structural verbs (Tab/Enter) fall
        // through to navigation. Esc is a no-op here — the modal owns cancel.
        if self.focused == DUE {
            match key.code {
                KeyCode::Left => self.move_cursor(CursorMove::PrevDay),
                KeyCode::Right => self.move_cursor(CursorMove::NextDay),
                KeyCode::Up => self.move_cursor(CursorMove::PrevWeek),
                KeyCode::Down => self.move_cursor(CursorMove::NextWeek),
                KeyCode::PageUp => self.move_cursor(CursorMove::PrevMonth),
                KeyCode::PageDown => self.move_cursor(CursorMove::NextMonth),
                KeyCode::Char(' ') => self.due_enabled = !self.due_enabled,
                KeyCode::Esc => {}
                _ => {
                    if let Some(cmd) = self.keys.resolve(key) {
                        match cmd {
                            FormCmd::FieldNext => self.focus_next(),
                            FormCmd::FieldPrev => self.focus_prev(),
                            FormCmd::Submit => return Ok(Some(Action::FocusButtons)),
                            FormCmd::CyclePriorityNext | FormCmd::CyclePriorityPrev => {}
                        }
                    }
                }
            }
            return Ok(None);
        }

        // The priority list has no text input, so it can safely interpret every
        // binding (including the `cycle_priority_*` verbs that move the highlight).
        if self.focused == PRIORITY {
            if key.code != KeyCode::Esc
                && let Some(cmd) = self.keys.resolve(key)
            {
                match cmd {
                    FormCmd::FieldNext => self.focus_next(),
                    FormCmd::FieldPrev => self.focus_prev(),
                    FormCmd::Submit => return Ok(Some(Action::FocusButtons)),
                    FormCmd::CyclePriorityNext => self.priority = self.priority.next(),
                    FormCmd::CyclePriorityPrev => self.priority = self.priority.prev(),
                }
            }
            return Ok(None);
        }

        // Text fields: only the structural verbs act; everything else (Esc to leave
        // a Vim field, the `cycle_priority_*` keys, and ordinary characters) falls
        // through to the focused field so it types normally. No text field is last,
        // so Submit always advances (into the calendar/priority, then the buttons).
        if key.code != KeyCode::Esc {
            match self.keys.resolve(key) {
                Some(FormCmd::FieldNext) | Some(FormCmd::Submit) => {
                    self.focus_next();
                    return Ok(None);
                }
                Some(FormCmd::FieldPrev) => {
                    self.focus_prev();
                    return Ok(None);
                }
                Some(FormCmd::CyclePriorityNext) | Some(FormCmd::CyclePriorityPrev) | None => {}
            }
        }
        self.fields[self.focused].handle_key_event(key)
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
        // 3 text fields (3 rows each) + calendar block + priority list + status.
        Constraint::Length(3 * 3 + CAL_HEIGHT + PRIO_HEIGHT + 1)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        let [title, notes, tags, due, prio, status] = Layout::vertical([
            self.fields[TITLE].placement(),
            self.fields[NOTES].placement(),
            self.fields[TAGS].placement(),
            Constraint::Length(CAL_HEIGHT),
            Constraint::Length(PRIO_HEIGHT),
            Constraint::Length(1),
        ])
        .areas(area);

        self.fields[TITLE].draw(frame, title)?;
        self.fields[NOTES].draw(frame, notes)?;
        self.fields[TAGS].draw(frame, tags)?;

        let highlight = Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD);

        // Due calendar. The selected day is highlighted when a due date is set;
        // while navigating with the date unset the cursor is shown underlined so
        // movement is still visible. The border brightens when focused.
        let due_focused = self.focused == DUE;
        let mut store = CalendarEventStore::default();
        if self.due_enabled {
            store.add(self.due_cursor, highlight);
        } else if due_focused {
            store.add(
                self.due_cursor,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::UNDERLINED),
            );
        }
        let due_title = if self.due_enabled {
            format!("Due: {}", self.due_cursor)
        } else {
            "Due: none".to_string()
        };
        let due_border = if due_focused {
            Color::Yellow
        } else {
            Color::DarkGray
        };
        let calendar = Monthly::new(self.due_cursor, &store)
            .show_month_header(Style::default().add_modifier(Modifier::BOLD))
            .show_weekdays_header(Style::default().fg(Color::Cyan))
            .show_surrounding(Style::default().fg(Color::DarkGray))
            .block(
                Block::bordered()
                    .title(due_title)
                    .border_style(Style::default().fg(due_border)),
            );
        frame.render_widget(calendar, due);

        // Priority list; the highlighted row is the chosen priority.
        let prio_focused = self.focused == PRIORITY;
        let rows: Vec<ListItem> = PRIORITIES
            .iter()
            .map(|p| ListItem::new(format!(" {}", p.label())))
            .collect();
        let prio_border = if prio_focused {
            Color::Yellow
        } else {
            Color::DarkGray
        };
        let list = List::new(rows)
            .block(
                Block::bordered()
                    .title("Priority")
                    .border_style(Style::default().fg(prio_border)),
            )
            .highlight_style(highlight);
        let mut state = ListState::default();
        state.select(Some(self.priority.rank() as usize));
        frame.render_stateful_widget(list, prio, &mut state);

        let line = match &self.error {
            Some(err) => Line::from(err.as_str()).style(Style::default().fg(Color::Red)),
            None => Line::from(self.help_text()).style(Style::default().fg(Color::DarkGray)),
        };
        frame.render_widget(Paragraph::new(line).alignment(Alignment::Center), status);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use pretty_assertions::assert_eq;
    use tokio::sync::mpsc;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    /// A form wired up exactly as the modal does (config + action handler), so its
    /// `[keybindings.form]` map is live and `SaveTodo` is captured on `rx`.
    fn form() -> (TodoForm, mpsc::UnboundedReceiver<Action>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut form = TodoForm::add(ListId([0u8; 16]));
        form.register_config_handler(Config::defaults()).unwrap();
        form.register_action_handler(tx).unwrap();
        (form, rx)
    }

    fn submitted(rx: &mut mpsc::UnboundedReceiver<Action>) -> TodoItemInput {
        match rx.try_recv() {
            Ok(Action::SaveTodo { input, .. }) => input,
            other => panic!("expected SaveTodo, got {other:?}"),
        }
    }

    #[test]
    fn disabled_due_submits_none() {
        let (mut form, mut rx) = form();
        form.fields[TITLE].set_value("Buy milk");
        form.update(Action::SubmitForm).unwrap();
        let input = submitted(&mut rx);
        assert_eq!(input.title, "Buy milk");
        assert_eq!(input.due, None);
    }

    #[test]
    fn space_toggle_submits_cursor_at_midnight_utc() {
        let (mut form, mut rx) = form();
        form.fields[TITLE].set_value("Pay rent");
        form.focused = DUE;
        form.handle_key_event(key(KeyCode::Char(' '))).unwrap();
        assert!(form.due_enabled);
        let expected = form.due_cursor.midnight().assume_utc();
        form.update(Action::SubmitForm).unwrap();
        assert_eq!(submitted(&mut rx).due, Some(expected));
    }

    #[test]
    fn arrows_move_the_cursor_by_day_and_week() {
        let (mut form, _rx) = form();
        form.focused = DUE;
        form.due_cursor = Date::from_calendar_date(2026, Month::June, 15).unwrap();
        form.handle_key_event(key(KeyCode::Right)).unwrap();
        assert_eq!(form.due_cursor.day(), 16);
        form.handle_key_event(key(KeyCode::Down)).unwrap();
        assert_eq!(form.due_cursor, Date::from_calendar_date(2026, Month::June, 23).unwrap());
        form.handle_key_event(key(KeyCode::Left)).unwrap();
        assert_eq!(form.due_cursor.day(), 22);
    }

    #[test]
    fn month_step_clamps_short_months() {
        // Jan 31 → Feb: 2024 is a leap year (29), 2023 is not (28).
        let leap = Date::from_calendar_date(2024, Month::January, 31).unwrap();
        assert_eq!(
            TodoForm::shift_month(leap, 1),
            Date::from_calendar_date(2024, Month::February, 29).unwrap()
        );
        let non_leap = Date::from_calendar_date(2023, Month::January, 31).unwrap();
        assert_eq!(
            TodoForm::shift_month(non_leap, 1),
            Date::from_calendar_date(2023, Month::February, 28).unwrap()
        );
        // Stepping back across a year boundary.
        let jan = Date::from_calendar_date(2026, Month::January, 10).unwrap();
        assert_eq!(
            TodoForm::shift_month(jan, -1),
            Date::from_calendar_date(2025, Month::December, 10).unwrap()
        );
    }

    #[test]
    fn priority_cycles_through_the_list() {
        let (mut form, mut rx) = form();
        form.fields[TITLE].set_value("t");
        form.focused = PRIORITY;
        // `space` is bound to cycle_priority_next in the default form keymap.
        for expected in [Priority::Low, Priority::Med, Priority::High, Priority::None] {
            form.handle_key_event(key(KeyCode::Char(' '))).unwrap();
            assert_eq!(form.priority, expected);
        }
        form.handle_key_event(key(KeyCode::Char(' '))).unwrap(); // → Low
        form.update(Action::SubmitForm).unwrap();
        assert_eq!(submitted(&mut rx).priority, Priority::Low);
    }

    #[test]
    fn edit_prepopulates_due_and_priority() {
        let due = Date::from_calendar_date(2026, Month::March, 9)
            .unwrap()
            .midnight()
            .assume_utc();
        let item = TodoItem {
            id: "abc".to_string(),
            title: "Ship it".to_string(),
            notes: "soon".to_string(),
            due: Some(due),
            priority: Priority::High,
            done: false,
            tags: vec!["work".to_string()],
            subtasks: vec![],
            order_key: "a0".to_string(),
        };
        let form = TodoForm::edit(ListId([0u8; 16]), &item);
        assert!(form.due_enabled);
        assert_eq!(form.due_cursor, due.date());
        assert_eq!(form.priority, Priority::High);
    }
}
