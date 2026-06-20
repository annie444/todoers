use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{prelude::*, widgets::*};
use ratatui_textarea::TextArea;
use tokio::sync::mpsc::UnboundedSender;
use tracing::debug;
use unicode_width::UnicodeWidthStr;

use super::{Captures, Component};
use crate::action::Action;
use crate::config::Config;
use crate::tui::Event;

/// A single-line text input.
#[derive(Default)]
pub struct TextInput {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    /// The current contents of the field.
    text: String,
    /// Cursor position as a CHARACTER index into `text` (`0..=text.chars().count()`).
    cursor: usize,
    /// Whether the input is currently capturing keystrokes.
    capturing: bool,
    /// When set, render the contents as bullets (for passwords).
    mask: bool,
    /// Shown as the bordered block's title.
    label: String,
    /// The actual text area widget, which we use for its built-in
    /// horizontal scrolling and cursor placement logic.
    text_area: TextArea,
}

/// A normalized editing intent, decoupled from raw key events.
///
/// `map_key` turns a [`KeyEvent`] into one of these; `apply` is the only place
/// that mutates `(text, cursor)`. Remove the `allow(dead_code)` once every
/// variant is produced by `map_key` and consumed by `apply`.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edit<'a> {
    /// Insert a character at the cursor.
    Insert(char),
    /// Insert a string at the cursor (for paste events).
    String(&'a str),
    /// Delete the character before the cursor (Backspace).
    DeleteBack,
    /// Delete the character at the cursor (Delete).
    DeleteFwd,
    /// Move the cursor one character left.
    Left,
    /// Move the cursor one character right.
    Right,
    /// Move the cursor to the start of the line.
    Home,
    /// Move the cursor to the end of the line.
    End,
    /// Commit the current contents (Enter).
    Submit,
    /// Abandon capture (Esc).
    Cancel,
}

impl TextInput {
    #[tracing::instrument]
    pub fn new() -> Self {
        Self {
            label: "Input".to_string(),
            ..Default::default()
        }
    }

    /// Builder: set the block title shown above the field.
    #[tracing::instrument(skip(self))]
    pub fn label(mut self, label: impl Into<String> + std::fmt::Debug) -> Self {
        self.label = label.into();
        self
    }

    /// Builder: render the contents as bullets instead of the raw text (passwords).
    #[tracing::instrument(skip(self))]
    pub fn masked(mut self) -> Self {
        self.mask = true;
        self
    }

    /// Give this input keyboard focus: start capturing and park the cursor at the
    /// end of the existing contents. Unlike `Action::StartCapture`, this does NOT
    /// clear the text — a multi-field form keeps each field's value while focus moves.
    #[tracing::instrument(skip(self))]
    pub fn focus(&mut self) {
        self.capturing = true;
        self.cursor = self.char_count();
    }

    /// Remove keyboard focus (stop capturing) without disturbing the contents.
    #[tracing::instrument(skip(self))]
    pub fn blur(&mut self) {
        self.capturing = false;
    }

    /// The current contents of the field.
    #[tracing::instrument(skip(self))]
    pub fn value(&self) -> &str {
        &self.text
    }

    /// Number of characters currently in the field (NOT bytes).
    #[tracing::instrument(skip(self))]
    fn char_count(&self) -> usize {
        self.text.chars().count()
    }

    /// Byte offset of character index `idx`, or `text.len()` if `idx` is at/past
    /// the end. Use this to convert the character-indexed cursor into the byte
    /// index that `String::insert` / `String::remove` expect.
    #[tracing::instrument(skip(self))]
    fn byte_at(&self, idx: usize) -> usize {
        self.text
            .char_indices()
            .nth(idx)
            .map(|(b, _)| b)
            .unwrap_or(self.text.len())
    }

    /// Translate a key event into an editing intent, or `None` to ignore it.
    #[tracing::instrument]
    fn map_key<'a>(key: KeyEvent) -> Option<Edit<'a>> {
        match key.code {
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .contains(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                Some(Edit::Insert(c))
            }
            KeyCode::Backspace => Some(Edit::DeleteBack),
            KeyCode::Delete => Some(Edit::DeleteFwd),
            KeyCode::Left => Some(Edit::Left),
            KeyCode::Right => Some(Edit::Right),
            KeyCode::Home => Some(Edit::Home),
            KeyCode::End => Some(Edit::End),
            KeyCode::Enter => Some(Edit::Submit),
            KeyCode::Esc => Some(Edit::Cancel),
            _ => None,
        }
    }

    /// Apply an editing intent to `(text, cursor)` and return an [`Action`] to
    /// emit upstream, if any.
    #[tracing::instrument(skip(self))]
    fn apply(&mut self, edit: Edit) -> Option<Action> {
        match edit {
            Edit::Insert(c) => {
                let at = self.byte_at(self.cursor);
                self.text.insert(at, c);
                self.cursor += 1;
            }
            Edit::String(s) => {
                let at = self.byte_at(self.cursor);
                self.text.insert_str(at, &s);
                self.cursor += s.chars().count();
            }
            Edit::DeleteBack => {
                if self.cursor > 0 {
                    let at = self.byte_at(self.cursor - 1);
                    self.text.remove(at); // remove() takes a byte index, returns the char
                    self.cursor -= 1;
                }
            }
            Edit::DeleteFwd => {
                if self.cursor < self.char_count() {
                    let at = self.byte_at(self.cursor);
                    self.text.remove(at);
                }
            }
            Edit::Left => self.cursor = self.cursor.saturating_sub(1),
            Edit::Right => self.cursor = (self.cursor + 1).min(self.char_count()),
            Edit::Home => self.cursor = 0,
            Edit::End => self.cursor = self.char_count(),
            Edit::Submit => {
                let action = Action::SubmitInput(self.text.clone());
                self.capturing = false;
                self.text.clear();
                self.cursor = 0;
                return Some(action);
            }
            Edit::Cancel => return Some(Action::StopCapture),
        }
        None
    }
}

impl Captures for TextInput {}

impl Component for TextInput {
    #[tracing::instrument(skip(self))]
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
    fn handle_events(&mut self, event: Option<Event>) -> anyhow::Result<Option<Action>> {
        let action = match event {
            Some(Event::Key(key_event)) => self.handle_key_event(key_event)?,
            Some(Event::Mouse(mouse_event)) => self.handle_mouse_event(mouse_event)?,
            Some(Event::Paste(text)) => self.apply(Edit::String(&text)),
            _ => None,
        };
        Ok(action)
    }

    #[tracing::instrument(skip(self))]
    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        if !self.capturing {
            return Ok(None);
        }
        debug!("saw key event: {key:?}");
        Ok(Self::map_key(key).and_then(|edit| self.apply(edit)))
    }

    #[tracing::instrument(skip(self))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        match action {
            Action::StartCapture => {
                self.capturing = true;
                self.text.clear();
                self.cursor = 0;
            }
            Action::StopCapture => {
                self.capturing = false;
            }
            _ => {}
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        // Every component is handed the full frame, so carve out our own slot:
        // a single bordered row, centered.
        let [area] = Layout::vertical([Constraint::Length(3)])
            .flex(layout::Flex::Center)
            .areas(area);
        let [area] = Layout::horizontal([Constraint::Percentage(80)])
            .flex(layout::Flex::Center)
            .areas(area);

        let border_style = if self.capturing {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Gray)
        };
        let block = Block::bordered()
            .border_style(border_style)
            .title(self.label.as_str());
        let inner = block.inner(area);
        frame.render_widget(block, area);
        // Bullets are width-1, so the cursor column math below (which measures the
        // raw text) still lines up for masked fields.
        let display = if self.mask {
            "•".repeat(self.char_count())
        } else {
            self.text.clone()
        };
        frame.render_widget(Paragraph::new(display), inner);

        // Place the hardware cursor at the correct DISPLAY column. The column is
        // the rendered width of the text before the cursor — not the character
        // count — so wide glyphs (CJK, emoji) line up. (Basic version: assumes
        // the text fits; long-line horizontal scrolling is a later enhancement.)
        if self.capturing {
            let before: String = self.text.chars().take(self.cursor).collect();
            let col = UnicodeWidthStr::width(before.as_str()) as u16;
            let max_col = inner.width.saturating_sub(1);
            frame.set_cursor_position((inner.x + col.min(max_col), inner.y));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Build an input in a known state for testing `apply` in isolation.
    fn input(text: &str, cursor: usize) -> TextInput {
        TextInput {
            text: text.to_string(),
            cursor,
            capturing: true,
            ..Default::default()
        }
    }

    #[test]
    fn insert_at_cursor() {
        let mut ti = input("ac", 1);
        assert_eq!(ti.apply(Edit::Insert('b')), None);
        assert_eq!(ti.text, "abc");
        assert_eq!(ti.cursor, 2);
    }

    #[test]
    fn insert_at_end() {
        let mut ti = input("ab", 2);
        ti.apply(Edit::Insert('c'));
        assert_eq!(ti.text, "abc");
        assert_eq!(ti.cursor, 3);
    }

    #[test]
    fn delete_back_removes_char_before_cursor() {
        let mut ti = input("abc", 2);
        ti.apply(Edit::DeleteBack);
        assert_eq!(ti.text, "ac");
        assert_eq!(ti.cursor, 1);
    }

    #[test]
    fn delete_back_at_start_is_noop() {
        let mut ti = input("abc", 0);
        ti.apply(Edit::DeleteBack);
        assert_eq!(ti.text, "abc");
        assert_eq!(ti.cursor, 0);
    }

    #[test]
    fn delete_fwd_removes_char_at_cursor() {
        let mut ti = input("abc", 1);
        ti.apply(Edit::DeleteFwd);
        assert_eq!(ti.text, "ac");
        assert_eq!(ti.cursor, 1);
    }

    #[test]
    fn delete_fwd_at_end_is_noop() {
        let mut ti = input("abc", 3);
        ti.apply(Edit::DeleteFwd);
        assert_eq!(ti.text, "abc");
        assert_eq!(ti.cursor, 3);
    }

    #[test]
    fn cursor_moves_clamp_to_bounds() {
        let mut ti = input("ab", 0);
        ti.apply(Edit::Left); // already at start, stays
        assert_eq!(ti.cursor, 0);
        ti.apply(Edit::Right);
        assert_eq!(ti.cursor, 1);
        ti.apply(Edit::End);
        assert_eq!(ti.cursor, 2);
        ti.apply(Edit::Right); // already at end, stays
        assert_eq!(ti.cursor, 2);
        ti.apply(Edit::Home);
        assert_eq!(ti.cursor, 0);
    }

    /// The reason the cursor is a *character* index: byte-indexing would split
    /// or mis-count multi-byte UTF-8 here ("é" is two bytes).
    #[test]
    fn editing_is_unicode_safe() {
        let mut ti = input("café", 4); // 4 chars, 5 bytes
        ti.apply(Edit::DeleteBack); // remove 'é'
        assert_eq!(ti.text, "caf");
        assert_eq!(ti.cursor, 3);

        let mut ti = input("aé", 1); // cursor between 'a' and 'é'
        ti.apply(Edit::Insert('X'));
        assert_eq!(ti.text, "aXé");
        assert_eq!(ti.cursor, 2);
    }

    #[test]
    fn submit_emits_action_with_current_text() {
        let mut ti = input("hello", 5);
        assert_eq!(
            ti.apply(Edit::Submit),
            Some(Action::SubmitInput("hello".to_string()))
        );
    }

    #[test]
    fn cancel_stops_capture() {
        let mut ti = input("hello", 5);
        assert_eq!(ti.apply(Edit::Cancel), Some(Action::StopCapture));
    }
}
