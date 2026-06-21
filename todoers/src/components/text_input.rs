use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{prelude::*, widgets::*};
use ratatui_textarea::{CursorMove, Input, Key, TextArea};
use tokio::sync::mpsc::UnboundedSender;
use tracing::debug;

use super::{Captures, Component};
use crate::action::Action;
use crate::config::{Config, EditingMode};
use crate::tui::Event;

/// Character used to mask password fields.
const MASK_CHAR: char = '•';

/// A single-line text input backed by [`ratatui_textarea::TextArea`].
///
/// The widget does all of the editing, cursor placement, and horizontal
/// scrolling. We only choose *which* key bindings drive it: in
/// [`EditingMode::Emacs`] keys are handed straight to [`TextArea::input`] (which
/// ships a full emacs keymap); in [`EditingMode::Vim`] they run through a small
/// modal [`VimState`] machine layered on [`TextArea::input_without_shortcuts`].
#[derive(Default)]
pub struct TextInput {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    /// Whether the input is currently capturing keystrokes.
    capturing: bool,
    /// When set, render the contents as bullets (for passwords).
    mask: bool,
    /// Shown as the bordered block's title.
    label: String,
    /// The editing widget; owns the text buffer and cursor.
    text_area: TextArea<'static>,
    /// Vim modal-editing state. Only consulted in [`EditingMode::Vim`].
    vim: VimState,
}

/// A user-facing label for a focused field's editing mode, surfaced in the
/// status footer (lualine-style). Only produced for fields in [`EditingMode::Vim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditorMode {
    Normal,
    Insert,
    Visual,
    /// An operator (`d`/`c`/`y`) is waiting for a motion.
    OperatorPending,
}

impl EditorMode {
    /// Short uppercase label, e.g. `"NORMAL"`.
    pub fn label(self) -> &'static str {
        match self {
            EditorMode::Normal => "NORMAL",
            EditorMode::Insert => "INSERT",
            EditorMode::Visual => "VISUAL",
            EditorMode::OperatorPending => "O-PENDING",
        }
    }
}

/// The current Vim sub-mode of a field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum VimMode {
    /// Motions and operators; `i`/`a`/… switch to [`VimMode::Insert`].
    #[default]
    Normal,
    /// Plain text entry; `Esc` returns to [`VimMode::Normal`].
    Insert,
    /// A selection is active; motions extend it, `d`/`c`/`y` operate on it.
    Visual,
    /// An operator (`d`/`c`/`y`) was pressed and is waiting for a motion.
    Operator(char),
}

/// Minimal modal-editing state machine for a single-line [`TextArea`].
#[derive(Debug, Default)]
struct VimState {
    mode: VimMode,
    /// Accumulates a numeric count prefix (e.g. the `2` in `2dw`).
    count: Option<usize>,
}

impl VimState {
    /// Drive the textarea from one key. Returns an [`Action`] to emit upstream,
    /// if any (currently always `None` — submit is owned by the parent form).
    fn on_key(&mut self, ta: &mut TextArea<'static>, input: Input) -> Option<Action> {
        match self.mode {
            VimMode::Insert => self.insert_key(ta, input),
            VimMode::Normal => self.normal_key(ta, input),
            VimMode::Visual => self.visual_key(ta, input),
            VimMode::Operator(op) => self.operator_key(ta, op, input),
        }
    }

    /// In Insert mode every key edits, except `Esc`/`Ctrl-C` which leave to Normal
    /// (Vim parks the cursor one column left on exit).
    fn insert_key(&mut self, ta: &mut TextArea<'static>, input: Input) -> Option<Action> {
        if input.key == Key::Esc || (input.ctrl && input.key == Key::Char('c')) {
            self.mode = VimMode::Normal;
            ta.move_cursor(CursorMove::Back);
            return None;
        }
        ta.input_without_shortcuts(input);
        None
    }

    /// Normalize a key into the `char` command Vim thinks in (arrows alias to hjkl,
    /// Home/End to `0`/`$`, etc.). Returns `None` for keys Vim ignores.
    fn command_char(input: Input) -> Option<char> {
        Some(match input.key {
            Key::Char(c) => c,
            Key::Left | Key::Backspace => 'h',
            Key::Right => 'l',
            Key::Up => 'k',
            Key::Down => 'j',
            Key::Home => '0',
            Key::End => '$',
            Key::Delete => 'x',
            _ => return None,
        })
    }

    fn normal_key(&mut self, ta: &mut TextArea<'static>, input: Input) -> Option<Action> {
        // Ctrl-R = redo (the only Ctrl chord we honor in Normal mode).
        if input.ctrl && input.key == Key::Char('r') {
            ta.redo();
            self.count = None;
            return None;
        }
        let Some(c) = Self::command_char(input) else {
            self.count = None;
            return None;
        };

        // Count prefix: any digit, plus `0` once a count is already in progress.
        if c.is_ascii_digit() && (c != '0' || self.count.is_some()) {
            let d = c.to_digit(10).unwrap() as usize;
            self.count = Some(self.count.unwrap_or(0) * 10 + d);
            return None;
        }
        let n = self.count.take().unwrap_or(1);

        match c {
            'h' => repeat(n, || ta.move_cursor(CursorMove::Back)),
            'l' => repeat(n, || ta.move_cursor(CursorMove::Forward)),
            'j' => repeat(n, || ta.move_cursor(CursorMove::Down)),
            'k' => repeat(n, || ta.move_cursor(CursorMove::Up)),
            'w' => repeat(n, || ta.move_cursor(CursorMove::WordForward)),
            'e' => repeat(n, || ta.move_cursor(CursorMove::WordEnd)),
            'b' => repeat(n, || ta.move_cursor(CursorMove::WordBack)),
            '0' | '^' => ta.move_cursor(CursorMove::Head),
            '$' => ta.move_cursor(CursorMove::End),
            'i' => self.mode = VimMode::Insert,
            'I' => {
                ta.move_cursor(CursorMove::Head);
                self.mode = VimMode::Insert;
            }
            'a' => {
                ta.move_cursor(CursorMove::Forward);
                self.mode = VimMode::Insert;
            }
            // `A`, and `o`/`O` on a single line, all open insert at end of line.
            'A' | 'o' | 'O' => {
                ta.move_cursor(CursorMove::End);
                self.mode = VimMode::Insert;
            }
            'x' => repeat(n, || {
                ta.delete_next_char();
            }),
            'D' => {
                ta.delete_line_by_end();
            }
            'C' => {
                ta.delete_line_by_end();
                self.mode = VimMode::Insert;
            }
            's' => {
                ta.delete_next_char();
                self.mode = VimMode::Insert;
            }
            'p' | 'P' => {
                ta.paste();
            }
            'u' => {
                ta.undo();
            }
            'v' => {
                ta.start_selection();
                self.mode = VimMode::Visual;
            }
            'd' | 'c' | 'y' => self.mode = VimMode::Operator(c),
            _ => {}
        }
        None
    }

    fn visual_key(&mut self, ta: &mut TextArea<'static>, input: Input) -> Option<Action> {
        if input.key == Key::Esc {
            ta.cancel_selection();
            self.mode = VimMode::Normal;
            return None;
        }
        let c = Self::command_char(input)?;
        if c.is_ascii_digit() && (c != '0' || self.count.is_some()) {
            let d = c.to_digit(10).unwrap() as usize;
            self.count = Some(self.count.unwrap_or(0) * 10 + d);
            return None;
        }
        let n = self.count.take().unwrap_or(1);
        match c {
            'h' => repeat(n, || ta.move_cursor(CursorMove::Back)),
            'l' => repeat(n, || ta.move_cursor(CursorMove::Forward)),
            'w' => repeat(n, || ta.move_cursor(CursorMove::WordForward)),
            'e' => repeat(n, || ta.move_cursor(CursorMove::WordEnd)),
            'b' => repeat(n, || ta.move_cursor(CursorMove::WordBack)),
            '0' | '^' => ta.move_cursor(CursorMove::Head),
            '$' => ta.move_cursor(CursorMove::End),
            'd' | 'x' => {
                ta.cut();
                self.mode = VimMode::Normal;
            }
            'c' => {
                ta.cut();
                self.mode = VimMode::Insert;
            }
            'y' => {
                ta.copy();
                ta.cancel_selection();
                self.mode = VimMode::Normal;
            }
            'v' => {
                ta.cancel_selection();
                self.mode = VimMode::Normal;
            }
            _ => {}
        }
        None
    }

    fn operator_key(
        &mut self,
        ta: &mut TextArea<'static>,
        op: char,
        input: Input,
    ) -> Option<Action> {
        if input.key == Key::Esc {
            self.mode = VimMode::Normal;
            self.count = None;
            return None;
        }
        let Some(c) = Self::command_char(input) else {
            self.mode = VimMode::Normal;
            self.count = None;
            return None;
        };
        let n = self.count.take().unwrap_or(1);

        // Doubled operator (`dd`/`cc`/`yy`) acts on the whole line.
        if c == op {
            ta.move_cursor(CursorMove::Head);
            ta.start_selection();
            ta.move_cursor(CursorMove::End);
            self.finish_operator(ta, op);
            return None;
        }

        // Operator + motion: select across the motion, then apply.
        ta.start_selection();
        let moved = match c {
            'w' => {
                repeat(n, || ta.move_cursor(CursorMove::WordForward));
                true
            }
            'e' => {
                repeat(n, || ta.move_cursor(CursorMove::WordEnd));
                true
            }
            'b' => {
                repeat(n, || ta.move_cursor(CursorMove::WordBack));
                true
            }
            'h' => {
                repeat(n, || ta.move_cursor(CursorMove::Back));
                true
            }
            'l' => {
                repeat(n, || ta.move_cursor(CursorMove::Forward));
                true
            }
            '0' | '^' => {
                ta.move_cursor(CursorMove::Head);
                true
            }
            '$' => {
                ta.move_cursor(CursorMove::End);
                true
            }
            _ => false,
        };
        if moved {
            self.finish_operator(ta, op);
        } else {
            ta.cancel_selection();
            self.mode = VimMode::Normal;
        }
        None
    }

    /// Apply the pending operator to the active selection and set the next mode.
    fn finish_operator(&mut self, ta: &mut TextArea<'static>, op: char) {
        match op {
            'd' => {
                ta.cut();
                self.mode = VimMode::Normal;
            }
            'c' => {
                ta.cut();
                self.mode = VimMode::Insert;
            }
            'y' => {
                ta.copy();
                ta.cancel_selection();
                self.mode = VimMode::Normal;
            }
            _ => self.mode = VimMode::Normal,
        }
    }
}

/// Run `f` `n` times (vim count prefix on a motion/edit).
fn repeat(n: usize, mut f: impl FnMut()) {
    for _ in 0..n {
        f();
    }
}

/// Convert a crossterm [`KeyEvent`] into a backend-agnostic [`Input`].
///
/// Built by hand rather than via `Input::from` so it is decoupled from whichever
/// crossterm version `ratatui-textarea` links against.
fn to_input(key: KeyEvent) -> Input {
    let k = match key.code {
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Enter => Key::Enter,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Tab => Key::Tab,
        KeyCode::Delete => Key::Delete,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Esc => Key::Esc,
        KeyCode::F(n) => Key::F(n),
        _ => Key::Null,
    };
    Input {
        key: k,
        ctrl: key.modifiers.contains(KeyModifiers::CONTROL),
        alt: key.modifiers.contains(KeyModifiers::ALT),
        shift: key.modifiers.contains(KeyModifiers::SHIFT),
    }
}

/// Build a fresh, empty textarea, applying the mask char for password fields.
fn build_textarea(mask: bool) -> TextArea<'static> {
    let mut ta = TextArea::default();
    if mask {
        ta.set_mask_char(MASK_CHAR);
    }
    ta
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
        self.text_area.set_mask_char(MASK_CHAR);
        self
    }

    /// The current Vim sub-mode (Normal by default / in Emacs mode).
    fn editing_mode(&self) -> EditingMode {
        self.config.config.editing_mode
    }

    /// Give this input keyboard focus: start capturing, park the cursor at the end
    /// of the existing contents, and (in Vim) reset to Normal mode. Unlike
    /// `Action::StartCapture`, this does NOT clear the text — a multi-field form
    /// keeps each field's value while focus moves between them.
    #[tracing::instrument(skip(self))]
    pub fn focus(&mut self) {
        self.capturing = true;
        self.text_area.move_cursor(CursorMove::End);
        self.vim = VimState::default();
    }

    /// Remove keyboard focus (stop capturing) without disturbing the contents.
    #[tracing::instrument(skip(self))]
    pub fn blur(&mut self) {
        self.capturing = false;
    }

    /// The current contents of the field. (Single-line, so the lines join to one.)
    #[tracing::instrument(skip(self))]
    pub fn value(&self) -> String {
        self.text_area.lines().join("")
    }

    /// Replace the contents (e.g. to pre-fill an edit/rename form). Resets the
    /// buffer to the given single-line value with the cursor at the end.
    #[tracing::instrument(skip(self))]
    pub fn set_value(&mut self, value: &str) {
        let mut ta = build_textarea(self.mask);
        ta.insert_str(value);
        self.text_area = ta;
        self.vim = VimState::default();
    }

    /// Clear the buffer and reset Vim state (used when capture (re)starts).
    fn reset(&mut self) {
        self.text_area = build_textarea(self.mask);
        self.vim = VimState::default();
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
            Some(Event::Paste(text)) => {
                if self.capturing {
                    self.text_area.insert_str(&text);
                }
                None
            }
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
        let input = to_input(key);
        match self.editing_mode() {
            EditingMode::Emacs => {
                self.text_area.input(input);
                Ok(None)
            }
            EditingMode::Vim => Ok(self.vim.on_key(&mut self.text_area, input)),
        }
    }

    /// In Vim mode, an `Esc` pressed while *not* in Normal mode is consumed to
    /// return to Normal — so it must not also close the surrounding modal/form.
    #[tracing::instrument(skip(self))]
    fn consumes_escape(&self) -> bool {
        self.editing_mode() == EditingMode::Vim && self.vim.mode != VimMode::Normal
    }

    /// The Vim sub-mode label to show in the footer, or `None` when the field is
    /// not a focused Vim field (Emacs mode or not capturing).
    #[tracing::instrument(skip(self))]
    fn editor_mode(&self) -> Option<EditorMode> {
        if self.editing_mode() != EditingMode::Vim || !self.capturing {
            return None;
        }
        Some(match self.vim.mode {
            VimMode::Normal => EditorMode::Normal,
            VimMode::Insert => EditorMode::Insert,
            VimMode::Visual => EditorMode::Visual,
            VimMode::Operator(_) => EditorMode::OperatorPending,
        })
    }

    #[tracing::instrument(skip(self))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        match action {
            Action::StartCapture => {
                self.capturing = true;
                self.reset();
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

        // The cursor is a styled cell rendered by the widget itself: a reversed
        // block while editing, a distinct color in Vim Normal/Visual mode, and
        // hidden (no highlight) when the field is not focused.
        let cursor_style = if !self.capturing {
            Style::default()
        } else if self.editing_mode() == EditingMode::Vim && self.vim.mode != VimMode::Insert {
            Style::default().fg(Color::Black).bg(Color::Green)
        } else {
            Style::default().add_modifier(Modifier::REVERSED)
        };
        self.text_area.set_cursor_style(cursor_style);
        frame.render_widget(&self.text_area, inner);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use pretty_assertions::assert_eq;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    fn ch(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty())
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    /// An Emacs-mode input, focused and ready to type.
    fn emacs() -> TextInput {
        let mut ti = TextInput::new();
        ti.capturing = true;
        ti
    }

    /// A Vim-mode input, focused and starting in Normal mode.
    fn vim() -> TextInput {
        let mut ti = TextInput::new();
        ti.config.config.editing_mode = EditingMode::Vim;
        ti.capturing = true;
        ti
    }

    fn typed(ti: &mut TextInput, s: &str) {
        for c in s.chars() {
            ti.handle_key_event(ch(c)).unwrap();
        }
    }

    #[test]
    fn emacs_typing_inserts_text() {
        let mut ti = emacs();
        typed(&mut ti, "hello");
        assert_eq!(ti.value(), "hello");
    }

    #[test]
    fn emacs_backspace_deletes_before_cursor() {
        let mut ti = emacs();
        typed(&mut ti, "abc");
        ti.handle_key_event(key(KeyCode::Backspace)).unwrap();
        assert_eq!(ti.value(), "ab");
    }

    /// Ctrl-A jumps to the head, so the next insert lands at the start.
    #[test]
    fn emacs_ctrl_a_moves_to_head() {
        let mut ti = emacs();
        typed(&mut ti, "abc");
        ti.handle_key_event(ctrl('a')).unwrap();
        typed(&mut ti, "X");
        assert_eq!(ti.value(), "Xabc");
    }

    /// Ctrl-E returns to the end; Ctrl-K kills to end of line.
    #[test]
    fn emacs_ctrl_k_kills_to_end() {
        let mut ti = emacs();
        typed(&mut ti, "abcdef");
        ti.handle_key_event(ctrl('a')).unwrap();
        ti.handle_key_event(key(KeyCode::Right)).unwrap();
        ti.handle_key_event(key(KeyCode::Right)).unwrap();
        ti.handle_key_event(ctrl('k')).unwrap();
        assert_eq!(ti.value(), "ab");
    }

    /// Editing is Unicode-safe: multibyte glyphs are deleted whole.
    #[test]
    fn emacs_editing_is_unicode_safe() {
        let mut ti = emacs();
        typed(&mut ti, "café");
        ti.handle_key_event(key(KeyCode::Backspace)).unwrap();
        assert_eq!(ti.value(), "caf");
    }

    /// Without `i`, Vim Normal mode ignores typed letters as commands.
    #[test]
    fn vim_normal_does_not_insert() {
        let mut ti = vim();
        typed(&mut ti, "hello");
        assert_eq!(ti.value(), "");
    }

    /// `i` enters Insert mode; subsequent keys type; `Esc` returns to Normal.
    #[test]
    fn vim_insert_then_escape() {
        let mut ti = vim();
        assert!(!ti.consumes_escape());
        ti.handle_key_event(ch('i')).unwrap();
        assert!(ti.consumes_escape(), "Insert mode must swallow Esc");
        typed(&mut ti, "hi");
        assert_eq!(ti.value(), "hi");
        ti.handle_key_event(key(KeyCode::Esc)).unwrap();
        assert!(!ti.consumes_escape(), "back in Normal mode, Esc bubbles up");
        assert_eq!(ti.vim.mode, VimMode::Normal);
    }

    /// `x` deletes the char under the cursor in Normal mode.
    #[test]
    fn vim_x_deletes_char() {
        let mut ti = vim();
        ti.handle_key_event(ch('i')).unwrap();
        typed(&mut ti, "abc");
        ti.handle_key_event(key(KeyCode::Esc)).unwrap(); // cursor parks on 'c'
        ti.handle_key_event(ch('0')).unwrap(); // back to head ('a')
        ti.handle_key_event(ch('x')).unwrap();
        assert_eq!(ti.value(), "bc");
    }

    /// `dd` clears the (single) line.
    #[test]
    fn vim_dd_clears_line() {
        let mut ti = vim();
        ti.handle_key_event(ch('i')).unwrap();
        typed(&mut ti, "delete me");
        ti.handle_key_event(key(KeyCode::Esc)).unwrap();
        ti.handle_key_event(ch('d')).unwrap();
        ti.handle_key_event(ch('d')).unwrap();
        assert_eq!(ti.value(), "");
    }

    /// `A` appends at end of line: enters insert mode with the cursor past the text.
    #[test]
    fn vim_append_at_end() {
        let mut ti = vim();
        ti.handle_key_event(ch('i')).unwrap();
        typed(&mut ti, "ab");
        ti.handle_key_event(key(KeyCode::Esc)).unwrap();
        ti.handle_key_event(ch('0')).unwrap();
        ti.handle_key_event(ch('A')).unwrap();
        typed(&mut ti, "cd");
        assert_eq!(ti.value(), "abcd");
    }
}
