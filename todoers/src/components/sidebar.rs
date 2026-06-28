use crossterm::event::KeyEvent;
use indexmap::IndexMap;
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;
use unicode_width::UnicodeWidthStr;

use todoers_client::model::{MetaList, ViewTarget};
use todoers_types::ListId;

use super::home::{self, Focus, HomeCmd};
use super::{Captures, Component};
use crate::action::{Action, DeleteTarget};
use crate::config::{Config, IconType, KeyContext, compile_keymap, parse_command};
use crate::view::SharedView;

const LIST_ICON_NF: char = '\u{f0ca}';
const LIST_ICON_UTF: char = '📋';
const LIST_ICON_BASIC: char = 'L';

/// Sidebar of meta-lists + user lists. Reads all data from the
/// shared [`crate::view::ViewModel`]; it never touches the store
/// directly — it emits intent [`Action`]s that `App` fulfills, and mutates only
/// the pure-UI bits of the view-model (pane layout) itself.
pub struct Sidebar {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    view: SharedView,
    icon: ListIcon,
    focus: Focus,
    sidebar_visible: bool,
    /// Selection index into the sidebar (meta-lists first, then user lists).
    sidebar_idx: usize,
    /// Compiled `[keybindings.home]` map + the multi-key sequence buffer.
    keymap: IndexMap<Vec<KeyEvent>, HomeCmd>,
    /// Footer hint lines, derived from the live bindings. Rebuilt only when the
    /// keymap changes (`register_config_handler`) so `draw` never reformats them
    /// per frame — it just borrows the cached strings.
    layout_hint: String,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListIcon(char);

impl std::fmt::Display for ListIcon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<char> for ListIcon {
    fn from(c: char) -> Self {
        Self(c)
    }
}

impl ListIcon {
    pub fn nf() -> Self {
        Self(LIST_ICON_NF)
    }
    pub fn utf() -> Self {
        Self(LIST_ICON_UTF)
    }
    pub fn basic() -> Self {
        Self(LIST_ICON_BASIC)
    }
}

impl Sidebar {
    #[tracing::instrument(skip(view))]
    pub fn new(view: SharedView) -> Self {
        Self {
            command_tx: None,
            config: Config::default(),
            view,
            icon: ListIcon::nf(),
            focus: Focus::default(),
            sidebar_visible: true,
            sidebar_idx: 0,
            keymap: IndexMap::new(),
            layout_hint: String::new(),
        }
    }

    fn send(&self, action: Action) {
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(action);
        }
    }

    /// Number of selectable sidebar rows = fixed meta-lists + user lists.
    fn sidebar_len(&self) -> usize {
        MetaList::all().len() + self.view.borrow().lists.len()
    }

    /// Resolve a sidebar row index to a view target.
    fn target_at(&self, idx: usize) -> Option<ViewTarget> {
        let metas = MetaList::all();
        if idx < metas.len() {
            Some(ViewTarget::Meta(metas[idx]))
        } else {
            self.view
                .borrow()
                .lists
                .get(idx - metas.len())
                .map(|l| ViewTarget::List(l.id))
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if matches!(self.focus, Focus::Sidebar) {
            let len = self.sidebar_len();
            if len == 0 {
                return;
            }
            let cur = self.sidebar_idx.min(len - 1) as isize;
            self.sidebar_idx = (cur + delta).rem_euclid(len as isize) as usize;
        }
    }

    /// The sidebar-selected *user* list (None when a meta-list row is selected).
    fn selected_user_list(&self) -> Option<(ListId, String)> {
        let metas = MetaList::all().len();
        if self.sidebar_idx < metas {
            return None;
        }
        self.view
            .borrow()
            .lists
            .get(self.sidebar_idx - metas)
            .map(|l| (l.id, l.name.clone()))
    }

    /// The list a list-level command (share/members) targets: the sidebar
    /// selection when the sidebar has focus, else the active pane's list.
    fn command_list(&self) -> Option<ListId> {
        if matches!(self.focus, Focus::Sidebar) {
            return self.selected_user_list().map(|(id, _)| id);
        }
        None
    }

    /// Run a resolved [`HomeCmd`] against the current focus/selection. Layout and
    /// focus verbs mutate local view state; command verbs build the same intent
    /// [`Action`]s the app already fulfills and emit them on the action channel.
    fn execute(&mut self, cmd: HomeCmd) {
        use HomeCmd as Hc;
        match cmd {
            Hc::FocusSidebar => self.focus = Focus::Sidebar,
            Hc::FocusPane => self.focus = Focus::Pane,
            Hc::SelectNext => self.move_selection(1),
            Hc::SelectPrev => self.move_selection(-1),
            Hc::Share => {
                if let Some(action) = self.command_list().map(Action::ShareModal) {
                    self.send(action);
                }
            }
            Hc::Members => {
                if let Some(action) = self.command_list().map(Action::MembersModal) {
                    self.send(action);
                }
            }
            Hc::Rename => {
                if let Some((list_id, name)) = self.selected_user_list() {
                    self.send(Action::RenameListModal { list_id, name });
                }
            }
            Hc::Delete if matches!(self.focus, Focus::Sidebar) => {
                if let Some((id, _)) = self.selected_user_list() {
                    self.send(Action::ConfirmDelete(DeleteTarget::List(id)));
                }
            }
            _ => { /* other commands are handled by the active pane */ }
        }
    }

    // ── rendering ──────────────────────────────────────────────────────────────

    /// Build a ` key:label key:label ` hint line from the live bindings, skipping
    /// any command the user has left unbound.
    fn hint(&self, items: &[(HomeCmd, &str)]) -> String {
        let parts: Vec<String> = items
            .iter()
            .filter_map(|(verb, label)| {
                crate::config::first_key_for(&self.keymap, verb).map(|k| format!("{k}:{label}"))
            })
            .collect();
        format!(" {} ", parts.join(" "))
    }

    /// Rebuild the cached footer hints from the current bindings. Called whenever
    /// the keymap changes (`register_config_handler`); `draw` only reads the cache.
    /// `layout_hint` is the sidebar's split/stack/cycle/close line; `command_hint`
    /// is the todo pane's command line.
    fn rebuild_hints(&mut self) {
        self.layout_hint = self.hint(&[
            (HomeCmd::SplitHorizontal, "split"),
            (HomeCmd::SplitVertical, "stack"),
            (HomeCmd::CyclePane, "pane"),
            (HomeCmd::ClosePane, "close"),
        ]);
    }
}

impl Captures for Sidebar {}

impl Component for Sidebar {
    #[tracing::instrument(skip(self, tx))]
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.command_tx = Some(tx);
        Ok(())
    }

    #[tracing::instrument(skip(self, config))]
    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        self.config = config;
        self.icon = match self.config.config.icon_type {
            IconType::NerdFonts => ListIcon::nf(),
            IconType::Emojis => ListIcon::utf(),
            IconType::Basic => ListIcon::basic(),
        };
        self.keymap = compile_keymap(
            self.config.keybindings.context(KeyContext::Home),
            parse_command::<HomeCmd>,
        );
        // The footer hints derive from the (now-updated) keymap; cache them so the
        // per-frame `draw` only borrows them.
        self.rebuild_hints();
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        if matches!(action, Action::ToggleSidebar) {
            self.sidebar_visible = !self.sidebar_visible;
            if !self.sidebar_visible {
                self.focus = Focus::Pane;
            }
        }
        Ok(None)
    }

    fn placement(&self) -> Constraint {
        let length = if self.sidebar_visible {
            let layout_width: u16 = TryInto::<u16>::try_into(self.layout_hint.width())
                .map(|l| l.saturating_add(2))
                .unwrap_or(u16::MAX);
            let max_list_width: u16 = self
                .view
                .borrow()
                .lists
                .iter()
                .map(|l| {
                    TryInto::<u16>::try_into(l.name.width())
                        .map(|l| l.saturating_add(4))
                        .unwrap_or(u16::MAX)
                })
                .max()
                .unwrap_or(u16::MIN);
            let calc_width = layout_width.max(max_list_width);
            calc_width.min(50)
        } else {
            0
        };
        Constraint::Length(length)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        if self.sidebar_visible {
            let view = self.view.borrow();
            let mut rows: Vec<ListItem> = Vec::with_capacity(self.sidebar_len());
            for m in MetaList::all() {
                rows.push(
                    ListItem::new(format!(" ★ {}", m.label())).style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::ITALIC),
                    ),
                );
            }
            for l in &view.lists {
                let badge = if l.open_count > 0 {
                    format!(" ({})", l.open_count)
                } else {
                    String::new()
                };
                rows.push(ListItem::new(format!(" {} {}{}", self.icon, l.name, badge)));
            }

            let focused = self.focus == Focus::Sidebar;
            let block = Block::default()
                .title("Lists")
                .title_bottom(Line::from(self.layout_hint.as_str()).right_aligned())
                .borders(Borders::ALL)
                .border_style(home::border_style(focused));
            let list = List::new(rows)
                .block(block)
                .highlight_style(home::highlight_style(focused))
                .highlight_symbol("▌");
            let mut state = ListState::default();
            state.select(Some(
                self.sidebar_idx.min(self.sidebar_len().saturating_sub(1)),
            ));
            frame.render_stateful_widget(list, area, &mut state);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use pretty_assertions::assert_eq;

    /// The on-screen hints are derived from the live bindings and, with defaults,
    /// reproduce the original hardcoded strings.
    #[test]
    fn hints_derive_from_default_bindings() {
        let mut sidebar = Sidebar::new(SharedView::default());
        sidebar.register_config_handler(Config::defaults()).unwrap();
        assert_eq!(sidebar.layout_hint, " |:split -:stack w:pane X:close ");
    }

    /// A rebound key takes effect: map `a` to `new_list` and it now emits the new
    /// list action instead of add-todo.
    #[test]
    fn rebinding_a_key_changes_the_hints() {
        let mut cfg = Config::defaults();
        cfg.keybindings
            .0
            .get_mut(&KeyContext::Home)
            .unwrap()
            .insert(
                crate::config::parse_key_sequence("a").unwrap(),
                crate::config::CommandSpec::Bare("split".into()),
            );

        let mut sidebar = Sidebar::new(SharedView::default());
        sidebar.register_config_handler(cfg).unwrap();

        assert_eq!(sidebar.layout_hint, " a:split -:stack w:pane X:close ");
    }
}
