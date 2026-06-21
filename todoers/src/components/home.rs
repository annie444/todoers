use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;

use todoers_types::ListId;

use super::{Captures, Component};
use crate::action::{Action, DeleteTarget};
use crate::config::Config;
use crate::model::{MetaList, Priority, ViewTarget};
use crate::store::SharedView;

const LIST_ICON_NF: char = '\u{f0ca}';
const LIST_ICON_UTF: char = '📋';
const LIST_ICON_BASIC: char = 'L';

/// Which panel currently has keyboard focus (two-pane model: Tab/h/l switch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Sidebar,
    Pane,
}

/// The single-screen workspace: a sidebar of meta-lists + user lists beside a
/// main pane showing the selected list's todo items. Reads all of its data from
/// the shared [`ViewModel`](crate::store::ViewModel); it never touches the store
/// directly — it emits intent [`Action`]s that `App` fulfills.
pub struct Home {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    view: SharedView,
    icon: ListIcon,
    focus: Focus,
    sidebar_visible: bool,
    /// Selection index into the sidebar (meta-lists first, then user lists).
    sidebar_idx: usize,
    /// Selection index into the current pane's items.
    pane_idx: usize,
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

impl Default for Home {
    fn default() -> Self {
        Self::new(SharedView::default())
    }
}

impl Home {
    #[tracing::instrument(skip(view))]
    pub fn new(view: SharedView) -> Self {
        Self {
            command_tx: None,
            config: Config::default(),
            view,
            icon: ListIcon::utf(),
            focus: Focus::default(),
            sidebar_visible: true,
            sidebar_idx: 0,
            pane_idx: 0,
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
        let len = match self.focus {
            Focus::Sidebar => self.sidebar_len(),
            Focus::Pane => self.view.borrow().items.len(),
        };
        if len == 0 {
            return;
        }
        let slot = match self.focus {
            Focus::Sidebar => &mut self.sidebar_idx,
            Focus::Pane => &mut self.pane_idx,
        };
        let cur = (*slot).min(len - 1) as isize;
        *slot = (cur + delta).rem_euclid(len as isize) as usize;
    }

    /// Open the sidebar-selected target in the main pane and move focus to it.
    fn open_selected(&mut self) {
        if let Some(target) = self.target_at(self.sidebar_idx) {
            self.pane_idx = 0;
            self.focus = Focus::Pane;
            self.send(Action::OpenView(target));
        }
    }

    /// The `(list_id, item_id)` of the pane's selected item, if any.
    fn selected_item(&self) -> Option<(ListId, String)> {
        self.view
            .borrow()
            .items
            .get(self.pane_idx)
            .map(|(lid, it)| (*lid, it.id.clone()))
    }

    /// The list currently shown in the pane (None for a meta-list view).
    fn current_list(&self) -> Option<ListId> {
        match self.view.borrow().current {
            Some(ViewTarget::List(id)) => Some(id),
            _ => None,
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

    /// Map a command key to an intent action, given current focus/selection.
    /// Returns `None` for keys this view doesn't act on.
    fn command(&self, c: char) -> Option<Action> {
        match c {
            // New list works from anywhere.
            'n' => Some(Action::NewListModal),
            // Add a todo to the list shown in the pane (not in meta-list views).
            'a' => self.current_list().map(Action::AddTodoModal),
            // Edit / toggle the selected item (pane focus).
            'e' if self.focus == Focus::Pane => self
                .selected_item()
                .map(|(list_id, item_id)| Action::EditTodoModal { list_id, item_id }),
            'x' if self.focus == Focus::Pane => self
                .selected_item()
                .map(|(list_id, item_id)| Action::ToggleDone { list_id, item_id }),
            // Rename the sidebar-selected user list.
            'R' => self
                .selected_user_list()
                .map(|(list_id, name)| Action::RenameListModal { list_id, name }),
            // Delete: a sidebar user list, or the selected todo in the pane.
            'd' => match self.focus {
                Focus::Sidebar => self
                    .selected_user_list()
                    .map(|(id, _)| Action::ConfirmDelete(DeleteTarget::List(id))),
                Focus::Pane => self.selected_item().map(|(list_id, item_id)| {
                    Action::ConfirmDelete(DeleteTarget::Todo { list_id, item_id })
                }),
            },
            _ => None,
        }
    }

    // ── rendering ──────────────────────────────────────────────────────────────

    fn draw_sidebar(&self, frame: &mut Frame, area: Rect) {
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
            .borders(Borders::ALL)
            .border_style(border_style(focused));
        let list = List::new(rows)
            .block(block)
            .highlight_style(highlight_style(focused))
            .highlight_symbol("▌");
        let mut state = ListState::default();
        state.select(Some(
            self.sidebar_idx.min(self.sidebar_len().saturating_sub(1)),
        ));
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn draw_pane(&self, frame: &mut Frame, area: Rect) {
        let view = self.view.borrow();
        let title = match view.current {
            Some(ViewTarget::Meta(m)) => m.label().to_string(),
            Some(ViewTarget::List(_)) => view
                .lists
                .iter()
                .find(|l| Some(ViewTarget::List(l.id)) == view.current)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| "List".into()),
            None => "Todoers".into(),
        };
        let focused = self.focus == Focus::Pane;

        let header = Row::new(["", "!", "Task", "Due"])
            .style(Style::default().add_modifier(Modifier::BOLD | Modifier::DIM));
        let rows = view.items.iter().map(|(_, it)| {
            let check = if it.done { "✓" } else { " " };
            let due = it.due.map(|d| d.date().to_string()).unwrap_or_default();
            let title_style = if it.done {
                Style::default()
                    .add_modifier(Modifier::CROSSED_OUT)
                    .fg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(check),
                Cell::from(it.priority.label()).style(priority_style(it.priority)),
                Cell::from(it.title.clone()).style(title_style),
                Cell::from(due).style(Style::default().fg(Color::DarkGray)),
            ])
        });
        let widths = [
            Constraint::Length(1),
            Constraint::Length(4),
            Constraint::Fill(1),
            Constraint::Length(12),
        ];
        let block = Block::default()
            .title(title)
            .title_bottom(Line::from(" n:new  a:add  e:edit  x:done  d:del  Tab:switch ").right_aligned())
            .borders(Borders::ALL)
            .border_style(border_style(focused));
        let table = Table::new(rows, widths)
            .header(header)
            .block(block)
            .row_highlight_style(highlight_style(focused))
            .highlight_symbol("▌");
        let mut state = TableState::default();
        if !view.items.is_empty() {
            state.select(Some(self.pane_idx.min(view.items.len() - 1)));
        }
        frame.render_stateful_widget(table, area, &mut state);
    }
}

fn border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn highlight_style(focused: bool) -> Style {
    if focused {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::DIM)
    }
}

fn priority_style(p: Priority) -> Style {
    match p {
        Priority::High => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Priority::Med => Style::default().fg(Color::Yellow),
        Priority::Low => Style::default().fg(Color::Blue),
        Priority::None => Style::default().fg(Color::DarkGray),
    }
}

impl Captures for Home {}

impl Component for Home {
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
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Sidebar => Focus::Pane,
                    Focus::Pane => Focus::Sidebar,
                };
            }
            KeyCode::Char('h') | KeyCode::Left => self.focus = Focus::Sidebar,
            KeyCode::Char('l') | KeyCode::Right => self.focus = Focus::Pane,
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Enter => {
                if self.focus == Focus::Sidebar {
                    self.open_selected();
                }
            }
            KeyCode::Char(c) => {
                if let Some(action) = self.command(c) {
                    self.send(action);
                }
            }
            _ => {}
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        if let Action::ToggleSidebar = action {
            self.sidebar_visible = !self.sidebar_visible;
            if !self.sidebar_visible {
                self.focus = Focus::Pane;
            }
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        if self.sidebar_visible {
            let [sidebar, pane] =
                Layout::horizontal([Constraint::Length(28), Constraint::Fill(1)]).areas(area);
            self.draw_sidebar(frame, sidebar);
            self.draw_pane(frame, pane);
        } else {
            self.draw_pane(frame, area);
        }
        Ok(())
    }
}
