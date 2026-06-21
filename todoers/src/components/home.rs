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

/// Which panel currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Focus {
    #[default]
    Sidebar,
    Pane,
}

/// The single-screen workspace: a sidebar of meta-lists + user lists beside one
/// or two todo panes (split side-by-side or stacked). Reads all data from the
/// shared [`ViewModel`](crate::store::ViewModel); it never touches the store
/// directly — it emits intent [`Action`]s that `App` fulfills, and mutates only
/// the pure-UI bits of the view-model (pane layout) itself.
pub struct Home {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    view: SharedView,
    icon: ListIcon,
    focus: Focus,
    sidebar_visible: bool,
    /// Selection index into the sidebar (meta-lists first, then user lists).
    sidebar_idx: usize,
    /// Which pane has focus (0 or 1).
    active_pane: usize,
    /// Per-pane selected item index.
    pane_sel: [usize; 2],
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
            active_pane: 0,
            pane_sel: [0, 0],
        }
    }

    fn send(&self, action: Action) {
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(action);
        }
    }

    fn pane_count(&self) -> usize {
        self.view.borrow().panes.len()
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
        match self.focus {
            Focus::Sidebar => {
                let len = self.sidebar_len();
                if len == 0 {
                    return;
                }
                let cur = self.sidebar_idx.min(len - 1) as isize;
                self.sidebar_idx = (cur + delta).rem_euclid(len as isize) as usize;
            }
            Focus::Pane => {
                let len = self
                    .view
                    .borrow()
                    .panes
                    .get(self.active_pane)
                    .map(|p| p.items.len())
                    .unwrap_or(0);
                if len == 0 {
                    return;
                }
                let slot = &mut self.pane_sel[self.active_pane];
                let cur = (*slot).min(len - 1) as isize;
                *slot = (cur + delta).rem_euclid(len as isize) as usize;
            }
        }
    }

    /// Open the sidebar-selected target in the active pane and focus it.
    fn open_selected(&mut self) {
        if let Some(target) = self.target_at(self.sidebar_idx) {
            self.pane_sel[self.active_pane] = 0;
            self.focus = Focus::Pane;
            self.send(Action::OpenView {
                target,
                pane: self.active_pane,
            });
        }
    }

    /// The `(list_id, item_id)` of the active pane's selected item, if any.
    fn selected_item(&self) -> Option<(ListId, String)> {
        let v = self.view.borrow();
        let pane = v.panes.get(self.active_pane)?;
        pane.items
            .get(self.pane_sel[self.active_pane])
            .map(|(lid, it)| (*lid, it.id.clone()))
    }

    /// The list shown in the active pane (None for a meta-list view).
    fn current_list(&self) -> Option<ListId> {
        match self.view.borrow().panes.get(self.active_pane)?.target {
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

    /// The list a list-level command (share/members) targets: the sidebar
    /// selection when the sidebar has focus, else the active pane's list.
    fn command_list(&self) -> Option<ListId> {
        match self.focus {
            Focus::Sidebar => self.selected_user_list().map(|(id, _)| id),
            Focus::Pane => self.current_list(),
        }
    }

    /// Map a command key to an intent action, given current focus/selection.
    fn command(&self, c: char) -> Option<Action> {
        match c {
            'n' => Some(Action::NewListModal),
            'o' => Some(Action::CycleSort),
            's' => self.command_list().map(Action::ShareModal),
            'm' => self.command_list().map(Action::MembersModal),
            'a' => self.current_list().map(Action::AddTodoModal),
            'e' if self.focus == Focus::Pane => self
                .selected_item()
                .map(|(list_id, item_id)| Action::EditTodoModal { list_id, item_id }),
            'x' if self.focus == Focus::Pane => self
                .selected_item()
                .map(|(list_id, item_id)| Action::ToggleDone { list_id, item_id }),
            'R' => self
                .selected_user_list()
                .map(|(list_id, name)| Action::RenameListModal { list_id, name }),
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

    // ── pane layout (pure UI state, handled locally) ───────────────────────────

    fn split(&mut self, dir: Direction) {
        {
            let mut v = self.view.borrow_mut();
            if v.panes.len() == 1 {
                let clone = v.panes[0].clone();
                v.panes.push(clone);
                self.pane_sel[1] = self.pane_sel[0];
            }
            v.split = Some(dir);
        }
        self.active_pane = 1;
        self.focus = Focus::Pane;
    }

    fn close_pane(&mut self) {
        let mut v = self.view.borrow_mut();
        if v.panes.len() <= 1 {
            return;
        }
        let keep = self.active_pane.min(v.panes.len() - 1);
        let pane = v.panes[keep].clone();
        v.panes = vec![pane];
        v.split = None;
        drop(v);
        self.pane_sel = [self.pane_sel[keep], 0];
        self.active_pane = 0;
    }

    fn cycle_pane(&mut self) {
        let n = self.pane_count();
        if n > 1 {
            self.focus = Focus::Pane;
            self.active_pane = (self.active_pane + 1) % n;
        }
    }

    fn resize(&mut self, delta: i16) {
        let mut v = self.view.borrow_mut();
        if v.split.is_some() {
            v.ratio = (v.ratio as i16 + delta).clamp(10, 90) as u16;
        }
    }

    /// Tab order: Sidebar → pane 0 → pane 1 (if split) → Sidebar.
    fn cycle_focus(&mut self) {
        let split = self.view.borrow().split.is_some();
        match (self.focus, self.active_pane) {
            (Focus::Sidebar, _) => {
                self.focus = Focus::Pane;
                self.active_pane = 0;
            }
            (Focus::Pane, 0) if split => self.active_pane = 1,
            _ => self.focus = Focus::Sidebar,
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
            .title_bottom(Line::from(" |:split -:stack w:pane X:close ").right_aligned())
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

    fn draw_pane(&self, frame: &mut Frame, area: Rect, idx: usize) {
        let view = self.view.borrow();
        let Some(pane) = view.panes.get(idx) else {
            return;
        };
        let base_title = match pane.target {
            Some(ViewTarget::Meta(m)) => m.label().to_string(),
            Some(ViewTarget::List(id)) => view
                .lists
                .iter()
                .find(|l| l.id == id)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| "List".into()),
            None => "Todoers".into(),
        };
        let title = format!("{base_title}  ·  sort: {}", view.sort.label());
        let focused = self.focus == Focus::Pane && self.active_pane == idx;

        let header = Row::new(["", "!", "Task", "Due"])
            .style(Style::default().add_modifier(Modifier::BOLD | Modifier::DIM));
        let rows = pane.items.iter().map(|(_, it)| {
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
            .title_bottom(
                Line::from(" n:new a:add e:edit x:done d:del o:sort s:share m:members ")
                    .right_aligned(),
            )
            .borders(Borders::ALL)
            .border_style(border_style(focused));
        let table = Table::new(rows, widths)
            .header(header)
            .block(block)
            .row_highlight_style(highlight_style(focused))
            .highlight_symbol("▌");
        let mut state = TableState::default();
        if !pane.items.is_empty() {
            state.select(Some(self.pane_sel[idx].min(pane.items.len() - 1)));
        }
        frame.render_stateful_widget(table, area, &mut state);
    }

    fn draw_panes(&self, frame: &mut Frame, area: Rect) {
        let (split, ratio) = {
            let v = self.view.borrow();
            (v.split, v.ratio.clamp(10, 90))
        };
        match split {
            None => self.draw_pane(frame, area, 0),
            Some(dir) => {
                let chunks = Layout::new(
                    dir,
                    [
                        Constraint::Percentage(ratio),
                        Constraint::Percentage(100 - ratio),
                    ],
                )
                .split(area);
                self.draw_pane(frame, chunks[0], 0);
                self.draw_pane(frame, chunks[1], 1);
            }
        }
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
            KeyCode::Tab | KeyCode::BackTab => self.cycle_focus(),
            KeyCode::Char('h') | KeyCode::Left => self.focus = Focus::Sidebar,
            KeyCode::Char('l') | KeyCode::Right => self.focus = Focus::Pane,
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            // Pane layout: side-by-side / stacked / cycle / close / resize.
            KeyCode::Char('|') => self.split(Direction::Horizontal),
            KeyCode::Char('-') => self.split(Direction::Vertical),
            KeyCode::Char('w') => self.cycle_pane(),
            KeyCode::Char('X') => self.close_pane(),
            KeyCode::Char('<') => self.resize(-5),
            KeyCode::Char('>') => self.resize(5),
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
            let [sidebar, panes] =
                Layout::horizontal([Constraint::Percentage(18), Constraint::Percentage(82)])
                    .areas(area);
            self.draw_sidebar(frame, sidebar);
            self.draw_panes(frame, panes);
        } else {
            self.draw_panes(frame, area);
        }
        Ok(())
    }
}
