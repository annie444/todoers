use crossterm::event::KeyEvent;
use indexmap::IndexMap;
use ratatui::{prelude::*, widgets::*};
use serde::Deserialize;
use tokio::sync::mpsc::UnboundedSender;

use todoers_client::model::{MetaList, Priority, ViewTarget};
use todoers_types::ListId;

use super::{Captures, Component};
use crate::action::{Action, DeleteTarget};
use crate::config::{Config, IconType, KeyContext, compile_keymap, parse_command, resolve};
use crate::store::SharedView;

/// The workspace's key-triggerable operations. Bound to keys via
/// `[keybindings.home]`; the component resolves a key to one of these and runs
/// it against its current focus/selection (so e.g. `share` targets whatever the
/// sidebar/pane currently points at).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HomeCmd {
    FocusSidebar,
    FocusPane,
    CycleFocus,
    SelectNext,
    SelectPrev,
    OpenSelected,
    SplitHorizontal,
    SplitVertical,
    CyclePane,
    ClosePane,
    GrowPane,
    ShrinkPane,
    NewList,
    CycleSort,
    Share,
    Members,
    AddTodo,
    EditTodo,
    ToggleDone,
    Rename,
    Delete,
}

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
    /// Compiled `[keybindings.home]` map + the multi-key sequence buffer.
    keymap: IndexMap<Vec<KeyEvent>, HomeCmd>,
    pending: Vec<KeyEvent>,
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
            icon: ListIcon::nf(),
            focus: Focus::default(),
            sidebar_visible: true,
            sidebar_idx: 0,
            active_pane: 0,
            pane_sel: [0, 0],
            keymap: IndexMap::new(),
            pending: Vec::new(),
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

    /// Run a resolved [`HomeCmd`] against the current focus/selection. Layout and
    /// focus verbs mutate local view state; command verbs build the same intent
    /// [`Action`]s the app already fulfills and emit them on the action channel.
    fn execute(&mut self, cmd: HomeCmd) {
        use HomeCmd::*;
        match cmd {
            FocusSidebar => self.focus = Focus::Sidebar,
            FocusPane => self.focus = Focus::Pane,
            CycleFocus => self.cycle_focus(),
            SelectNext => self.move_selection(1),
            SelectPrev => self.move_selection(-1),
            OpenSelected => {
                if self.focus == Focus::Sidebar {
                    self.open_selected();
                }
            }
            SplitHorizontal => self.split(Direction::Horizontal),
            SplitVertical => self.split(Direction::Vertical),
            CyclePane => self.cycle_pane(),
            ClosePane => self.close_pane(),
            GrowPane => self.resize(5),
            ShrinkPane => self.resize(-5),
            NewList => self.send(Action::NewListModal),
            CycleSort => self.send(Action::CycleSort),
            Share => {
                if let Some(action) = self.command_list().map(Action::ShareModal) {
                    self.send(action);
                }
            }
            Members => {
                if let Some(action) = self.command_list().map(Action::MembersModal) {
                    self.send(action);
                }
            }
            AddTodo => {
                if let Some(action) = self.current_list().map(Action::AddTodoModal) {
                    self.send(action);
                }
            }
            EditTodo => {
                if self.focus == Focus::Pane
                    && let Some((list_id, item_id)) = self.selected_item()
                {
                    self.send(Action::EditTodoModal { list_id, item_id });
                }
            }
            ToggleDone => {
                if self.focus == Focus::Pane
                    && let Some((list_id, item_id)) = self.selected_item()
                {
                    self.send(Action::ToggleDone { list_id, item_id });
                }
            }
            Rename => {
                if let Some((list_id, name)) = self.selected_user_list() {
                    self.send(Action::RenameListModal { list_id, name });
                }
            }
            Delete => match self.focus {
                Focus::Sidebar => {
                    if let Some((id, _)) = self.selected_user_list() {
                        self.send(Action::ConfirmDelete(DeleteTarget::List(id)));
                    }
                }
                Focus::Pane => {
                    if let Some((list_id, item_id)) = self.selected_item() {
                        self.send(Action::ConfirmDelete(DeleteTarget::Todo {
                            list_id,
                            item_id,
                        }));
                    }
                }
            },
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
        // Tell the worker the pane count changed so it snapshots both panes.
        self.send(Action::RefreshLists);
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
        // Tell the worker the pane count changed so it snapshots the kept pane.
        self.send(Action::RefreshLists);
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

    /// Pane-layout hint shown on the sidebar (split/stack/cycle/close).
    fn layout_hint(&self) -> String {
        self.hint(&[
            (HomeCmd::SplitHorizontal, "split"),
            (HomeCmd::SplitVertical, "stack"),
            (HomeCmd::CyclePane, "pane"),
            (HomeCmd::ClosePane, "close"),
        ])
    }

    /// Command hint shown on a todo pane.
    fn command_hint(&self) -> String {
        self.hint(&[
            (HomeCmd::NewList, "new"),
            (HomeCmd::AddTodo, "add"),
            (HomeCmd::EditTodo, "edit"),
            (HomeCmd::ToggleDone, "done"),
            (HomeCmd::Delete, "del"),
            (HomeCmd::CycleSort, "sort"),
            (HomeCmd::Share, "share"),
            (HomeCmd::Members, "members"),
        ])
    }

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
            .title_bottom(Line::from(self.layout_hint()).right_aligned())
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
            .title_bottom(Line::from(self.command_hint()).right_aligned())
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
        self.icon = match self.config.config.icon_type {
            IconType::NerdFonts => ListIcon::nf(),
            IconType::Emojis => ListIcon::utf(),
            IconType::Basic => ListIcon::basic(),
        };
        self.keymap = compile_keymap(
            self.config.keybindings.context(KeyContext::Home),
            parse_command::<HomeCmd>,
        );
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        if let Some(cmd) = resolve(&self.keymap, &mut self.pending, key) {
            self.execute(cmd);
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        match action {
            Action::ToggleSidebar => {
                self.sidebar_visible = !self.sidebar_visible;
                if !self.sidebar_visible {
                    self.focus = Focus::Pane;
                }
            }
            // Drop any half-typed multi-key sequence on the tick boundary, mirroring
            // the app-level global buffer.
            Action::Tick => self.pending.clear(),
            _ => {}
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        if self.sidebar_visible {
            let [sidebar, panes] =
                Layout::horizontal([Constraint::Length(30), Constraint::Fill(1)]).areas(area);
            self.draw_sidebar(frame, sidebar);
            self.draw_panes(frame, panes);
        } else {
            self.draw_panes(frame, area);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crossterm::event::{KeyCode, KeyModifiers};
    use pretty_assertions::assert_eq;
    use tokio::sync::mpsc;

    fn ch(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty())
    }

    /// With the default `[keybindings.home]` map loaded, command keys resolve to
    /// their `HomeCmd` and emit the matching intent action on the channel.
    #[test]
    fn default_command_keys_emit_actions() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut home = Home::new(SharedView::default());
        home.register_action_handler(tx).unwrap();
        home.register_config_handler(Config::defaults()).unwrap();

        home.handle_key_event(ch('n')).unwrap();
        assert_eq!(rx.try_recv().unwrap(), Action::NewListModal);

        home.handle_key_event(ch('o')).unwrap();
        assert_eq!(rx.try_recv().unwrap(), Action::CycleSort);
    }

    /// Focus/navigation keys mutate local view state rather than emitting actions.
    #[test]
    fn default_focus_keys_mutate_local_state() {
        let mut home = Home::new(SharedView::default());
        home.register_config_handler(Config::defaults()).unwrap();

        home.handle_key_event(ch('l')).unwrap();
        assert_eq!(home.focus, Focus::Pane);
        home.handle_key_event(ch('h')).unwrap();
        assert_eq!(home.focus, Focus::Sidebar);
    }

    /// The on-screen hints are derived from the live bindings and, with defaults,
    /// reproduce the original hardcoded strings.
    #[test]
    fn hints_derive_from_default_bindings() {
        let mut home = Home::new(SharedView::default());
        home.register_config_handler(Config::defaults()).unwrap();
        assert_eq!(home.layout_hint(), " |:split -:stack w:pane X:close ");
        assert_eq!(
            home.command_hint(),
            " n:new a:add e:edit x:done d:del o:sort s:share m:members "
        );
    }

    /// A rebound key takes effect: map `a` to `new_list` and it now emits the new
    /// list action instead of add-todo.
    #[test]
    fn rebinding_a_key_changes_the_command() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut cfg = Config::defaults();
        cfg.keybindings
            .0
            .get_mut(&KeyContext::Home)
            .unwrap()
            .insert(
                crate::config::parse_key_sequence("a").unwrap(),
                crate::config::CommandSpec::Bare("new_list".into()),
            );

        let mut home = Home::new(SharedView::default());
        home.register_action_handler(tx).unwrap();
        home.register_config_handler(cfg).unwrap();

        home.handle_key_event(ch('a')).unwrap();
        assert_eq!(rx.try_recv().unwrap(), Action::NewListModal);
    }
}
