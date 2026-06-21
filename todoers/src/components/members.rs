use crossterm::event::{KeyCode, KeyEvent, MouseEvent};
use ratatui::prelude::*;
use ratatui::widgets::*;
use tokio::sync::mpsc::UnboundedSender;

use todoers_types::{ListId, Member, MemberId, Role};

use super::{Captures, Component};
use crate::action::Action;
use crate::config::Config;
use crate::tui::Event;

/// An interactive list of a list's members. Lives in a [`Modal::message`]
/// (Close button, Esc closes); `d`/Enter on a member (other than yourself)
/// emits [`Action::Unshare`], which rotates the list's DEK.
pub struct Members {
    list_id: ListId,
    members: Vec<Member>,
    me: MemberId,
    selected: usize,
    command_tx: Option<UnboundedSender<Action>>,
}

impl Captures for Members {
    fn captures_input(&self) -> bool {
        true
    }
}

impl Members {
    pub fn new(list_id: ListId, members: Vec<Member>, me: MemberId) -> Self {
        Self {
            list_id,
            members,
            me,
            selected: 0,
            command_tx: None,
        }
    }

    fn unshare_selected(&self) {
        let Some(member) = self.members.get(self.selected) else {
            return;
        };
        // Can't remove yourself from this dialog.
        if member.id == self.me {
            return;
        }
        if let Some(tx) = &self.command_tx {
            let _ = tx.send(Action::Unshare {
                list_id: self.list_id,
                member_id: member.id,
            });
        }
    }
}

impl Component for Members {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.command_tx = Some(tx);
        Ok(())
    }

    fn register_config_handler(&mut self, _config: Config) -> anyhow::Result<()> {
        Ok(())
    }

    fn handle_events(&mut self, event: Option<Event>) -> anyhow::Result<Option<Action>> {
        match event {
            Some(Event::Key(key)) => self.handle_key_event(key),
            Some(Event::Mouse(mouse)) => self.handle_mouse_event(mouse),
            _ => Ok(None),
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        if self.members.is_empty() {
            return Ok(None);
        }
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.selected = (self.selected + 1) % self.members.len();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selected = (self.selected + self.members.len() - 1) % self.members.len();
            }
            KeyCode::Char('d') | KeyCode::Enter => self.unshare_selected(),
            _ => {}
        }
        Ok(None)
    }

    fn handle_mouse_event(&mut self, _mouse: MouseEvent) -> anyhow::Result<Option<Action>> {
        Ok(None)
    }

    fn update(&mut self, _action: Action) -> anyhow::Result<Option<Action>> {
        Ok(None)
    }

    fn placement(&self) -> Constraint {
        Constraint::Length((self.members.len() as u16).clamp(1, 10) + 2)
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        let rows: Vec<ListItem> = self
            .members
            .iter()
            .map(|m| {
                let role = match m.role {
                    Role::Owner => "owner ",
                    Role::Member => "member",
                };
                let short = hex::encode(m.id.0);
                let you = if m.id == self.me { "  (you)" } else { "" };
                ListItem::new(format!(" {role}  {}…{you}", &short[..8]))
            })
            .collect();
        let block = Block::default()
            .title("Members")
            .title_bottom(Line::from(" d/Enter: remove ").right_aligned())
            .borders(Borders::ALL);
        let list = List::new(rows).block(block).highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        let mut state = ListState::default();
        if !self.members.is_empty() {
            state.select(Some(self.selected.min(self.members.len() - 1)));
        }
        frame.render_stateful_widget(list, area, &mut state);
        Ok(())
    }
}
