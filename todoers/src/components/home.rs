use ratatui::{prelude::*, widgets::*};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;

use super::{Captures, Component};
use crate::action::Action;
use crate::config::Config;

const LIST_ICON_NF: char = '';
const LIST_ICON_UTF: char = '📋';
const LIST_ICON_BASIC: char = 'L';

#[derive(Default)]
pub struct Home {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
    icon: ListIcon,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl From<ListIcon> for char {
    fn from(icon: ListIcon) -> Self {
        icon.0
    }
}

impl ListIcon {
    pub fn new(icon: char) -> Self {
        Self(icon)
    }

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

impl Home {
    #[tracing::instrument]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
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
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        let [list_area, todos_area] =
            Layout::vertical([Constraint::Length(25), Constraint::Fill(1)]).areas(area);
        // TODO: this is just a placeholder for the actual list of lists. We will
        // replace it with the actual list of lists later.
        let list = List::new(
            ["demo1", "demo2", "demo3", "demo4", "demo5"]
                .iter()
                .map(|s| ListItem::new(format!("{} {}", self.icon, *s)))
                .collect::<Vec<_>>(),
        )
        .block(Block::default().title("Lists").borders(Borders::ALL))
        .direction(ListDirection::TopToBottom)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">");
        frame.render_stateful_widget(list, list_area, &mut ListState::default());
        Ok(())
    }
}
