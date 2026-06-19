use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;

use super::{Captures, Component};
use crate::action::Action;
use crate::config::Config;

#[derive(Default)]
pub struct Home {
    command_tx: Option<UnboundedSender<Action>>,
    config: Config,
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
        frame.render_widget(Paragraph::new("Home"), area);
        Ok(())
    }
}
