use crossterm::event::KeyModifiers;
use indexmap::IndexMap;
use ratatui::layout::Flex;
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;
use tracing::warn;

use super::{Captures, Component};
use crate::action::Action;
use crate::app::Mode;
use crate::config::Config;
use crate::tui::Event;

#[derive(Default)]
pub struct Keys {
    command_tx: Option<UnboundedSender<Action>>,
    keys: IndexMap<String, String>,
    mode: Mode,
    keys_style: Style,
    sep_style: Style,
    action_style: Style,
    line_style: Style,
}

impl Keys {
    #[tracing::instrument]
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            keys_style: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            sep_style: Style::default().dim(),
            action_style: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            line_style: Style::default().fg(Color::DarkGray),
            ..Default::default()
        }
    }
}

impl Captures for Keys {}

impl Component for Keys {
    #[tracing::instrument(skip(self, tx))]
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        self.command_tx = Some(tx);
        Ok(())
    }

    #[tracing::instrument(skip(self, config))]

    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        if let Some(keybinds) = config.keybindings.0.get(&self.mode) {
            let mut key_strs: IndexMap<String, Vec<String>> = IndexMap::new();
            for (keys, action) in keybinds {
                for key in keys {
                    let mut key_str = String::new();
                    if !key.modifiers.is_empty() {
                        if key.modifiers.contains(KeyModifiers::CONTROL) {
                            key_str.push_str("Ctrl+");
                        }
                        if key.modifiers.contains(KeyModifiers::ALT) {
                            key_str.push_str("Alt+");
                        }
                        if key.modifiers.contains(KeyModifiers::SHIFT) {
                            key_str.push_str("Shift+");
                        }
                        if key.modifiers.contains(KeyModifiers::SUPER) {
                            key_str.push_str("Super+");
                        }
                        if key.modifiers.contains(KeyModifiers::META) {
                            key_str.push_str("Meta+");
                        }
                        if key.modifiers.contains(KeyModifiers::HYPER) {
                            key_str.push_str("Hyper+");
                        }
                    }
                    key_str.push_str(&format!("{}", key.code));
                    key_strs
                        .entry(action.to_string())
                        .or_default()
                        .push(key_str);
                }
            }
            for (action, keys) in key_strs.into_iter() {
                self.keys.insert(keys.join("/"), action);
            }
        } else {
            warn!("No keybindings found for mode: {:?}", self.mode);
        };
        Ok(())
    }

    #[tracing::instrument(skip(self, action))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        match action {
            Action::Tick => {
                // add any logic here that should run on every tick
            }
            Action::Render => {
                // add any logic here that should run on every render
            }
            _ => {}
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn handle_events(&mut self, event: Option<Event>) -> anyhow::Result<Option<Action>> {
        let action = match event {
            Some(Event::Key(key_event)) => self.handle_key_event(key_event)?,
            Some(Event::Mouse(mouse_event)) => self.handle_mouse_event(mouse_event)?,
            _ => None,
        };
        Ok(action)
    }

    #[tracing::instrument(skip(self))]
    fn placement(&self) -> Constraint {
        Constraint::Length(2)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        let [line, keys_vert] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)])
            .vertical_margin(0)
            .areas(area);
        frame.render_widget(Fill::new("─").style(self.line_style), line);
        let key_areas = Layout::horizontal(vec![Constraint::Fill(1); self.keys.len()])
            .flex(Flex::SpaceBetween)
            .split(keys_vert);
        for (i, (keys, action)) in self.keys.iter().enumerate() {
            let text_areas = Layout::horizontal([
                Constraint::Fill(2),
                Constraint::Length(3),
                Constraint::Fill(3),
            ])
            .flex(Flex::Center)
            .split(key_areas[i]);
            frame.render_widget(
                Paragraph::new(Text::styled(keys, self.keys_style))
                    .alignment(HorizontalAlignment::Right),
                text_areas[0],
            );
            frame.render_widget(
                Paragraph::new(Text::styled(" - ", self.sep_style))
                    .alignment(HorizontalAlignment::Center),
                text_areas[1],
            );
            frame.render_widget(
                Paragraph::new(Text::styled(action, self.action_style))
                    .alignment(HorizontalAlignment::Left),
                text_areas[2],
            );
        }
        Ok(())
    }
}
