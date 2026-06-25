use std::collections::HashSet;

use indexmap::IndexMap;
use ratatui::layout::Flex;
use ratatui::{prelude::*, widgets::*};
use tokio::sync::mpsc::UnboundedSender;

use super::{Captures, Component};
use crate::action::Action;
use crate::app::Mode;
use crate::config::{Config, KeyContext, command_label, key_event_to_string};
use crate::tui::Event;

#[derive(Default)]
pub struct Keys {
    command_tx: Option<UnboundedSender<Action>>,
    keys: IndexMap<String, String>,
    /// One `Fill(1)` per footer entry, built once when the key map is set so the
    /// per-frame `draw` doesn't reallocate it on every render.
    key_constraints: Vec<Constraint>,
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
        // The footer surfaces the app-wide `global` bindings plus the bindings for
        // this mode's own surface, keeping only those flagged `show = true`.
        let contexts = [KeyContext::Global, KeyContext::from(self.mode)];
        let mut key_strs: IndexMap<String, HashSet<String>> = IndexMap::new();
        for ctx in contexts {
            let Some(keybinds) = config.keybindings.context(ctx) else {
                continue;
            };
            for (keys, spec) in keybinds {
                if spec.show() {
                    for key in keys {
                        key_strs
                            .entry(command_label(spec.command()))
                            .or_default()
                            .insert(key_event_to_string(key));
                    }
                }
            }
        }
        for (action, keys) in key_strs.into_iter() {
            self.keys
                .insert(keys.into_iter().collect::<Vec<_>>().join("/"), action);
        }
        self.key_constraints = vec![Constraint::Fill(1); self.keys.len()];
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
        let key_areas = Layout::horizontal(self.key_constraints.iter().copied())
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
