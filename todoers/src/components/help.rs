use std::collections::HashMap;

use crossterm::event::KeyModifiers;
use ratatui::{prelude::*, widgets::*};

use super::{Captures, Component};
use crate::action::Action;
use crate::app::Mode;
use crate::config::Config;

/// Read-only help body: a keybindings cheatsheet for a single [`Mode`].
///
/// Rendered *inside* a [`Modal`](super::Modal) (which supplies the border and
/// buttons), so this component only draws the list of `<keys> — <action>` lines.
/// The cheatsheet is built from the same per-mode keybinding config the
/// [`Keys`](super::Keys) footer reads, so it always reflects the live bindings.
pub struct Help {
    mode: Mode,
    /// Joined key strings -> action label (e.g. "q/Ctrl+c" -> "quit").
    keys: HashMap<String, String>,
}

impl Help {
    #[tracing::instrument]
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            keys: HashMap::new(),
        }
    }

    /// Render a single crossterm key into a display string, including modifiers.
    /// Mirrors the formatting used by [`Keys`](super::Keys) so the two agree.
    #[tracing::instrument]
    fn key_label(key: &crossterm::event::KeyEvent) -> String {
        let mut s = String::new();
        if !key.modifiers.is_empty() {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                s.push_str("Ctrl+");
            }
            if key.modifiers.contains(KeyModifiers::ALT) {
                s.push_str("Alt+");
            }
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                s.push_str("Shift+");
            }
            if key.modifiers.contains(KeyModifiers::SUPER) {
                s.push_str("Super+");
            }
            if key.modifiers.contains(KeyModifiers::META) {
                s.push_str("Meta+");
            }
            if key.modifiers.contains(KeyModifiers::HYPER) {
                s.push_str("Hyper+");
            }
        }
        s.push_str(&format!("{}", key.code));
        s
    }
}

impl Captures for Help {}

impl Component for Help {
    #[tracing::instrument(skip(self, config))]
    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        if let Some(keybinds) = config.keybindings.0.get(&self.mode) {
            let mut key_strs: HashMap<String, Vec<String>> = HashMap::new();
            for (keys, action_cfg) in keybinds {
                let action: &Action = action_cfg.into();
                for key in keys {
                    key_strs
                        .entry(action.to_string())
                        .or_default()
                        .push(Self::key_label(key));
                }
            }
            for (action, keys) in key_strs.into_iter() {
                self.keys.insert(keys.join("/"), action);
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    fn placement(&self) -> Constraint {
        // One row per binding, plus a little breathing room.
        Constraint::Length(self.keys.len() as u16 + 2)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        // Stable ordering: sort by action label so the list doesn't jump around
        // between renders (HashMap iteration order is otherwise unspecified).
        let mut rows: Vec<(&String, &String)> = self.keys.iter().collect();
        rows.sort_by(|a, b| a.1.cmp(b.1));

        let lines: Vec<Line> = rows
            .into_iter()
            .map(|(keys, action)| {
                Line::from(vec![
                    Span::styled(
                        keys.clone(),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(" — ", Style::default().dim()),
                    Span::styled(
                        action.clone(),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                ])
            })
            .collect();

        frame.render_widget(Paragraph::new(lines), area);
        Ok(())
    }
}
