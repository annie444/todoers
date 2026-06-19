use ratatui::prelude::*;
use ratatui::widgets::Paragraph;

use super::{Captures, Component};

/// A read-only modal body: a short, centered, word-wrapped message.
///
/// Used as the body of non-interactive dialogs (e.g. the "Login or Register?"
/// chooser), where the [`Modal`](super::Modal) supplies the title and buttons and
/// this component just renders the prompt text. It captures no input, so the
/// modal keeps keyboard focus on its buttons.
pub struct Prompt {
    text: String,
}

impl Prompt {
    #[tracing::instrument]
    pub fn new(text: impl Into<String> + std::fmt::Debug) -> Self {
        Self { text: text.into() }
    }
}

impl Captures for Prompt {}

impl Component for Prompt {
    #[tracing::instrument(skip(self))]
    fn placement(&self) -> Constraint {
        // Two lines of breathing room above the button row.
        Constraint::Length(2)
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        frame.render_widget(
            Paragraph::new(self.text.as_str())
                .alignment(Alignment::Center)
                .wrap(ratatui::widgets::Wrap { trim: true }),
            area,
        );
        Ok(())
    }
}
