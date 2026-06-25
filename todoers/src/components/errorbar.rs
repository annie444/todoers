use ratatui::{prelude::*, widgets::*};
use tokio::time::{Duration, Instant};
use tracing::{error, warn};

use super::{Captures, Component};
use crate::action::Action;

pub struct ErrorBar {
    show: bool,
    text: String,
    style: Style,
    duration: Duration,
    show_time: Instant,
    history: Vec<String>,
}

impl Default for ErrorBar {
    fn default() -> Self {
        Self {
            show: false,
            text: String::new(),
            style: Style::default().fg(Color::Red),
            duration: Duration::from_secs(0),
            show_time: Instant::now(),
            history: Vec::new(),
        }
    }
}

impl ErrorBar {
    #[tracing::instrument]
    pub fn new() -> Self {
        Self::default()
    }

    fn show_error(&mut self, msg: String, duration: Duration) {
        self.text = msg;
        self.duration = duration;
        self.show_time = Instant::now();
        self.show = true;
    }

    fn clear(&mut self) {
        self.show = false;
        self.history.push(self.text.clone());
        self.text.clear();
        self.duration = Duration::from_secs(0);
    }

    fn is_showing(&self) -> bool {
        self.show && self.show_time.elapsed() <= self.duration
    }
}

impl Captures for ErrorBar {}

impl Component for ErrorBar {
    #[tracing::instrument(skip(self, action))]
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        match action {
            Action::ClearScreen => self.clear(),
            Action::Tick if self.show && self.show_time.elapsed() >= self.duration => {
                self.clear();
            }
            Action::Error(e) => {
                error!("Error received: {e}");
                self.show_error(e, Duration::from_secs(5));
            }
            _ => {}
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    fn placement(&self) -> Constraint {
        if self.is_showing() {
            Constraint::Length(2)
        } else {
            Constraint::Length(0)
        }
    }

    #[tracing::instrument(skip(self))]
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()> {
        frame.render_widget(
            Paragraph::new(Text::styled(&self.text, self.style))
                .alignment(HorizontalAlignment::Center),
            area,
        );
        Ok(())
    }
}
