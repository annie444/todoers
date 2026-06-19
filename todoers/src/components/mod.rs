use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect, Size};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::Action, config::Config, tui::Event};

mod button;
mod errorbar;
mod help;
mod home;
mod keys;
mod login;
mod modal;
mod prompt;
mod register;
mod text_input;
mod unlock;

pub use button::Button;
pub use errorbar::ErrorBar;
pub use help::Help;
pub use home::Home;
pub use keys::Keys;
pub use login::Login;
pub use modal::Modal;
pub use prompt::Prompt;
pub use register::Register;
pub use text_input::TextInput;
pub use unlock::Unlock;

/// `Captures` is a trait that indicates whether a component captures input events.
///
/// Implementors of this trait can specify whether they capture input events, which can be used by
/// the main application loop to determine how to route events to components.
pub trait Captures {
    fn captures_input(&self) -> bool {
        false
    }
}

/// `Component` is a trait that represents a visual and interactive element of the user interface.
///
/// Implementors of this trait can be registered with the main application loop and will be able to
/// receive events, update state, and be rendered on the screen.
pub trait Component: Captures {
    /// Register an action handler that can send actions for processing if necessary.
    ///
    /// # Arguments
    ///
    /// * `tx` - An unbounded sender that can send actions.
    ///
    /// # Returns
    ///
    /// * [`anyhow::Result<()>`] - An Ok result or an error.
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> anyhow::Result<()> {
        let _ = tx; // to appease clippy
        Ok(())
    }
    /// Register a configuration handler that provides configuration settings if necessary.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration settings.
    ///
    /// # Returns
    ///
    /// * [`anyhow::Result<()>`] - An Ok result or an error.
    fn register_config_handler(&mut self, config: Config) -> anyhow::Result<()> {
        let _ = config; // to appease clippy
        Ok(())
    }

    /// Return the layout constraints for this component. By default, it fills all available space.
    ///
    /// # Returns
    ///
    /// * [`ratatui::layout::Constraint`] - The layout constraint for this component.
    fn placement(&self) -> Constraint {
        Constraint::Fill(1)
    }
    /// Initialize the component with a specified area if necessary.
    ///
    /// # Arguments
    ///
    /// * `area` - Rectangular area to initialize the component within.
    ///
    /// # Returns
    ///
    /// * [`anyhow::Result<()>`] - An Ok result or an error.
    fn init(&mut self, area: Size) -> anyhow::Result<()> {
        let _ = area; // to appease clippy
        Ok(())
    }
    /// Handle incoming events and produce actions if necessary.
    ///
    /// # Arguments
    ///
    /// * `event` - An optional event to be processed.
    ///
    /// # Returns
    ///
    /// * [`anyhow::Result<Option<Action>>`] - An action to be processed or none.
    fn handle_events(&mut self, event: Option<Event>) -> anyhow::Result<Option<Action>> {
        let action = match event {
            Some(Event::Key(key_event)) => self.handle_key_event(key_event)?,
            Some(Event::Mouse(mouse_event)) => self.handle_mouse_event(mouse_event)?,
            _ => None,
        };
        Ok(action)
    }
    /// Handle key events and produce actions if necessary.
    ///
    /// # Arguments
    ///
    /// * `key` - A key event to be processed.
    ///
    /// # Returns
    ///
    /// * [`anyhow::Result<Option<Action>>`] - An action to be processed or none.
    fn handle_key_event(&mut self, key: KeyEvent) -> anyhow::Result<Option<Action>> {
        let _ = key; // to appease clippy
        Ok(None)
    }
    /// Handle mouse events and produce actions if necessary.
    ///
    /// # Arguments
    ///
    /// * `mouse` - A mouse event to be processed.
    ///
    /// # Returns
    ///
    /// * [`anyhow::Result<Option<Action>>`] - An action to be processed or none.
    fn handle_mouse_event(&mut self, mouse: MouseEvent) -> anyhow::Result<Option<Action>> {
        let _ = mouse; // to appease clippy
        Ok(None)
    }
    /// Update the state of the component based on a received action. (REQUIRED)
    ///
    /// # Arguments
    ///
    /// * `action` - An action that may modify the state of the component.
    ///
    /// # Returns
    ///
    /// * [`anyhow::Result<Option<Action>>`] - An action to be processed or none.
    fn update(&mut self, action: Action) -> anyhow::Result<Option<Action>> {
        let _ = action; // to appease clippy
        Ok(None)
    }
    /// Render the component on the screen. (REQUIRED)
    ///
    /// # Arguments
    ///
    /// * `f` - A frame used for rendering.
    /// * `area` - The area in which the component should be drawn.
    ///
    /// # Returns
    ///
    /// * [`anyhow::Result<()>`] - An Ok result or an error.
    fn draw(&mut self, frame: &mut Frame, area: Rect) -> anyhow::Result<()>;
}
