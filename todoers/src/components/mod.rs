use crossterm::event::{KeyEvent, MouseEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect, Size};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::Action, config::Config, tui::Event};

pub(super) mod button;
pub(super) mod errorbar;
pub(super) mod form_keys;
#[cfg(feature = "fps")]
pub(super) mod fps;
pub(super) mod help;
pub(super) mod home;
pub(super) mod keys;
pub(super) mod list_form;
pub(super) mod login;
pub(super) mod members;
pub(super) mod modal;
pub(super) mod prompt;
pub(super) mod register;
pub(super) mod share_form;
pub(super) mod sidebar;
pub(super) mod text_input;
pub(super) mod todo_form;
pub(super) mod unlock;

pub use button::Button;
pub use errorbar::ErrorBar;
pub use form_keys::{FormAction, FormKeys};
#[cfg(feature = "fps")]
pub use fps::FpsCounter;
pub use help::Help;
pub use home::Home;
pub use keys::Keys;
pub use list_form::ListForm;
pub use login::Login;
pub use members::Members;
pub use modal::Modal;
pub use prompt::Prompt;
pub use register::Register;
pub use share_form::ShareForm;
pub use text_input::{EditorMode, TextInput};
pub use todo_form::TodoForm;
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
    /// Whether this component will *consume* an `Esc` press rather than letting it
    /// bubble up to close/cancel the surrounding modal or form.
    ///
    /// This exists for Vim-style editing: while a text field is in Insert/Visual/
    /// Operator-pending mode, `Esc` returns it to Normal mode and must not also
    /// dismiss the dialog. In Emacs mode (and Vim Normal mode) this is `false`, so
    /// `Esc` keeps its existing close/cancel behavior. Container components delegate
    /// to whichever child currently holds focus.
    fn consumes_escape(&self) -> bool {
        false
    }
    /// The Vim editing sub-mode to surface in the status footer, if this component
    /// (or whichever child currently has focus) is a focused Vim text field.
    /// Returns `None` in Emacs mode or when no Vim field is focused. Container
    /// components delegate to the focused child.
    fn editor_mode(&self) -> Option<EditorMode> {
        None
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

#[cfg(test)]
mod keybinding_default_tests {
    use crate::action::Action;
    use crate::config::{Config, KeyContext, compile_keymap, parse_command};

    /// Every command name in the shipped `app_config.toml` must be a valid verb for
    /// its surface — otherwise `compile_keymap` silently drops it and the default
    /// binding is dead. Compile each surface and assert nothing was dropped, which
    /// catches a typo in either the config or a verb enum.
    fn assert_all_compile<V>(ctx: KeyContext)
    where
        V: for<'de> serde::Deserialize<'de>,
    {
        let cfg = Config::defaults();
        let raw = cfg
            .keybindings
            .context(ctx)
            .unwrap_or_else(|| panic!("default config is missing the {ctx:?} section"));
        let compiled = compile_keymap(Some(raw), parse_command::<V>);
        assert_eq!(
            compiled.len(),
            raw.len(),
            "some default {ctx:?} bindings did not compile to a known command",
        );
    }

    #[test]
    fn default_keymaps_compile_for_every_surface() {
        assert_all_compile::<Action>(KeyContext::Global);
        assert_all_compile::<super::home::HomeCmd>(KeyContext::Home);
        assert_all_compile::<super::modal::ModalCmd>(KeyContext::Modal);
        assert_all_compile::<super::members::MembersCmd>(KeyContext::Members);
        assert_all_compile::<super::form_keys::FormCmd>(KeyContext::Form);
    }
}
