//! Shared, configurable key handling for form bodies (login/register/todo/list/
//! share/unlock).
//!
//! Every form has the same skeleton — move between fields, submit, and (for the
//! todo form) cycle a priority value — so they all bind the same
//! `[keybindings.form]` section. [`FormKeys`] compiles that section once and
//! resolves a key into a [`FormCmd`]; [`FormKeys::classify`] collapses it further
//! into the [`FormAction`] the simple text-only forms need, leaving anything it
//! doesn't recognize to fall through to the focused text field (so a key bound to
//! `cycle_priority_*` still types normally in a form that has no priority field).

use crossterm::event::{KeyCode, KeyEvent};
use indexmap::IndexMap;
use serde::Deserialize;

use crate::config::{Config, KeyContext, compile_keymap, parse_command, resolve};

/// A form's key-triggerable operations, bound via `[keybindings.form]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormCmd {
    /// Move focus to the next field.
    FieldNext,
    /// Move focus to the previous field.
    FieldPrev,
    /// Advance to the next field, or hand off to the modal buttons on the last.
    Submit,
    /// Cycle the todo form's priority value forward (ignored elsewhere).
    CyclePriorityNext,
    /// Cycle the todo form's priority value backward (ignored elsewhere).
    CyclePriorityPrev,
}

/// What a text-only form should do with a key, after resolving its binding.
pub enum FormAction {
    /// Move to the next field.
    Next,
    /// Move to the previous field.
    Prev,
    /// Submit (or advance from a non-last field).
    Submit,
    /// Not a form-navigation key: let the focused text field handle it.
    PassToField,
}

/// Compiled `[keybindings.form]` map plus the multi-key sequence buffer. Embedded
/// in each form component.
#[derive(Default)]
pub struct FormKeys {
    keymap: IndexMap<Vec<KeyEvent>, FormCmd>,
    pending: Vec<KeyEvent>,
}

impl FormKeys {
    /// (Re)compile the form keymap from the live config.
    pub fn configure(&mut self, config: &Config) {
        self.keymap = compile_keymap(
            config.keybindings.context(KeyContext::Form),
            parse_command::<FormCmd>,
        );
    }

    /// Resolve a key into a [`FormCmd`] (used by the todo form, which also handles
    /// the priority-cycle verbs).
    pub fn resolve(&mut self, key: KeyEvent) -> Option<FormCmd> {
        resolve(&self.keymap, &mut self.pending, key)
    }

    /// Resolve a key into a [`FormAction`] for the simple text-only forms. `Esc`
    /// is always passed to the focused field — the modal owns cancel, and a Vim
    /// field mid-edit consumes Esc to leave Insert mode. Priority-cycle verbs are
    /// not field navigation, so they fall through to the field too (where they
    /// type normally).
    pub fn classify(&mut self, key: KeyEvent) -> FormAction {
        if key.code == KeyCode::Esc {
            return FormAction::PassToField;
        }
        match self.resolve(key) {
            Some(FormCmd::FieldNext) => FormAction::Next,
            Some(FormCmd::FieldPrev) => FormAction::Prev,
            Some(FormCmd::Submit) => FormAction::Submit,
            Some(FormCmd::CyclePriorityNext) | Some(FormCmd::CyclePriorityPrev) | None => {
                FormAction::PassToField
            }
        }
    }
}
