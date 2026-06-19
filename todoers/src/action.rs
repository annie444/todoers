use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::app::Mode;
use crate::auth::UnlockedKeys;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Tick,
    Render,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    ClearScreen,
    Error(String),
    HelpModal,
    /// Open the "Login or Register?" chooser shown when there is no local account.
    AuthChooser,
    RegisterModal,
    LoginModal,
    /// Dismiss the currently open modal overlay (see `App::modal`).
    CloseModal,
    /// Emitted by a form body (`Register`/`Login`) when the user presses Enter on
    /// the last field: the enclosing `Modal` intercepts it to move focus from the
    /// fields onto its Submit button. It never reaches `App`.
    FocusButtons,
    /// Emitted by a form modal's Submit button. Forwarded down to the form body,
    /// which validates and (on success) emits `Register`/`Login`.
    SubmitForm,
    SetMode(Mode),
    StartCapture,
    StopCapture,
    SubmitInput(String),
    /// Submit a completed registration form. The password is class-3 material:
    /// never log this variant verbatim (see `Display` below and `App::handle_actions`).
    UnlockModal,
    Unlock {
        password: Zeroizing<String>,
    },
    Register {
        username: String,
        password: Zeroizing<String>,
    },
    Login {
        username: String,
        password: Zeroizing<String>,
    },
    Keys(Zeroizing<UnlockedKeys>),
}

impl std::fmt::Display for Action {
    #[tracing::instrument(name = "Action::fmt", skip(self, f))]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Tick => write!(f, "Tick"),
            Action::Render => write!(f, "Render"),
            Action::Resize(width, height) => write!(f, "Resize to {} x {}", width, height),
            Action::Suspend => write!(f, "Suspend"),
            Action::Resume => write!(f, "Resume"),
            Action::Quit => write!(f, "Quit"),
            Action::ClearScreen => write!(f, "Clear screen"),
            Action::Error(msg) => write!(f, "Error {}", msg),
            Action::HelpModal => write!(f, "Help"),
            Action::AuthChooser => write!(f, "Auth chooser"),
            Action::RegisterModal => write!(f, "Register"),
            Action::LoginModal => write!(f, "Login"),
            Action::CloseModal => write!(f, "Close modal"),
            Action::FocusButtons => write!(f, "Focus buttons"),
            Action::SubmitForm => write!(f, "Submit form"),
            Action::SetMode(mode) => write!(f, "Go {}", mode),
            Action::StartCapture => write!(f, "Start key capture"),
            Action::StopCapture => write!(f, "Stop key capture"),
            Action::SubmitInput(text) => write!(f, "Submit {}", text),
            Action::UnlockModal => write!(f, "Unlock todoers"),
            Action::Unlock { .. } => write!(f, "Unlock keys"),
            Action::Register { username, .. } => write!(f, "Register {}", username),
            Action::Login { username, .. } => write!(f, "Login {}", username),
            Action::Keys(_) => write!(f, "Cryptographic keys"),
        }
    }
}
