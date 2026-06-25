use std::{collections::HashMap, env, path::PathBuf, sync::LazyLock};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use directories::{BaseDirs, ProjectDirs, UserDirs};
use indexmap::IndexMap;
use ratatui::style::{Color, Modifier, Style};
use serde::{Deserialize, de::Deserializer};
use tracing::{debug, error, warn};

use todoers_client::get_data_dir;

use crate::app::Mode;

const CONFIG: &str = include_str!("../app_config.toml");

#[derive(Clone, Debug, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub config_dir: PathBuf,
    /// Base URL of the todoers server used for registration/login.
    #[serde(default = "default_server_url")]
    pub server_url: String,
    /// Icon style used in the UI: `nerd-fonts` (default), `emojis`, or `basic`.
    #[serde(default)]
    pub icon_type: IconType,
    /// Password-less device unlock via a local AGE/SSH key. Per-device (lives in
    /// the local config), so each device can use a different key.
    #[serde(default)]
    pub device_unlock: DeviceUnlockConfig,
    /// Text-field editing style: `emacs` (default) or `vim`.
    #[serde(default)]
    pub editing_mode: EditingMode,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IconType {
    NerdFonts,
    Emojis,
    Basic,
}

impl Default for IconType {
    fn default() -> Self {
        if cfg!(windows) {
            IconType::Emojis
        } else {
            IconType::NerdFonts
        }
    }
}

/// Which key bindings a focused text field obeys.
///
/// `Emacs` delegates to [`ratatui_textarea::TextArea::input`], which ships a full
/// set of emacs motions/edits. `Vim` runs a modal state machine on top of the same
/// widget (see [`crate::components::text_input`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EditingMode {
    #[default]
    Emacs,
    Vim,
}

/// Per-device password-less unlock settings. When `enabled`, after a normal
/// password login this device seals its keys to `recipient` and enrolls a trusted
/// key with the server; subsequent launches unlock with `identity` and no password.
#[derive(Clone, Debug, Deserialize, Default)]
pub struct DeviceUnlockConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Recipient to seal the cache to: the hex-encoded X-Wing public key printed
    /// by `todoers keygen`.
    #[serde(default)]
    pub recipient: Option<String>,
    /// Path to the identity file used to open the cache: the hex-encoded X-Wing
    /// secret key written by `todoers keygen`.
    #[serde(default)]
    pub identity: Option<String>,
}

#[tracing::instrument]
fn default_server_url() -> String {
    "http://127.0.0.1:8192".to_string()
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default, flatten)]
    pub config: AppConfig,
    #[serde(default)]
    pub keybindings: KeyBindings,
    #[serde(default)]
    pub styles: Styles,
}

pub static PROJECT_NAME: LazyLock<String> =
    LazyLock::new(|| env!("CARGO_CRATE_NAME").to_uppercase().to_string());
pub static CONFIG_FOLDER: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    env::var(format!("{}_CONFIG", PROJECT_NAME.clone()))
        .ok()
        .map(PathBuf::from)
});

impl Config {
    /// The built-in default configuration (the embedded `app_config.toml`), with no
    /// user config files layered on top. Useful for tests that need the default
    /// keymaps without depending on the host's config directory.
    #[cfg(test)]
    pub fn defaults() -> Self {
        toml::from_str(CONFIG).expect("embedded app_config.toml must be valid")
    }

    #[tracing::instrument]
    pub fn new() -> anyhow::Result<Self, config::ConfigError> {
        let default_config: Config = toml::from_str(CONFIG).unwrap();
        let data_dir = get_data_dir();
        let config_dir = get_config_dir();
        debug!("Using data directory: {}", data_dir.display());
        debug!("Using config directory: {}", config_dir.display());
        let mut builder = config::Config::builder()
            .set_default("data_dir", data_dir.to_str().unwrap())?
            .set_default("config_dir", config_dir.to_str().unwrap())?;

        let config_files = [
            ("config.json5", config::FileFormat::Json5),
            ("config.json", config::FileFormat::Json),
            ("config.yaml", config::FileFormat::Yaml),
            ("config.toml", config::FileFormat::Toml),
            ("config.ini", config::FileFormat::Ini),
        ];
        let mut found_config = false;
        for (file, format) in &config_files {
            let source = config::File::from(config_dir.join(file))
                .format(*format)
                .required(false);
            builder = builder.add_source(source);
            if config_dir.join(file).exists() {
                found_config = true
            }
        }
        if !found_config {
            error!("No configuration file found. Application may not behave as expected");
        }

        let mut cfg: Self = builder.build()?.try_deserialize()?;

        for (mode, default_bindings) in default_config.keybindings.0.iter() {
            let user_bindings = cfg.keybindings.0.entry(*mode).or_default();
            for (key, cmd) in default_bindings.iter() {
                user_bindings
                    .entry(key.clone())
                    .or_insert_with(|| cmd.clone());
            }
        }
        for (mode, default_styles) in default_config.styles.0.iter() {
            let user_styles = cfg.styles.0.entry(*mode).or_default();
            for (style_key, style) in default_styles.iter() {
                user_styles.entry(style_key.clone()).or_insert(*style);
            }
        }

        cfg.config.device_unlock.identity.iter_mut().for_each(|p| {
            if p.get(0..1).map(|i| i == "~").unwrap_or(false)
                && let Some(user) =
                    UserDirs::new().map(|u| u.home_dir().to_string_lossy().to_string())
            {
                p.replace_range(0..1, &user);
            }
        });

        debug!("Config loaded: {cfg:#?}");

        Ok(cfg)
    }
}

#[tracing::instrument]
pub fn get_config_dir() -> PathBuf {
    if let Some(s) = CONFIG_FOLDER.clone() {
        s
    } else if let Some(user) =
        UserDirs::new().map(|u| u.home_dir().join(".config").join(env!("CARGO_PKG_NAME")))
        && user.exists()
    {
        user
    } else if let Some(base) = BaseDirs::new().map(|b| b.config_dir().join(env!("CARGO_PKG_NAME")))
        && base.exists()
    {
        base
    } else if let Some(proj_dirs) = project_dir() {
        proj_dirs.config_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".config")
    }
}

#[tracing::instrument]
fn project_dir() -> Option<ProjectDirs> {
    ProjectDirs::from("com", "annieehler", env!("CARGO_PKG_NAME"))
}

/// The surface a keymap belongs to. A superset of [`Mode`]: besides the three
/// top-level modes it names the overlay/list surfaces (`modal`, `members`,
/// `form`) and the app-wide `global` section. Each surface resolves its own
/// section against an incoming key (see [`resolve`]); only `global` is resolved
/// at the app level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyContext {
    /// App-wide commands, resolved in `App::handle_key_event` with the capture +
    /// global-chord guard so Ctrl-chords work everywhere.
    Global,
    Home,
    Login,
    Register,
    /// A modal's button-row navigation (focus/activate/cancel).
    Modal,
    /// The members dialog (select/unshare).
    Members,
    /// Shared field navigation for every form body (login/register/todo/list/
    /// share/unlock).
    Form,
}

impl From<Mode> for KeyContext {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Home => KeyContext::Home,
            Mode::Login => KeyContext::Login,
            Mode::Register => KeyContext::Register,
        }
    }
}

/// A single keybinding's value: the command name it triggers plus whether it is
/// surfaced in the help footer. Deserializes from either a bare string
/// (`"quit"`, never shown) or a table (`{ command = "quit", show = true }`).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum CommandSpec {
    Bare(String),
    Full {
        // `action` is accepted as an alias for backward compatibility with configs
        // written before per-surface command names existed.
        #[serde(alias = "action")]
        command: String,
        #[serde(default)]
        show: bool,
    },
}

impl CommandSpec {
    /// The command name (a [`KeyContext`]-specific verb, parsed by each surface).
    pub fn command(&self) -> &str {
        match self {
            CommandSpec::Bare(s) => s,
            CommandSpec::Full { command, .. } => command,
        }
    }
    /// Whether to list this binding in the help footer.
    pub fn show(&self) -> bool {
        match self {
            CommandSpec::Bare(_) => false,
            CommandSpec::Full { show, .. } => *show,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct KeyBindings(pub HashMap<KeyContext, IndexMap<Vec<KeyEvent>, CommandSpec>>);

impl KeyBindings {
    /// The raw (string-command) bindings for a surface, if any were configured.
    pub fn context(&self, ctx: KeyContext) -> Option<&IndexMap<Vec<KeyEvent>, CommandSpec>> {
        self.0.get(&ctx)
    }
}

impl<'de> Deserialize<'de> for KeyBindings {
    #[tracing::instrument(skip(deserializer))]
    fn deserialize<D>(deserializer: D) -> anyhow::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parsed_map =
            HashMap::<KeyContext, IndexMap<String, CommandSpec>>::deserialize(deserializer)?;

        let keybindings = parsed_map
            .into_iter()
            .map(|(ctx, inner_map)| {
                let converted_inner_map = inner_map
                    .into_iter()
                    .map(|(key_str, cmd)| (parse_key_sequence(&key_str).unwrap(), cmd))
                    .collect();
                (ctx, converted_inner_map)
            })
            .collect();

        Ok(KeyBindings(keybindings))
    }
}

/// A human-readable label for a command name, for the help footer/cheatsheet:
/// `toggle_sidebar` → `toggle sidebar`.
pub fn command_label(cmd: &str) -> String {
    cmd.replace('_', " ")
}

/// Parse a single command name into a surface's typed verb enum (or [`Action`]
/// for the `global` surface). Verbs derive `Deserialize` with snake_case names,
/// so this round-trips through a JSON string scalar.
pub fn parse_command<V>(cmd: &str) -> Option<V>
where
    V: for<'de> Deserialize<'de>,
{
    serde_json::from_value(serde_json::Value::String(cmd.to_string())).ok()
}

/// Compile a surface's raw string-command bindings into a typed `keymap` once,
/// at config-load. Unknown command names are logged and skipped so a typo in one
/// binding can't break the rest of the surface.
#[tracing::instrument(skip(raw, parse))]
pub fn compile_keymap<V>(
    raw: Option<&IndexMap<Vec<KeyEvent>, CommandSpec>>,
    parse: impl Fn(&str) -> Option<V>,
) -> IndexMap<Vec<KeyEvent>, V> {
    let mut out = IndexMap::new();
    let Some(raw) = raw else {
        return out;
    };
    for (keys, spec) in raw {
        match parse(spec.command()) {
            Some(v) => {
                out.insert(keys.clone(), v);
            }
            None => warn!("Unknown keybinding command '{}'; skipping", spec.command()),
        }
    }
    out
}

/// Resolve a key against a compiled `keymap`, supporting multi-key sequences via
/// a per-surface `pending` buffer. A single-key match fires immediately; a miss
/// is buffered and retried as a sequence. The buffer self-clears once it can no
/// longer be the prefix of any binding, so a stray key never wedges it.
pub fn resolve<V: Clone>(
    keymap: &IndexMap<Vec<KeyEvent>, V>,
    pending: &mut Vec<KeyEvent>,
    key: KeyEvent,
) -> Option<V> {
    // Match against the same normalized form the stored bindings use.
    let key = normalize_key(key);
    if let Some(v) = keymap.get([key].as_slice()) {
        pending.clear();
        return Some(v.clone());
    }
    pending.push(key);
    if let Some(v) = keymap.get(pending.as_slice()) {
        pending.clear();
        return Some(v.clone());
    }
    let still_prefix = keymap.keys().any(|seq| seq.starts_with(pending.as_slice()));
    if !still_prefix {
        pending.clear();
    }
    None
}

#[tracing::instrument]
fn parse_key_event(raw: &str) -> anyhow::Result<KeyEvent, String> {
    let raw_lower = raw.to_ascii_lowercase();
    let (remaining, modifiers) = extract_modifiers(&raw_lower);
    Ok(normalize_key(parse_key_code_with_modifiers(
        remaining, modifiers,
    )?))
}

/// Normalize a key for binding lookup. A `Char` already encodes its shifted form
/// (`X`, `<`, `|`), and terminals are inconsistent about *also* reporting
/// `SHIFT`. Dropping `SHIFT` for char keys lets a binding like `shift-x` or `<`
/// match whether or not the terminal set the modifier. Non-char keys (so that
/// `shift-tab`/`BackTab` etc. stay distinct) are untouched.
pub fn normalize_key(mut key: KeyEvent) -> KeyEvent {
    if matches!(key.code, KeyCode::Char(_)) {
        key.modifiers.remove(KeyModifiers::SHIFT);
    }
    key
}

#[tracing::instrument]
fn extract_modifiers(raw: &str) -> (&str, KeyModifiers) {
    let mut modifiers = KeyModifiers::empty();
    let mut current = raw;

    loop {
        match current {
            rest if rest.starts_with("ctrl-") => {
                modifiers.insert(KeyModifiers::CONTROL);
                current = &rest[5..];
            }
            rest if rest.starts_with("alt-") || rest.starts_with("opt-") => {
                modifiers.insert(KeyModifiers::ALT);
                current = &rest[4..];
            }
            rest if rest.starts_with("shift-") => {
                modifiers.insert(KeyModifiers::SHIFT);
                current = &rest[6..];
            }
            _ => break, // break out of the loop if no known prefix is detected
        };
    }

    (current, modifiers)
}

#[tracing::instrument]
fn parse_key_code_with_modifiers(
    raw: &str,
    mut modifiers: KeyModifiers,
) -> anyhow::Result<KeyEvent, String> {
    let c = match raw {
        "esc" => KeyCode::Esc,
        "enter" => KeyCode::Enter,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pageup" => KeyCode::PageUp,
        "pagedown" => KeyCode::PageDown,
        "backtab" => {
            modifiers.insert(KeyModifiers::SHIFT);
            KeyCode::BackTab
        }
        "backspace" => KeyCode::Backspace,
        "delete" => KeyCode::Delete,
        "insert" => KeyCode::Insert,
        "f1" => KeyCode::F(1),
        "f2" => KeyCode::F(2),
        "f3" => KeyCode::F(3),
        "f4" => KeyCode::F(4),
        "f5" => KeyCode::F(5),
        "f6" => KeyCode::F(6),
        "f7" => KeyCode::F(7),
        "f8" => KeyCode::F(8),
        "f9" => KeyCode::F(9),
        "f10" => KeyCode::F(10),
        "f11" => KeyCode::F(11),
        "f12" => KeyCode::F(12),
        "space" => KeyCode::Char(' '),
        "hyphen" => KeyCode::Char('-'),
        "minus" => KeyCode::Char('-'),
        "tab" => KeyCode::Tab,
        c if c.len() == 1 => {
            let mut c = c.chars().next().unwrap();
            if modifiers.contains(KeyModifiers::SHIFT) {
                c = c.to_ascii_uppercase();
            }
            KeyCode::Char(c)
        }
        _ => return Err(format!("Unable to parse {raw}")),
    };
    Ok(KeyEvent::new(c, modifiers))
}

#[tracing::instrument]
pub fn key_event_to_string(key_event: &KeyEvent) -> String {
    let char;
    let key_code = match key_event.code {
        KeyCode::Backspace => "backspace",
        KeyCode::Enter => "enter",
        KeyCode::Left => "left",
        KeyCode::Right => "right",
        KeyCode::Up => "up",
        KeyCode::Down => "down",
        KeyCode::Home => "home",
        KeyCode::End => "end",
        KeyCode::PageUp => "pageup",
        KeyCode::PageDown => "pagedown",
        KeyCode::Tab => "tab",
        KeyCode::BackTab => "backtab",
        KeyCode::Delete => "delete",
        KeyCode::Insert => "insert",
        KeyCode::F(c) => {
            char = format!("f({c})");
            &char
        }
        KeyCode::Char(' ') => "space",
        KeyCode::Char(c) => {
            char = c.to_string();
            &char
        }
        KeyCode::Esc => "esc",
        KeyCode::Null => "",
        KeyCode::CapsLock => "",
        KeyCode::Menu => "",
        KeyCode::ScrollLock => "",
        KeyCode::Media(_) => "",
        KeyCode::NumLock => "",
        KeyCode::PrintScreen => "",
        KeyCode::Pause => "",
        KeyCode::KeypadBegin => "",
        KeyCode::Modifier(_) => "",
    };

    let mut modifiers = Vec::with_capacity(3);

    if key_event.modifiers.intersects(KeyModifiers::CONTROL) {
        modifiers.push("ctrl");
    }

    if key_event.modifiers.intersects(KeyModifiers::SHIFT) {
        modifiers.push("shift");
    }

    if key_event.modifiers.intersects(KeyModifiers::ALT) {
        modifiers.push("alt");
    }

    let mut key = modifiers.join("-");

    if !key.is_empty() {
        key.push('-');
    }
    key.push_str(key_code);

    key
}

#[tracing::instrument]
pub fn parse_key_sequence(raw: &str) -> anyhow::Result<Vec<KeyEvent>, String> {
    let sequences = raw.split('+').collect::<Vec<_>>();

    sequences.into_iter().map(parse_key_event).collect()
}

/// Render a key sequence back to its config string form (`space+e`). Inverse of
/// [`parse_key_sequence`]; used to build the on-screen key hints from the live
/// bindings.
pub fn key_sequence_to_string(seq: &[KeyEvent]) -> String {
    seq.iter()
        .map(key_event_to_string)
        .collect::<Vec<_>>()
        .join("+")
}

/// The first key bound to `verb` in `keymap` (config order), as a display string,
/// or `None` if the command is unbound. For one-key-per-command hints.
pub fn first_key_for<V: PartialEq>(
    keymap: &IndexMap<Vec<KeyEvent>, V>,
    verb: &V,
) -> Option<String> {
    keymap
        .iter()
        .find(|(_, v)| *v == verb)
        .map(|(seq, _)| key_sequence_to_string(seq))
}

/// Every key bound to `verb`, joined by `/` (e.g. `d/enter`), or `None` if the
/// command is unbound.
pub fn all_keys_for<V: PartialEq>(keymap: &IndexMap<Vec<KeyEvent>, V>, verb: &V) -> Option<String> {
    let keys: Vec<String> = keymap
        .iter()
        .filter(|(_, v)| *v == verb)
        .map(|(seq, _)| key_sequence_to_string(seq))
        .collect();
    (!keys.is_empty()).then(|| keys.join("/"))
}

#[derive(Clone, Debug, Default)]
pub struct Styles(pub HashMap<Mode, HashMap<String, Style>>);

impl<'de> Deserialize<'de> for Styles {
    #[tracing::instrument(skip(deserializer))]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parsed_map = HashMap::<Mode, HashMap<String, String>>::deserialize(deserializer)?;

        let styles = parsed_map
            .into_iter()
            .map(|(mode, inner_map)| {
                let converted_inner_map = inner_map
                    .into_iter()
                    .map(|(str, style)| (str, parse_style(&style)))
                    .collect();
                (mode, converted_inner_map)
            })
            .collect();

        Ok(Styles(styles))
    }
}

#[tracing::instrument]
pub fn parse_style(line: &str) -> Style {
    let (foreground, background) =
        line.split_at(line.to_lowercase().find("on ").unwrap_or(line.len()));
    let foreground = process_color_string(foreground);
    let background = process_color_string(&background.replace("on ", ""));

    let mut style = Style::default();
    if let Some(fg) = parse_color(&foreground.0) {
        style = style.fg(fg);
    }
    if let Some(bg) = parse_color(&background.0) {
        style = style.bg(bg);
    }
    style = style.add_modifier(foreground.1 | background.1);
    style
}

#[tracing::instrument]
fn process_color_string(color_str: &str) -> (String, Modifier) {
    let color = color_str
        .replace("grey", "gray")
        .replace("bright ", "")
        .replace("bold ", "")
        .replace("underline ", "")
        .replace("inverse ", "");

    let mut modifiers = Modifier::empty();
    if color_str.contains("underline") {
        modifiers |= Modifier::UNDERLINED;
    }
    if color_str.contains("bold") {
        modifiers |= Modifier::BOLD;
    }
    if color_str.contains("inverse") {
        modifiers |= Modifier::REVERSED;
    }

    (color, modifiers)
}

#[tracing::instrument]
fn parse_color(s: &str) -> Option<Color> {
    let s = s.trim_start();
    let s = s.trim_end();
    if s.contains("bright color") {
        let s = s.trim_start_matches("bright ");
        let c = s
            .trim_start_matches("color")
            .parse::<u8>()
            .unwrap_or_default();
        Some(Color::Indexed(c.wrapping_shl(8)))
    } else if s.contains("color") {
        let c = s
            .trim_start_matches("color")
            .parse::<u8>()
            .unwrap_or_default();
        Some(Color::Indexed(c))
    } else if s.contains("gray") {
        let c = 232
            + s.trim_start_matches("gray")
                .parse::<u8>()
                .unwrap_or_default();
        Some(Color::Indexed(c))
    } else if s.contains("rgb") {
        let red = (s.as_bytes()[3] as char).to_digit(10).unwrap_or_default() as u8;
        let green = (s.as_bytes()[4] as char).to_digit(10).unwrap_or_default() as u8;
        let blue = (s.as_bytes()[5] as char).to_digit(10).unwrap_or_default() as u8;
        let c = 16 + red * 36 + green * 6 + blue;
        Some(Color::Indexed(c))
    } else if s == "bold black" {
        Some(Color::Indexed(8))
    } else if s == "bold red" {
        Some(Color::Indexed(9))
    } else if s == "bold green" {
        Some(Color::Indexed(10))
    } else if s == "bold yellow" {
        Some(Color::Indexed(11))
    } else if s == "bold blue" {
        Some(Color::Indexed(12))
    } else if s == "bold magenta" {
        Some(Color::Indexed(13))
    } else if s == "bold cyan" {
        Some(Color::Indexed(14))
    } else if s == "bold white" {
        Some(Color::Indexed(15))
    } else if s == "black" {
        Some(Color::Indexed(0))
    } else if s == "red" {
        Some(Color::Indexed(1))
    } else if s == "green" {
        Some(Color::Indexed(2))
    } else if s == "yellow" {
        Some(Color::Indexed(3))
    } else if s == "blue" {
        Some(Color::Indexed(4))
    } else if s == "magenta" {
        Some(Color::Indexed(5))
    } else if s == "cyan" {
        Some(Color::Indexed(6))
    } else if s == "white" {
        Some(Color::Indexed(7))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::action::Action;

    #[test]
    fn test_parse_style_default() {
        let style = parse_style("");
        assert_eq!(style, Style::default());
    }

    #[test]
    fn test_parse_style_foreground() {
        let style = parse_style("red");
        assert_eq!(style.fg, Some(Color::Indexed(1)));
    }

    #[test]
    fn test_parse_style_background() {
        let style = parse_style("on blue");
        assert_eq!(style.bg, Some(Color::Indexed(4)));
    }

    #[test]
    fn test_parse_style_modifiers() {
        let style = parse_style("underline red on blue");
        assert_eq!(style.fg, Some(Color::Indexed(1)));
        assert_eq!(style.bg, Some(Color::Indexed(4)));
    }

    #[test]
    fn test_process_color_string() {
        let (color, modifiers) = process_color_string("underline bold inverse gray");
        assert_eq!(color, "gray");
        assert!(modifiers.contains(Modifier::UNDERLINED));
        assert!(modifiers.contains(Modifier::BOLD));
        assert!(modifiers.contains(Modifier::REVERSED));
    }

    #[test]
    fn test_parse_color_rgb() {
        let color = parse_color("rgb123");
        let expected = 16 + 36 + 2 * 6 + 3;
        assert_eq!(color, Some(Color::Indexed(expected)));
    }

    #[test]
    fn test_parse_color_unknown() {
        let color = parse_color("unknown");
        assert_eq!(color, None);
    }

    #[test]
    fn test_config() -> anyhow::Result<()> {
        let c = Config::new()?;
        let spec = c
            .keybindings
            .0
            .get(&KeyContext::Global)
            .unwrap()
            .get(&parse_key_sequence("q").unwrap_or_default())
            .unwrap();
        assert_eq!(spec.command(), "quit");
        assert!(spec.show());
        Ok(())
    }

    #[test]
    fn resolve_single_and_multi_key() {
        let mut km: IndexMap<Vec<KeyEvent>, &'static str> = IndexMap::new();
        km.insert(parse_key_sequence("q").unwrap(), "quit");
        km.insert(parse_key_sequence("space+e").unwrap(), "toggle");

        let mut pending = Vec::new();
        // Single key fires immediately and leaves no pending state.
        assert_eq!(
            resolve(&km, &mut pending, parse_key_event("q").unwrap()),
            Some("quit")
        );
        assert!(pending.is_empty());

        // A multi-key sequence buffers the prefix, then fires on completion.
        assert_eq!(
            resolve(&km, &mut pending, parse_key_event("space").unwrap()),
            None
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(
            resolve(&km, &mut pending, parse_key_event("e").unwrap()),
            Some("toggle")
        );
        assert!(pending.is_empty());

        // A dead prefix self-clears so a stray key can't wedge the buffer.
        assert_eq!(
            resolve(&km, &mut pending, parse_key_event("space").unwrap()),
            None
        );
        assert_eq!(
            resolve(&km, &mut pending, parse_key_event("x").unwrap()),
            None
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn compile_keymap_skips_unknown_commands() {
        let mut raw: IndexMap<Vec<KeyEvent>, CommandSpec> = IndexMap::new();
        raw.insert(
            parse_key_sequence("q").unwrap(),
            CommandSpec::Bare("quit".into()),
        );
        raw.insert(
            parse_key_sequence("z").unwrap(),
            CommandSpec::Bare("not_a_command".into()),
        );
        let compiled = compile_keymap(Some(&raw), parse_command::<Action>);
        assert_eq!(
            compiled.get(&parse_key_sequence("q").unwrap()),
            Some(&Action::Quit)
        );
        assert!(compiled.get(&parse_key_sequence("z").unwrap()).is_none());
    }

    #[test]
    fn test_simple_keys() {
        assert_eq!(
            parse_key_event("a").unwrap(),
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty())
        );

        assert_eq!(
            parse_key_event("enter").unwrap(),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::empty())
        );

        assert_eq!(
            parse_key_event("esc").unwrap(),
            KeyEvent::new(KeyCode::Esc, KeyModifiers::empty())
        );
    }

    #[test]
    fn test_with_modifiers() {
        assert_eq!(
            parse_key_event("ctrl-a").unwrap(),
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL)
        );

        assert_eq!(
            parse_key_event("alt-enter").unwrap(),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT)
        );

        assert_eq!(
            parse_key_event("shift-esc").unwrap(),
            KeyEvent::new(KeyCode::Esc, KeyModifiers::SHIFT)
        );
    }

    #[test]
    fn test_multiple_modifiers() {
        assert_eq!(
            parse_key_event("ctrl-alt-a").unwrap(),
            KeyEvent::new(
                KeyCode::Char('a'),
                KeyModifiers::CONTROL | KeyModifiers::ALT
            )
        );

        assert_eq!(
            parse_key_event("ctrl-shift-enter").unwrap(),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL | KeyModifiers::SHIFT)
        );
    }

    #[test]
    fn test_reverse_multiple_modifiers() {
        assert_eq!(
            key_event_to_string(&KeyEvent::new(
                KeyCode::Char('a'),
                KeyModifiers::CONTROL | KeyModifiers::ALT
            )),
            "ctrl-alt-a".to_string()
        );
    }

    #[test]
    fn test_invalid_keys() {
        assert!(parse_key_event("invalid-key").is_err());
        assert!(parse_key_event("ctrl-invalid-key").is_err());
    }

    #[test]
    fn test_case_insensitivity() {
        assert_eq!(
            parse_key_event("CTRL-a").unwrap(),
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL)
        );

        assert_eq!(
            parse_key_event("AlT-eNtEr").unwrap(),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::ALT)
        );
    }
}
