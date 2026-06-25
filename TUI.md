# TUI.md

Architecture outline for **`todoers`** — the ratatui terminal client **binary**. It is a
thin UI shell over the **`todoers-client`** library, which holds the keys and does all crypto
(see [ENCRYPTION.md](./ENCRYPTION.md)), owns the local-first SQLite store, and talks to the
blind relay over HTTP/WS (see [API.md](./API.md)). This document covers the **UI
architecture** in the `todoers` crate: the event loop, the `Component` trait, actions, modes,
modals, and how networked work stays off the render loop. Anything touching crypto, the DB
(`db.rs`), networking (`net/`), or session keys lives in `todoers-client/src/`, not here.

## Build note

The `todoers` binary depends on `todoers-client`, which uses compile-time-checked
`sqlx::query!` macros for some queries, so **building needs `CLIENT_DATABASE_URL`** pointing
at a migrated SQLite DB (see CLAUDE.md → Build & run; one-time: `cd todoers-client && sqlx
database create && sqlx migrate run --source db/migrations`). The binary also has a
`vergen-gix` build script that reads git/cargo/build info at compile time (used in
`--version`), so a git repo must be present to build. Run it with `cargo todoers` (alias for
`run -p todoers --`).

## Entry point

`main.rs` builds a multi-thread Tokio runtime, then: init error/logging hooks →
parse `Cli` (`cli.rs`) → load `Config` (`config.rs`) → **unlock the database encryption key**
(load-or-create the SQLCipher key envelope, then device auto-unlock or, as a fallback, prompt
for the recovery key on stdin — see [ENCRYPTION.md](./ENCRYPTION.md)) → open the encrypted
SQLite `Db` (`todoers-client`'s `db.rs`) with that key → on first run print the recovery key
→ load any local `account` → construct `App` and call `App::run`.

## The Component architecture (`app.rs`)

`App` owns the whole client: a `Config`, the SQLite `Db`, the cached `account`
and unlocked `acct_keys`, the current `Mode`, a `HashMap<Mode, Box<dyn
Component>>`, an optional `Modal` overlay, persistent chrome (`Keys` footer,
`ErrorBar`), and an mpsc `Action` channel.

The main loop in `App::run` is a `tokio::select!` over two sources — terminal
events and replies from the store-worker — followed by draining the action queue:

```
select! { Tui event → on_event ; worker WorkerMsg → handle_worker_msg }
   →  handle_actions  →  render
```

1. **`on_event`** takes the `Event` the select produced and turns it into
   `Action`s on the channel. It also routes the raw event to either the open
   modal *or* the active mode component (never both), so the background stays
   inert behind an overlay. After the first event, the loop **drains the rest of
   the buffered terminal events** (`Tui::try_next_event`) in the same turn: the
   producer emits ~64 events/s (60 Render + 4 Tick) into an unbounded channel, so
   draining lets a burst collapse into a single coalesced render rather than one
   render per event — the loop drops stale frames instead of snowballing a backlog.
2. **`handle_worker_msg`** installs a store-worker reply: a `ViewSnapshot`
   refreshes the shared `ViewModel` (and requests one `Render`); request/reply
   messages (`FullItem`/`Members`) stash data and emit a "ready" action so the
   modal opens on the next `handle_actions` pass (which has `tui`).
3. **`handle_actions`** (synchronous) drains the whole channel each turn,
   coalescing renders to at most one. For each action `App` mutates UI/global
   state and forwards it to the modal or active component's `update`. **It never
   blocks on the store** — mutations become `StoreCommand`s sent to the worker.
4. **`render`** draws the active mode in the body, then the modal on top, then the
   error bar and keybinding footer. The background mode is redrawn every frame so
   a modal floats over the live workspace as a clean backdrop (and switching
   modals leaves no stale cells). The one exception is the **auth prompt** (no
   verified account yet): there is no workspace to show behind the login/register
   dialog, so the background draw is skipped to keep the per-frame cost low
   instead of redrawing the full `Home` workspace under the dialog every frame.

### Store-worker (`store_worker.rs`)

All db/crypto/Loro work runs on a dedicated tokio task (actor pattern). The UI
future is non-`Send` (`Rc<RefCell<ViewModel>>`, `Box<dyn Component>`), but the
`Store` (which owns the session keys + `LoroDoc`s) is `Send`, so it moves to the
worker. The UI sends `StoreCommand`s and receives `WorkerMsg`s — chiefly
`ViewSnapshot`s of plain `Send` data it installs into the view-model. The worker
remembers the current `(targets, sort)` and emits a fresh snapshot after every
mutating command; the UI re-sends `SetView` whenever pane targets/sort/count
change. This keeps input and render responsive *during* store mutations.

### The `Component` trait (`components/mod.rs`)

Every screen and widget implements `Component`. Only `draw` is required; the rest
default to no-ops:

- `register_action_handler(tx)` / `register_config_handler(config)` — wire the
  component to the action channel and live config.
- `init(area)` — one-time setup.
- `handle_events` → `handle_key_event` / `handle_mouse_event` — turn input into an
  optional `Action`.
- `update(action)` — react to an action, optionally emitting a follow-up.
- `draw(frame, area)` — render (required).
- `placement()` — layout constraint (defaults to fill).

The companion `Captures` trait says whether a component is currently swallowing
text input (see [Input capture](#input-capture)).

## Actions (`action.rs`)

`Action` is the single message enum — the only way state changes propagate.
Notable members: lifecycle (`Tick`, `Render`, `Resize`, `Suspend`, `Quit`,
`ClearScreen`), navigation (`SetMode`, `AuthChooser`, `*Modal`, `CloseModal`),
input/focus (`StartCapture`, `StopCapture`, `SubmitInput`, `SubmitForm`,
`FocusButtons`), and auth (`Register`, `Login`, `Unlock`, `Keys`).

> **Secrets in actions:** `Action::Register`, `Login`, and `Unlock` carry the
> password (`Zeroizing<String>`). They are deliberately redacted in `Display` and
> excluded from the `debug!` in `handle_actions` — **never log them verbatim.**
> `Keys` carries the unlocked secret keys; treat it the same way.

## Modes (`app.rs`)

`Mode` (`Home`, `Register`, `Login`) selects the active component and which
keybinding map is live. `Mode` implements `Captures` so the app knows, per mode,
whether typed keys should be swallowed by a focused form. Switching modes
(`handle_switch_mode`) rebuilds the keybinding footer and re-inits the component.

## Modals (`components/modal.rs`)

A `Modal` is a centered overlay that floats over whatever mode is running. It is
**mode-agnostic** — not in the `modes` map; `App` owns it as `Option<Modal>`,
routes events to it while open, and draws it last (it `Clear`s its own region).
It's a title + an arbitrary `body` component + a row of `Button`s; focus cycles
between buttons, and an interactive body (a form) can hold focus first.
Constructors: `Modal::new` (explicit buttons + `esc_action`), `Modal::message`
(single Close), `Modal::form` (Submit/Cancel around a form body).

The auth gate is driven entirely by modals: on `Tick`, if there is no verified
account, `App` emits `AuthChooser` → the user picks `LoginModal` or
`RegisterModal` → the form modal collects credentials and emits `Login` /
`Register`.

## Input capture

While a text field is focused, `App.capturing` is set. In `handle_key_event`,
captured keystrokes bypass keybinding dispatch so they reach the input — **except**
"global chords" (`is_global_chord`: any Ctrl/Alt combo), which always dispatch so
the user can quit/suspend/switch forms from inside a field or modal. A bare key
(`?`, letters, `Esc`, `Tab`, `Enter`) is left for the focused form/modal.

## Networked work runs off the UI loop

`App` never blocks the render loop on I/O. Registration, login, and unlock
`tokio::spawn` a task that calls into the `net/` module and feeds results back as
`Action`s (`Error`, or `Keys` + `StopCapture` + `CloseModal` + `SetMode`).
CPU-bound Argon2id KDF work is wrapped in `spawn_blocking`. Key separation (both in
`todoers-client`):

- **`net/`** — HTTP transport only (reqwest); the two-message OPAQUE
  register/login flows and the offline fallback path.
- **`auth.rs`** — pure (builds/consumes wire DTOs, no I/O), so it stays
  unit-testable without a network.

`net::login` recovers keys from the server escrow on success and, when that fails
and a local `account` exists, falls back to an offline unlock. On first login on a
device it persists a local account so future launches recognize the user and
offline unlock works.

## Config (`config.rs`)

Defaults are baked in via `include_str!("../app_config.toml")`, then layered over
user files (toml/json/yaml/ini) from the XDG config dir. Keybindings and styles
parse from strings (e.g. `"ctrl-d"`, `"underline red on blue"`). The `Keys`
footer component renders the active mode's bindings (it's empty until
`register_config_handler` supplies the config — `refresh_keys` rebuilds it on
every mode switch).

## Components inventory (`components/`)

| Component | Role |
| --- | --- |
| `Home` | Landing mode. |
| `Register` / `Login` / `Unlock` | Auth form bodies (live inside form modals). |
| `Modal` | Centered overlay host (title + body + buttons). |
| `Prompt` | Static message body (e.g. the auth chooser). |
| `Help` | Per-mode keybinding cheatsheet (message modal). |
| `Button` | Focusable button that emits an `Action` when activated. |
| `TextInput` | Single text field; drives `capturing`. |
| `Keys` | Persistent keybinding footer. |
| `ErrorBar` | Transient timed error banner. |

## Local store (`todoers-client`'s `db.rs`)

SQLite, local-first, **SQLCipher-encrypted at rest**: the materialized CRDT, an outbound
queue for offline edits, sync cursors against the server log, cached wrapped keys, the
`account` row, and a member directory for offline signature verification. The `Db` and all
queries live in `todoers-client`; the binary just holds a handle. See the at-rest class rules
in `todoers-client/db/migrations/0001_init.sql` and [ENCRYPTION.md](./ENCRYPTION.md).
