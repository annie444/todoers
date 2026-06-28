use std::io::{Stdout, stdout};
use std::ops::{Deref, DerefMut};
use std::time::Duration;

use crossterm::cursor;
use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event as CrosstermEvent, EventStream, KeyEvent, KeyEventKind, MouseEvent,
};
use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen};
use futures::{FutureExt, StreamExt};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::error;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Init,
    Quit,
    Error,
    Closed,
    Tick,
    Render,
    FocusGained,
    FocusLost,
    Paste(String),
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
}

pub struct Tui {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
    pub task: JoinHandle<()>,
    pub cancellation_token: CancellationToken,
    pub event_rx: UnboundedReceiver<Event>,
    pub event_tx: UnboundedSender<Event>,
    pub frame_rate: f64,
    pub tick_rate: f64,
    pub mouse: bool,
    pub paste: bool,
}

impl Tui {
    #[tracing::instrument]
    pub fn new() -> anyhow::Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        Ok(Self {
            terminal: Terminal::new(CrosstermBackend::new(stdout()))?,
            task: tokio::spawn(async {}),
            cancellation_token: CancellationToken::new(),
            event_rx,
            event_tx,
            frame_rate: 60.0,
            tick_rate: 4.0,
            mouse: false,
            paste: false,
        })
    }

    #[tracing::instrument(skip(self))]
    pub fn mouse(mut self, mouse: bool) -> Self {
        self.mouse = mouse;
        self
    }

    #[tracing::instrument(skip(self))]
    pub fn paste(mut self, paste: bool) -> Self {
        self.paste = paste;
        self
    }

    #[tracing::instrument(skip(self))]
    pub fn start(&mut self) {
        self.cancel(); // Cancel any existing task
        self.cancellation_token = CancellationToken::new();
        let event_loop = Self::event_loop(
            self.event_tx.clone(),
            self.cancellation_token.clone(),
            self.tick_rate,
            self.frame_rate,
        );
        self.task = tokio::spawn(async {
            event_loop.await;
        });
    }

    #[tracing::instrument(skip(event_tx, cancellation_token))]
    async fn event_loop(
        event_tx: UnboundedSender<Event>,
        cancellation_token: CancellationToken,
        tick_rate: f64,
        frame_rate: f64,
    ) {
        let mut event_stream = EventStream::new();
        let mut tick_interval = interval(Duration::from_secs_f64(1.0 / tick_rate));
        let mut render_interval = interval(Duration::from_secs_f64(1.0 / frame_rate));

        // if this fails, then it's likely a bug in the calling code
        event_tx
            .send(Event::Init)
            .expect("failed to send init event");
        loop {
            let event = tokio::select! {
                _ = cancellation_token.cancelled() => {
                    break;
                }
                _ = tick_interval.tick() => Event::Tick,
                _ = render_interval.tick() => Event::Render,
                crossterm_event = event_stream.next().fuse() => match crossterm_event {
                    Some(Ok(event)) => match event {
                        CrosstermEvent::Key(key) if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat => Event::Key(key),
                        CrosstermEvent::Mouse(mouse) => Event::Mouse(mouse),
                        CrosstermEvent::Resize(x, y) => Event::Resize(x, y),
                        CrosstermEvent::FocusLost => Event::FocusLost,
                        CrosstermEvent::FocusGained => Event::FocusGained,
                        CrosstermEvent::Paste(s) => Event::Paste(s),
                        _ => continue, // ignore other events
                    }
                    Some(Err(_)) => Event::Error,
                    None => break, // the event stream has stopped and will not produce any more events
                },
            };
            if event_tx.send(event).is_err() {
                // the receiver has been dropped, so there's no point in continuing the loop
                break;
            }
        }
        cancellation_token.cancel();
    }

    #[tracing::instrument(skip(self))]
    pub fn stop(&self) -> anyhow::Result<()> {
        self.cancel();
        let mut counter = 0;
        while !self.task.is_finished() {
            std::thread::sleep(Duration::from_millis(1));
            counter += 1;
            if counter > 50 {
                self.task.abort();
            }
            if counter > 100 {
                error!("Failed to abort task in 100 milliseconds for unknown reason");
                break;
            }
        }
        Ok(())
    }

    /// Grab the host terminal: raw mode + alternate screen (+ optional mouse /
    /// bracketed-paste). Pure terminal state — does **not** touch the event
    /// loop, so both `enter` (cold start) and `resume` (after a suspend) can
    /// reuse it.
    #[tracing::instrument(skip(self))]
    fn acquire_terminal(&mut self) -> anyhow::Result<()> {
        crossterm::terminal::enable_raw_mode()?;
        crossterm::execute!(stdout(), EnterAlternateScreen, cursor::Hide)?;
        if self.mouse {
            crossterm::execute!(stdout(), EnableMouseCapture)?;
        }
        if self.paste {
            crossterm::execute!(stdout(), EnableBracketedPaste)?;
        }
        Ok(())
    }

    /// Hand the terminal back to the shell: undo everything `acquire_terminal`
    /// set. Also event-loop-agnostic, shared by `exit` (shutdown) and `suspend`.
    #[tracing::instrument(skip(self))]
    fn restore_terminal(&mut self) -> anyhow::Result<()> {
        if crossterm::terminal::is_raw_mode_enabled()? {
            self.flush()?;
            if self.paste {
                crossterm::execute!(stdout(), DisableBracketedPaste)?;
            }
            if self.mouse {
                crossterm::execute!(stdout(), DisableMouseCapture)?;
            }
            crossterm::execute!(stdout(), LeaveAlternateScreen, cursor::Show)?;
            crossterm::terminal::disable_raw_mode()?;
        }
        Ok(())
    }

    /// Cold start: grab the terminal *and* spin up the event loop.
    #[tracing::instrument(skip(self))]
    pub fn enter(&mut self) -> anyhow::Result<()> {
        self.acquire_terminal()?;
        self.start();
        Ok(())
    }

    /// Full shutdown: stop the event loop, then release the terminal.
    #[tracing::instrument(skip(self))]
    pub fn exit(&mut self) -> anyhow::Result<()> {
        self.stop()?;
        self.restore_terminal()?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub fn cancel(&self) {
        self.cancellation_token.cancel();
    }

    /// Drop to the shell (Ctrl-Z). Restore the terminal but **leave the event
    /// loop running**: `SIGTSTP` freezes the whole process, so the loop task —
    /// and its single long-lived crossterm `EventStream` — freezes with it and
    /// thaws intact on `SIGCONT` (`fg`). We deliberately do *not* `stop()` here;
    /// re-creating the `EventStream` on resume leaves the input reader wedged
    /// (no key/tick/render events → a frozen frame). Blocks at `raise` until
    /// the process is foregrounded again.
    #[tracing::instrument(skip(self))]
    pub fn suspend(&mut self) -> anyhow::Result<()> {
        self.restore_terminal()?;
        #[cfg(not(windows))]
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGTSTP)?;
        Ok(())
    }

    /// Counterpart to [`suspend`](Self::suspend), run after `fg`. Re-grab the
    /// terminal only — the event loop from [`enter`](Self::enter) is still
    /// alive, so we must **not** `start()` a second one. The caller follows this
    /// with an `Action::ClearScreen` so ratatui forgets its cached buffer and
    /// repaints the (now-blank) alternate screen in full.
    #[tracing::instrument(skip(self))]
    pub fn resume(&mut self) -> anyhow::Result<()> {
        self.acquire_terminal()
    }

    pub async fn next_event(&mut self) -> Option<Event> {
        self.event_rx.recv().await
    }

    /// Non-blocking sibling of [`next_event`](Self::next_event): return a
    /// buffered event if one is ready, otherwise `None`. The event channel is
    /// unbounded and the producer runs at a fixed 60 Hz render / 4 Hz tick, so
    /// the UI loop uses this to *drain* a burst in one turn and coalesce the
    /// redundant renders rather than processing (and drawing) each one.
    pub fn try_next_event(&mut self) -> Option<Event> {
        self.event_rx.try_recv().ok()
    }
}

impl Deref for Tui {
    type Target = Terminal<CrosstermBackend<Stdout>>;

    fn deref(&self) -> &Self::Target {
        &self.terminal
    }
}

impl DerefMut for Tui {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.terminal
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.exit().unwrap();
    }
}
