//! Progress display: indicatif bars on a terminal, a plain log line every
//! 10 s otherwise.

use std::{
    cell::Cell,
    io::IsTerminal,
    time::{Duration, Instant},
};

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};

pub fn fmt_bytes(n: u64) -> String {
    let n = n as f64;
    if n >= (1u64 << 40) as f64 {
        format!("{:.2} TiB", n / (1u64 << 40) as f64)
    } else {
        format!("{:.1} GiB", n / (1u64 << 30) as f64)
    }
}

pub struct Progress {
    bar: ProgressBar,
    status: ProgressBar,
    hits: ProgressBar,
    mp: MultiProgress,
    tty: bool,
    last_plain: Cell<Instant>,
    pass_start: Cell<(Instant, u64)>,
}

impl Progress {
    pub fn new() -> Progress {
        let tty = std::io::stderr().is_terminal();
        let target = if tty {
            ProgressDrawTarget::stderr_with_hz(5)
        } else {
            ProgressDrawTarget::hidden()
        };
        let mp = MultiProgress::with_draw_target(target);
        let bar = mp.add(ProgressBar::new(0));
        bar.set_style(
            ProgressStyle::with_template(
                "{elapsed_precise} [{wide_bar:.cyan/blue}] {binary_bytes}/{binary_total_bytes} \
                 {binary_bytes_per_sec:>12} ETA {eta:>4}",
            )
            .unwrap()
            .progress_chars("=> "),
        );
        let line = ProgressStyle::with_template("  {msg}").unwrap();
        let status = mp.add(ProgressBar::new(0).with_style(line.clone()));
        let hits = mp.add(ProgressBar::new(0).with_style(line));
        Progress {
            bar,
            status,
            hits,
            mp,
            tty,
            last_plain: Cell::new(Instant::now()),
            pass_start: Cell::new((Instant::now(), 0)),
        }
    }

    /// New scan pass: `done` bytes of `total` available are already scanned.
    pub fn start_pass(&self, done: u64, total: u64) {
        self.bar.set_length(total);
        self.bar.set_position(done);
        self.bar.reset_eta();
        self.pass_start.set((Instant::now(), done));
    }

    pub fn set_pos(&self, done: u64) {
        self.bar.set_position(done);
        if !self.tty && self.last_plain.get().elapsed() >= Duration::from_secs(10) {
            self.last_plain.set(Instant::now());
            let (t0, d0) = self.pass_start.get();
            let rate = (done - d0) as f64 / t0.elapsed().as_secs_f64().max(1e-3);
            let total = self.bar.length().unwrap_or(0);
            let eta = if rate > 0.0 {
                (total.saturating_sub(done)) as f64 / rate / 60.0
            } else {
                0.0
            };
            eprintln!(
                "[*] {} / {}  {:.0} MiB/s  ETA {eta:.1} min | {} | {}",
                fmt_bytes(done),
                fmt_bytes(total),
                rate / (1 << 20) as f64,
                self.status.message(),
                self.hits.message()
            );
        }
    }

    pub fn set_status(&self, msg: String) {
        self.status.set_message(msg);
    }

    pub fn set_hits(&self, msg: String) {
        self.hits.set_message(msg);
    }

    /// Print a line above the bars (or plainly when not on a terminal).
    pub fn println(&self, msg: impl AsRef<str>) {
        if self.tty {
            self.bar.println(msg.as_ref());
        } else {
            eprintln!("{}", msg.as_ref());
        }
    }

    /// Run `f` with the bars hidden (for output on stdout).
    pub fn suspend<R>(&self, f: impl FnOnce() -> R) -> R {
        self.mp.suspend(f)
    }

    pub fn finish(&self) {
        self.hits.finish();
        self.status.finish();
        self.bar.finish();
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self::new()
    }
}
