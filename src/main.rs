//! wscan - fast scan of a raw device or disk image for crypto-wallet
//! structures. Groups nearby hits, scores them and carves the surrounding data.
//!
//! With a ddrescue mapfile only rescued ('+') areas are scanned, and wscan
//! keeps following the mapfile until ddrescue finishes, scanning newly
//! rescued areas as they appear. Progress is kept in OUTDIR/state.json, so an
//! interrupted scan resumes where it stopped. Read-only on the source.

use std::{
    cell::{Cell, RefCell},
    fs::File,
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering::Relaxed},
    thread,
    time::{Duration, Instant, SystemTime},
};

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use clap::Parser;

use wscan::{
    intervals::IntervalSet,
    mapfile,
    patterns::Patterns,
    progress::{Progress, fmt_bytes},
    reader::{self, IoMode, PassCfg, Stats},
    recover::{self, Finding, Recovery},
    report::{self, ReportCfg},
    scan::{Hit, Scanner, Source},
    state::State,
};

fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let t = s.trim_end_matches(['B', 'b']).trim_end_matches('i');
    let (num, mul) = match t.chars().last() {
        Some('K' | 'k') => (&t[..t.len() - 1], 1u64 << 10),
        Some('M' | 'm') => (&t[..t.len() - 1], 1 << 20),
        Some('G' | 'g') => (&t[..t.len() - 1], 1 << 30),
        Some('T' | 't') => (&t[..t.len() - 1], 1 << 40),
        _ => (t, 1),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n * mul)
        .map_err(|_| format!("bad size {s:?}"))
}

#[derive(Parser)]
#[command(
    version,
    about = "Fast crypto-wallet scan of a disk image or device (ddrescue-aware)."
)]
struct Cli {
    /// Disk image or block device (opened read-only).
    src: PathBuf,
    /// Output directory.
    #[arg(short, long, default_value = "wallet_hits")]
    out: PathBuf,
    /// ddrescue mapfile: scan only rescued areas, and follow ddrescue until it finishes.
    #[arg(short, long)]
    mapfile: Option<PathBuf>,
    /// With a mapfile: scan what is rescued now and exit instead of following ddrescue.
    #[arg(long)]
    once: bool,
    /// Max seconds between mapfile checks in follow mode (checked earlier when it changes).
    #[arg(long, default_value_t = 30)]
    poll: u64,
    /// Rewrite the report every N minutes while following ddrescue.
    #[arg(long, value_name = "MIN")]
    report_every: Option<u64>,
    /// Scan worker threads [default: min(8, CPUs)].
    #[arg(short, long)]
    jobs: Option<usize>,
    /// Bytes per read chunk.
    #[arg(long, default_value = "32M", value_parser = parse_size)]
    chunk: u64,
    /// I/O strategy.
    #[arg(long, value_enum, default_value_t = IoMode::Read)]
    io: IoMode,
    /// Cap the read rate (MiB/s), e.g. to leave disk bandwidth to a running ddrescue.
    #[arg(long, value_name = "MIB_S")]
    max_rate: Option<f64>,
    /// Use the idle I/O priority class.
    #[arg(long)]
    idle_io: bool,
    /// Scan all-zero blocks too (normally skipped; no anchor can start in them).
    #[arg(long)]
    no_zero_skip: bool,
    /// Skip rebuilding wallet files (OUTDIR/recovered) after the report.
    #[arg(long)]
    no_recover: bool,
    /// Forget previous progress and rescan everything.
    #[arg(long)]
    fresh: bool,
    /// Bytes kept before the first hit of a cluster.
    #[arg(long, env = "BEFORE", default_value = "65536", value_parser = parse_size)]
    before: u64,
    /// Bytes kept after the last hit of a cluster.
    #[arg(long, env = "AFTER", default_value = "262144", value_parser = parse_size)]
    after: u64,
    /// Hits closer than this are merged into one cluster.
    #[arg(long, env = "GAP", default_value = "1048576", value_parser = parse_size)]
    gap: u64,
    /// Max size of one carved file.
    #[arg(long, env = "MAXCARVE", default_value = "8388608", value_parser = parse_size)]
    maxcarve: u64,
    /// Max length read for an encrypted Electrum blob.
    #[arg(long, env = "MAXMATCH", default_value = "8388608", value_parser = parse_size)]
    maxmatch: u64,
}

static STOP: AtomicBool = AtomicBool::new(false);

fn current_size(mut f: &File) -> Result<u64> {
    Ok(f.seek(SeekFrom::End(0))?)
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Live recovery: each cluster of hits is recovered as soon as everything
/// it could still grow into, and the pages around it, have been scanned.
struct Live {
    rec: Recovery,
    done: BTreeSet<u64>,
    last: Instant,
}

impl Live {
    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        st: &State,
        file: &File,
        size: u64,
        pats: &Patterns,
        gap: u64,
        prog: &Progress,
        tag: &str,
        force: bool,
    ) {
        if !force && self.last.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.last = Instant::now();
        let hits = report::dedup(&st.hits);
        let reach = gap + recover::MARGIN;
        for c in report::clusters(pats, &hits, gap) {
            if self.done.contains(&c.start)
                || !st
                    .scanned
                    .covers(c.start.saturating_sub(reach), (c.end + reach).min(size))
            {
                continue;
            }
            self.done.insert(c.start);
            let lo = hits.partition_point(|h| h.off < c.start);
            let hi = hits.partition_point(|h| h.off < c.end);
            if let Err(e) = self.rec.add(file, size, pats, &hits[lo..hi], gap) {
                prog.println(format!("[!] recovery at offset {}: {e:#}", c.start));
            }
            for f in self.rec.take_findings() {
                prog.println(fmt_finding(&f, tag));
            }
        }
    }
}

fn fmt_finding(f: &Finding, tag: &str) -> String {
    let mut s = format!(
        "{tag} {} at offset {} ({:.2} GiB)\n      {}\n      -> recovered/{}",
        f.kind.to_uppercase(),
        f.offset,
        f.offset as f64 / (1u64 << 30) as f64,
        f.summary,
        f.file
    );
    if !f.addresses.is_empty() {
        s += &format!("\n      addresses: {}", f.addresses.join(", "));
        if f.more_addresses > 0 {
            s += &format!(" (+{} more in recovered/addresses.tsv)", f.more_addresses);
        }
    }
    s
}

fn hits_line(pats: &Patterns, counts: &[u64], strong: usize, found: usize) -> String {
    let parts: Vec<String> = counts
        .iter()
        .enumerate()
        .filter(|(_, n)| **n > 0)
        .map(|(i, n)| format!("{}={n}", pats.list[i].name))
        .collect();
    let list = if parts.is_empty() {
        "none yet".into()
    } else {
        parts.join(" ")
    };
    format!("hits: {list} | clusters with score>=50: {strong} | recovered: {found}")
}

fn strong_clusters(pats: &Patterns, hits: &[Hit], gap: u64) -> usize {
    report::clusters(pats, &report::dedup(hits), gap)
        .iter()
        .filter(|c| c.score >= 50)
        .count()
}

fn main() -> Result<()> {
    let a = Cli::parse();
    let file = File::open(&a.src).with_context(|| format!("cannot open {}", a.src.display()))?;
    reader::fadvise(&file, 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    let src_abs = std::path::absolute(&a.src)?.to_string_lossy().into_owned();

    let pats = Patterns::new();
    let mut st = State::open(&a.out, &src_abs, &pats, a.fresh)?;
    let scanner = Scanner::new(pats, a.maxmatch, !a.no_zero_skip);
    let pats = &scanner.pats;

    let cpus = thread::available_parallelism().map_or(1, |n| n.get());
    let jobs = a.jobs.unwrap_or(cpus.min(8)).max(1);
    let mut io = a.io;
    let direct = match io {
        IoMode::Direct => match reader::open_direct(&a.src) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("[!] O_DIRECT not usable here ({e}); falling back to --io read");
                io = IoMode::Read;
                None
            }
        },
        _ => None,
    };
    let cfg = PassCfg {
        jobs,
        chunk: a.chunk.max(1 << 20),
        // Context so that verification windows rarely need a separate read.
        pre: pats.list.iter().map(|p| p.before).max().unwrap_or(0),
        post: pats.list.iter().filter_map(|p| p.after).max().unwrap_or(0),
        io,
        max_rate: a.max_rate.unwrap_or(0.0) * (1u64 << 20) as f64,
        idle_io: a.idle_io,
    };
    let follow = a.mapfile.is_some() && !a.once;
    let rcfg = ReportCfg {
        before: a.before,
        after: a.after,
        gap: a.gap,
        maxcarve: a.maxcarve,
    };

    ctrlc::set_handler(|| {
        if STOP.swap(true, Relaxed) {
            std::process::exit(130);
        }
    })?;

    let prog = Progress::new();
    prog.println(format!(
        "[*] wscan: {jobs} workers, {} MiB chunks, io={io:?}, prefilter={}",
        cfg.chunk >> 20,
        if scanner.uses_teddy() {
            "Teddy (SIMD)"
        } else {
            "Aho-Corasick"
        }
    ));
    let mut counts = vec![0u64; pats.list.len()];
    for h in &st.hits {
        counts[h.pat as usize] += 1;
    }
    prog.set_hits(hits_line(
        pats,
        &counts,
        strong_clusters(pats, &st.hits, a.gap),
        0,
    ));
    let stats = Stats::default();
    let mut last_report = Instant::now();
    let live = RefCell::new(match a.no_recover {
        true => None,
        false => Some(Live {
            rec: Recovery::new(&a.out)?,
            done: BTreeSet::new(),
            last: Instant::now(),
        }),
    });
    let found = || live.borrow().as_ref().map_or(0, |l| l.rec.found);
    // Resumed scan: recover (and show) what earlier runs already found.
    if let Some(l) = live.borrow_mut().as_mut() {
        let size = current_size(&file)?;
        l.step(
            &st,
            &file,
            size,
            pats,
            a.gap,
            &prog,
            "[=] found earlier:",
            true,
        );
    }

    loop {
        let size = current_size(&file)?;
        let map = a.mapfile.as_deref().map(mapfile::read).transpose()?;
        let rescued = match &map {
            Some(m) => m.rescued.clamp(size),
            None => IntervalSet::from_unsorted(vec![(0, size)]),
        };
        // ddrescue done (or no ddrescue): this pass sees the final data.
        let final_pass = map.as_ref().is_none_or(|m| m.finished()) || a.once;
        let status = |extra: &str| -> String {
            let bad = stats.bad_bytes.load(Relaxed);
            let bad = if bad > 0 {
                format!(" | {} unreadable (zero-filled)", fmt_bytes(bad))
            } else {
                String::new()
            };
            match &map {
                Some(m) => format!(
                    "ddrescue: {}{} - rescued {} of {} ({:.1}%){extra}{bad}",
                    m.phase(),
                    m.pass.map(|p| format!(" pass {p}")).unwrap_or_default(),
                    fmt_bytes(m.rescued.total()),
                    fmt_bytes(m.extent),
                    100.0 * m.rescued.total() as f64 / m.extent.max(1) as f64
                ),
                None => format!("source: {}{extra}{bad}", fmt_bytes(size)),
            }
        };
        prog.set_status(status(""));
        let src = Source {
            file: &file,
            size,
            rescued: &rescued,
        };

        // 1. Re-check anchors whose window touched unrescued data, once it is rescued.
        let mut w = scanner.worker();
        let recheck: Vec<_> = st
            .pending
            .iter()
            .copied()
            .filter(|p| {
                let (s, e) = scanner.window(p.pat as usize, p.off, size);
                final_pass || rescued.covers(s, e)
            })
            .collect();
        for p in recheck {
            st.pending.remove(&p);
            scanner.verify(&mut w, &src, p.pat as usize, p.off, &[], 0);
        }
        st.pending.extend(w.pending.drain(..));
        for h in &w.hits {
            counts[h.pat as usize] += 1;
        }
        st.add_hits(pats, &w.hits)?;

        // 2. Scan what is rescued but not scanned yet.
        let todo = rescued.subtract(&st.scanned);
        let total = rescued.total();
        if !todo.is_empty() {
            prog.println(format!(
                "[*] {} to scan ({} of {} available so far)",
                fmt_bytes(todo.total()),
                fmt_bytes(total),
                fmt_bytes(size)
            ));
        }
        prog.start_pass(total - todo.total(), total);
        let done = Cell::new(total - todo.total());
        let st_cell = RefCell::new(&mut st);
        let counts_cell = RefCell::new(&mut counts);
        let (last_save, last_strong) = (Cell::new(Instant::now()), Cell::new(Instant::now()));
        let mut err = None;
        let tick = || {
            prog.set_pos(done.get());
            if let Some(l) = live.borrow_mut().as_mut() {
                l.step(
                    &st_cell.borrow(),
                    &file,
                    size,
                    pats,
                    a.gap,
                    &prog,
                    "[+] FOUND",
                    false,
                );
            }
            if last_strong.get().elapsed() >= Duration::from_secs(5) {
                last_strong.set(Instant::now());
                let st = st_cell.borrow();
                prog.set_hits(hits_line(
                    pats,
                    &counts_cell.borrow(),
                    strong_clusters(pats, &st.hits, a.gap),
                    found(),
                ));
                prog.set_status(status(""));
            }
        };
        reader::run_pass(
            &scanner,
            &file,
            direct.as_ref(),
            size,
            &rescued,
            &todo,
            &cfg,
            &STOP,
            &stats,
            |r| {
                let mut st = st_cell.borrow_mut();
                st.scanned.insert(r.start, r.end);
                st.pending.extend(r.pending);
                {
                    let mut c = counts_cell.borrow_mut();
                    for h in &r.hits {
                        c[h.pat as usize] += 1;
                    }
                }
                if let Err(e) = st.add_hits(pats, &r.hits) {
                    err.get_or_insert(e);
                }
                if !r.hits.is_empty() {
                    // Refresh the hit line on the tick below.
                    last_strong.set(
                        Instant::now()
                            .checked_sub(Duration::from_secs(5))
                            .unwrap_or(last_strong.get()),
                    );
                }
                if last_save.get().elapsed() >= Duration::from_secs(10) {
                    last_save.set(Instant::now());
                    if let Err(e) = st.save(pats) {
                        err.get_or_insert(e);
                    }
                }
                done.set(done.get() + (r.end - r.start));
                drop(st);
                tick();
            },
            tick,
        )?;
        if let Some(e) = err {
            return Err(e);
        }
        st.save(pats)?;
        prog.set_pos(done.get());
        if let Some(l) = live.borrow_mut().as_mut() {
            l.step(&st, &file, size, pats, a.gap, &prog, "[+] FOUND", true);
        }
        prog.set_hits(hits_line(
            pats,
            &counts,
            strong_clusters(pats, &st.hits, a.gap),
            found(),
        ));

        if STOP.load(Relaxed) || final_pass || !follow {
            break;
        }
        if a.report_every
            .is_some_and(|m| last_report.elapsed() >= Duration::from_secs(m * 60))
        {
            prog.println("[*] writing intermediate report");
            prog.suspend(|| report::write(&a.out, &file, size, pats, &st.hits, &rcfg))?;
            last_report = Instant::now();
        }

        // 3. Wait for ddrescue to rescue more.
        let mapf = a.mapfile.as_deref().unwrap();
        let (m0, t0) = (mtime(mapf), Instant::now());
        while !STOP.load(Relaxed) {
            let el = t0.elapsed();
            if el >= Duration::from_secs(a.poll)
                || (el >= Duration::from_secs(5) && mtime(mapf) != m0)
            {
                break;
            }
            let left = a.poll.saturating_sub(el.as_secs());
            prog.set_status(status(&format!(
                " | waiting for ddrescue (next check <= {left}s)"
            )));
            thread::sleep(Duration::from_millis(500));
        }
        if STOP.load(Relaxed) {
            break;
        }
    }

    prog.finish();
    st.save(pats)?;
    drop(live);
    let size = current_size(&file)?;
    if STOP.load(Relaxed) {
        eprintln!(
            "[!] Interrupted - progress saved, run the same command to resume. Writing report of what was found so far."
        );
    }
    if !st.pending.is_empty() {
        eprintln!(
            "[*] {} hit(s) sit next to unrescued areas; they are re-checked on the next run.",
            st.pending.len()
        );
    }
    let bad = stats.bad_bytes.load(Relaxed);
    if bad > 0 {
        eprintln!(
            "[!] {} could not be read (I/O errors) and were treated as zeros.",
            fmt_bytes(bad)
        );
    }
    report::write(&a.out, &file, size, pats, &st.hits, &rcfg)?;
    if !a.no_recover {
        recover::run(&a.out, &file, size, pats, &report::dedup(&st.hits), a.gap)?;
    }
    if STOP.load(Relaxed) {
        std::process::exit(130);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("32M"), Ok(32 << 20));
        assert_eq!(parse_size("65536"), Ok(65536));
        assert_eq!(parse_size("1GiB"), Ok(1 << 30));
        assert_eq!(parse_size("8k"), Ok(8192));
        assert!(parse_size("x").is_err());
    }
}
