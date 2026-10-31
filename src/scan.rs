//! Hot loop: one SIMD multi-literal pass over a buffer to find anchors, then
//! the full regex on a small window around each anchor.

use std::fs::File;

use aho_corasick::{AhoCorasick, MatchKind, packed};
use regex_automata::{Anchored, Input, meta};

use crate::{intervals::IntervalSet, patterns::Patterns, reader::read_at_full};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hit {
    pub off: u64,
    pub len: u64,
    pub pat: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pending {
    pub pat: u16,
    pub off: u64,
}

/// Granularity of the all-zero skip.
const ZERO_BLOCK: usize = 64 << 10;

/// Multi-literal anchor search. Teddy (SIMD, what ripgrep uses for small
/// literal sets) when the CPU supports it, Aho-Corasick otherwise.
struct Prefilter {
    teddy: Option<packed::Searcher>,
    ac: AhoCorasick,
}

impl Prefilter {
    fn new(lits: &[&[u8]]) -> Prefilter {
        let teddy = packed::Config::new()
            .match_kind(packed::MatchKind::LeftmostFirst)
            .builder()
            .extend(lits)
            .build();
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(lits)
            .expect("anchor automaton");
        Prefilter { teddy, ac }
    }

    /// Start of the leftmost anchor occurrence in `hay[start..end]`.
    #[inline]
    fn find(&self, hay: &[u8], start: usize, end: usize) -> Option<usize> {
        match &self.teddy {
            Some(t) => t
                .find_in(hay, aho_corasick::Span { start, end })
                .map(|m| m.start()),
            None => self
                .ac
                .find(aho_corasick::Input::new(hay).span(start..end))
                .map(|m| m.start()),
        }
    }
}

/// What a worker needs besides the chunk buffer: the source file for
/// windows that do not fit in the buffer, its size, and the rescued areas.
pub struct Source<'a> {
    pub file: &'a File,
    pub size: u64,
    pub rescued: &'a IntervalSet,
}

/// Per-thread state, reused across chunks (no allocation in the hot loop).
pub struct Worker {
    caches: Vec<meta::Cache>,
    scratch: Vec<u8>,
    pub hits: Vec<Hit>,
    pub pending: Vec<Pending>,
}

pub struct Scanner {
    pub pats: Patterns,
    pre: Prefilter,
    pub zero_skip: bool,
    pub maxmatch: u64,
}

fn is_zero(b: &[u8]) -> bool {
    // OR-reduce 4 KiB at a time: vectorizes, yet non-zero data exits early.
    b.chunks(4096).all(|c| {
        let mut it = c.chunks_exact(16);
        let acc = it
            .by_ref()
            .fold(0u128, |a, c| a | u128::from_ne_bytes(c.try_into().unwrap()));
        acc == 0 && it.remainder().iter().all(|&x| x == 0)
    })
}

impl Scanner {
    pub fn new(pats: Patterns, maxmatch: u64, zero_skip: bool) -> Scanner {
        let lits: Vec<&[u8]> = pats.anchors.iter().map(|(_, a)| *a).collect();
        // The zero skip relies on no anchor starting with a NUL byte.
        assert!(lits.iter().all(|a| !a.is_empty() && a[0] != 0));
        Scanner {
            pre: Prefilter::new(&lits),
            pats,
            zero_skip,
            maxmatch,
        }
    }

    pub fn uses_teddy(&self) -> bool {
        self.pre.teddy.is_some()
    }

    pub fn worker(&self) -> Worker {
        Worker {
            caches: self.pats.list.iter().map(|p| p.re.create_cache()).collect(),
            scratch: Vec::new(),
            hits: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// Scan `data` (image bytes starting at absolute offset `base`) for
    /// anchors starting in `[from, to)`. Bytes of `data` outside that range
    /// are context for the verification windows.
    pub fn scan(&self, w: &mut Worker, src: &Source, data: &[u8], base: u64, from: u64, to: u64) {
        let lo = (from.max(base) - base) as usize;
        let hi = ((to - base) as usize).min(data.len());
        if lo >= hi {
            return;
        }
        if !self.zero_skip {
            return self.scan_run(w, src, data, base, lo, hi);
        }
        // Search only maximal runs of non-zero blocks.
        let mut run: Option<usize> = None;
        let mut b = lo;
        while b < hi {
            let e = (b + ZERO_BLOCK).min(hi);
            if is_zero(&data[b..e]) {
                if let Some(s) = run.take() {
                    self.scan_run(w, src, data, base, s, b);
                }
            } else if run.is_none() {
                run = Some(b);
            }
            b = e;
        }
        if let Some(s) = run {
            self.scan_run(w, src, data, base, s, hi);
        }
    }

    fn scan_run(&self, w: &mut Worker, src: &Source, data: &[u8], base: u64, lo: usize, hi: usize) {
        // Let anchors that start before `hi` finish inside the context bytes.
        let lim = (hi + self.pats.max_anchor_len - 1).min(data.len());
        let mut pos = lo;
        while let Some(p) = self.pre.find(data, pos, lim) {
            if p >= hi {
                break;
            }
            for &(pi, lit) in &self.pats.anchors {
                if data[p..].starts_with(lit) {
                    self.verify(w, src, pi, base + p as u64, data, base);
                }
            }
            pos = p + 1;
        }
    }

    /// Bytes `[start, end)` pattern `pi` looks at around the anchor at `a`.
    pub fn window(&self, pi: usize, a: u64, size: u64) -> (u64, u64) {
        let p = &self.pats.list[pi];
        (
            a.saturating_sub(p.before),
            size.min(a + p.after.unwrap_or(self.maxmatch)),
        )
    }

    /// Run pattern `pi`'s regex around the anchor at absolute offset `a`.
    /// The window is taken from `data` when it fits, otherwise read from the
    /// source. Records hits, and a pending entry when the window touches
    /// areas that are not rescued yet. Returns whether the window was fully rescued.
    pub fn verify(
        &self,
        w: &mut Worker,
        src: &Source,
        pi: usize,
        a: u64,
        data: &[u8],
        base: u64,
    ) -> bool {
        let p = &self.pats.list[pi];
        let (ws, we) = self.window(pi, a, src.size);
        let Worker {
            caches,
            scratch,
            hits,
            pending,
        } = w;
        let win: &[u8] = if ws >= base && we <= base + data.len() as u64 {
            &data[(ws - base) as usize..(we - base) as usize]
        } else {
            scratch.resize((we.saturating_sub(ws)) as usize, 0);
            let n = read_at_full(src.file, scratch, ws).unwrap_or(0);
            &scratch[..n]
        };
        let rel = (a - ws) as usize;
        let cache = &mut caches[pi];
        if rel < win.len() {
            if p.anchored() {
                let input = Input::new(win).span(rel..win.len()).anchored(Anchored::Yes);
                if let Some(m) = p.re.search_with(cache, &input) {
                    hits.push(Hit {
                        off: ws + m.start() as u64,
                        len: m.len() as u64,
                        pat: pi as u16,
                    });
                }
            } else {
                // Keep matches that contain the anchor.
                let mut pos = 0;
                while pos <= win.len() {
                    let Some(m) =
                        p.re.search_with(cache, &Input::new(win).span(pos..win.len()))
                    else {
                        break;
                    };
                    if m.start() > rel {
                        break;
                    }
                    if m.end() > rel {
                        hits.push(Hit {
                            off: ws + m.start() as u64,
                            len: m.len() as u64,
                            pat: pi as u16,
                        });
                    }
                    pos = if m.is_empty() { m.end() + 1 } else { m.end() };
                }
            }
        }
        let ok = src.rescued.covers(ws, we);
        if !ok {
            pending.push(Pending {
                pat: pi as u16,
                off: a,
            });
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::samples;

    fn scan_all(data: &[u8], zero_skip: bool) -> Vec<Hit> {
        let sc = Scanner::new(Patterns::new(), 8 << 20, zero_skip);
        let f = File::open("/dev/null").unwrap();
        let rescued = IntervalSet::from_unsorted(vec![(0, data.len() as u64)]);
        let src = Source {
            file: &f,
            size: data.len() as u64,
            rescued: &rescued,
        };
        let mut w = sc.worker();
        sc.scan(&mut w, &src, data, 0, 0, data.len() as u64);
        assert!(w.pending.is_empty());
        w.hits.sort();
        w.hits
    }

    #[test]
    fn finds_every_sample_in_noise_with_and_without_zero_skip() {
        let pats = Patterns::new();
        let mut data = vec![0u8; 3 << 20];
        let mut expect = Vec::new();
        let mut off = 100_000usize;
        for (name, s, rel) in samples::all() {
            data[off..off + s.len()].copy_from_slice(&s);
            expect.push((off + rel, pats.index(name).unwrap() as u16));
            off += 150_001;
        }
        for zs in [false, true] {
            let got: Vec<_> = scan_all(&data, zs)
                .iter()
                .map(|h| (h.off as usize, h.pat))
                .collect();
            assert_eq!(got, expect, "zero_skip={zs}");
        }
    }

    #[test]
    fn chunk_boundaries_report_each_hit_once() {
        let pats = Patterns::new();
        let (name, s, rel) = samples::all()
            .into_iter()
            .find(|s| s.0 == "eth_keystore")
            .unwrap();
        let mut data = vec![b'.'; 1 << 20];
        let at = 500_000usize;
        data[at..at + s.len()].copy_from_slice(&s);
        let anchor = at + memchr::memmem::find(&s, b"\"ciphertext\"").unwrap();
        let sc = Scanner::new(Patterns::new(), 8 << 20, true);
        let f = File::open("/dev/null").unwrap();
        let rescued = IntervalSet::from_unsorted(vec![(0, data.len() as u64)]);
        let src = Source {
            file: &f,
            size: data.len() as u64,
            rescued: &rescued,
        };
        // Split exactly inside the anchor and around it; chunks share the full buffer as context.
        for cut in [anchor - 1, anchor, anchor + 1, anchor + 5, at, at + s.len()] {
            let mut w = sc.worker();
            sc.scan(&mut w, &src, &data, 0, 0, cut as u64);
            sc.scan(&mut w, &src, &data, 0, cut as u64, data.len() as u64);
            assert_eq!(w.hits.len(), 1, "cut={cut}");
            assert_eq!(w.hits[0].off as usize, at + rel);
            assert_eq!(w.hits[0].pat as usize, pats.index(name).unwrap());
        }
    }

    #[test]
    fn unrescued_window_is_pending() {
        let (_, s, _) = samples::all()
            .into_iter()
            .find(|s| s.0 == "btc_ckey")
            .unwrap();
        let mut data = vec![0u8; 4096];
        data[1000..1000 + s.len()].copy_from_slice(&s);
        let sc = Scanner::new(Patterns::new(), 8 << 20, true);
        let f = File::open("/dev/null").unwrap();
        let rescued = IntervalSet::from_unsorted(vec![(0, 1008)]);
        let src = Source {
            file: &f,
            size: 4096,
            rescued: &rescued,
        };
        let mut w = sc.worker();
        sc.scan(&mut w, &src, &data, 0, 0, 1008);
        assert_eq!(w.hits.len(), 1);
        assert_eq!(w.pending, vec![Pending { pat: 1, off: 1000 }]);
    }

    #[test]
    fn zero_check() {
        assert!(is_zero(&[0; 1000]));
        let mut v = vec![0; 1000];
        v[999] = 1;
        assert!(!is_zero(&v));
        v[999] = 0;
        v[3] = 1;
        assert!(!is_zero(&v));
    }
}
