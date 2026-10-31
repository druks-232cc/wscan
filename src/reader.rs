//! I/O pipeline: one sequential reader thread feeds large chunks to N scan
//! workers through a recycled buffer pool. Spinning disks (and RAIDZ) see one
//! sequential stream instead of N competing ones.

use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    fs::File,
    io,
    os::unix::fs::FileExt,
    os::unix::io::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
    },
    thread,
    time::{Duration, Instant},
};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded, unbounded};

use crate::{
    intervals::IntervalSet,
    scan::{Hit, Pending, Scanner, Source},
};

/// Alignment of buffers and read offsets (O_DIRECT requirement).
pub const ALIGN: u64 = 4096;

fn align_down(x: u64) -> u64 {
    x & !(ALIGN - 1)
}

fn align_up(x: u64) -> u64 {
    (x + ALIGN - 1) & !(ALIGN - 1)
}

/// Heap buffer aligned to `ALIGN`.
pub struct AlignedBuf {
    ptr: *mut u8,
    cap: usize,
}

unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    pub fn new(cap: usize) -> AlignedBuf {
        let cap = align_up(cap.max(1) as u64) as usize;
        let ptr = unsafe { alloc_zeroed(Layout::from_size_align(cap, ALIGN as usize).unwrap()) };
        assert!(!ptr.is_null(), "out of memory allocating {cap} bytes");
        AlignedBuf { ptr, cap }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.cap) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.cap) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe {
            dealloc(
                self.ptr,
                Layout::from_size_align(self.cap, ALIGN as usize).unwrap(),
            )
        }
    }
}

/// Read-only shared mapping of the whole source.
pub struct Mmap {
    ptr: *mut libc::c_void,
    len: usize,
}

unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    pub fn new(file: &File, len: u64) -> io::Result<Mmap> {
        let len = len.max(1) as usize;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        unsafe { libc::madvise(ptr, len, libc::MADV_SEQUENTIAL) };
        Ok(Mmap { ptr, len })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

/// pread until `buf` is full or EOF. Returns the number of bytes read.
pub fn read_at_full(file: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match file.read_at(&mut buf[n..], off + n as u64) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Like `read_at_full`, but unreadable areas (bad sectors on a raw device)
/// are retried in smaller pieces and finally zero-filled and counted in `bad`.
fn read_robust(file: &File, buf: &mut [u8], off: u64, bad: &AtomicU64) -> usize {
    match read_at_full(file, buf, off) {
        Ok(n) => n,
        Err(_) if buf.len() as u64 <= ALIGN => {
            buf.fill(0);
            bad.fetch_add(buf.len() as u64, Relaxed);
            buf.len()
        }
        Err(_) => {
            let step = if buf.len() > 1 << 20 {
                1 << 20
            } else {
                ALIGN as usize
            };
            let mut done = 0;
            for piece in buf.chunks_mut(step) {
                let len = piece.len();
                let n = read_robust(file, piece, off + done as u64, bad);
                done += n;
                if n < len {
                    break; // EOF
                }
            }
            done
        }
    }
}

pub fn fadvise(file: &File, off: u64, len: u64, advice: libc::c_int) {
    unsafe { libc::posix_fadvise(file.as_raw_fd(), off as i64, len as i64, advice) };
}

/// Lower this thread's I/O priority to the idle class (best effort; ZFS and
/// some schedulers ignore it).
fn set_idle_io() {
    const IOPRIO_WHO_PROCESS: libc::c_long = 1;
    const IOPRIO_CLASS_IDLE: libc::c_long = 3;
    unsafe {
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            0,
            IOPRIO_CLASS_IDLE << 13,
        )
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum IoMode {
    /// Buffered pread from one sequential reader thread.
    Read,
    /// Memory-map the source; workers fault pages in.
    Mmap,
    /// O_DIRECT reads that bypass the page cache (falls back to `read`).
    Direct,
}

pub struct PassCfg {
    pub jobs: usize,
    pub chunk: u64,
    /// Context bytes read before / after each chunk for verification windows.
    pub pre: u64,
    pub post: u64,
    pub io: IoMode,
    /// Bytes per second, 0 = unlimited.
    pub max_rate: f64,
    pub idle_io: bool,
}

#[derive(Default)]
pub struct Stats {
    pub bad_bytes: AtomicU64,
}

/// A piece of the scan: anchors starting in `[from, end)` are reported,
/// `[start, end)` is what gets marked as scanned. `from < start` only at the
/// start of a scan interval, so that anchors straddling into a newly rescued
/// area are found.
#[derive(Clone, Copy, Debug)]
pub struct Chunk {
    pub start: u64,
    pub end: u64,
    pub from: u64,
}

pub fn plan_chunks(todo: &IntervalSet, chunk: u64, max_anchor_len: usize) -> Vec<Chunk> {
    let mut out = Vec::new();
    for &(s, e) in todo.as_slice() {
        let mut c = s;
        while c < e {
            let ce = (c + chunk).min(e);
            let from = if c == s {
                s.saturating_sub(max_anchor_len as u64 - 1)
            } else {
                c
            };
            out.push(Chunk {
                start: c,
                end: ce,
                from,
            });
            c = ce;
        }
    }
    out
}

enum Data {
    Buf(AlignedBuf, usize),
    Map(Arc<Mmap>, usize, usize),
}

struct Job {
    chunk: Chunk,
    base: u64,
    data: Data,
}

impl Job {
    fn bytes(&self) -> &[u8] {
        match &self.data {
            Data::Buf(b, len) => &b.as_slice()[..*len],
            Data::Map(m, s, e) => &m.as_slice()[*s..*e],
        }
    }
}

pub struct ChunkResult {
    pub start: u64,
    pub end: u64,
    pub hits: Vec<Hit>,
    pub pending: Vec<Pending>,
}

#[allow(clippy::too_many_arguments)]
fn reader_buffered(
    file: &File,
    chunks: &[Chunk],
    size: u64,
    cfg: &PassCfg,
    pool: (usize, usize),
    free_rx: &Receiver<AlignedBuf>,
    job_tx: &Sender<Job>,
    stop: &AtomicBool,
    stats: &Stats,
) {
    // Buffers are allocated only when all existing ones are in use, so a
    // disk-bound scan touches little memory and fast media get more read-ahead.
    let (nbuf, cap) = pool;
    let mut allocated = 0;
    if cfg.idle_io {
        set_idle_io();
    }
    let (t0, mut read_total) = (Instant::now(), 0u64);
    let mut carry = AlignedBuf::new((cfg.pre + cfg.post + 4 * ALIGN) as usize);
    let (mut carry_base, mut carry_len) = (0u64, 0usize);
    let drop_cache = cfg.io == IoMode::Read;
    for (k, c) in chunks.iter().enumerate() {
        if stop.load(Relaxed) {
            return;
        }
        let lo = align_down(c.from.saturating_sub(cfg.pre));
        // Not clamped to size: O_DIRECT needs aligned lengths, EOF ends the read anyway.
        let hi = align_up((c.end + cfg.post).min(size));
        let mut buf = match free_rx.try_recv() {
            Ok(b) => b,
            Err(_) if allocated < nbuf => {
                allocated += 1;
                AlignedBuf::new(cap)
            }
            Err(_) => match free_rx.recv() {
                Ok(b) => b,
                Err(_) => return,
            },
        };
        let dst = buf.as_mut_slice();
        let mut filled = 0usize;
        if carry_len > 0 && carry_base <= lo && lo < carry_base + carry_len as u64 {
            let n = ((carry_base + carry_len as u64).min(hi) - lo) as usize;
            let s = (lo - carry_base) as usize;
            dst[..n].copy_from_slice(&carry.as_slice()[s..s + n]);
            filled = n;
        }
        let want = (hi - lo) as usize;
        if filled < want {
            let n = read_robust(
                file,
                &mut dst[filled..want],
                lo + filled as u64,
                &stats.bad_bytes,
            );
            filled += n;
            read_total += n as u64;
            if cfg.max_rate > 0.0 {
                let ahead = read_total as f64 / cfg.max_rate - t0.elapsed().as_secs_f64();
                if ahead > 0.0 {
                    thread::sleep(Duration::from_secs_f64(ahead));
                }
            }
        }
        let len = filled.min(size.saturating_sub(lo) as usize);
        // Keep the tail the next chunk needs as context, so every byte is read once.
        carry_len = 0;
        if let Some(n) = chunks.get(k + 1) {
            let nlo = align_down(n.from.saturating_sub(cfg.pre));
            let end = lo + len as u64;
            if nlo >= lo && nlo < end && (end - nlo) as usize <= carry.cap {
                let s = (nlo - lo) as usize;
                carry.as_mut_slice()[..len - s].copy_from_slice(&dst[s..len]);
                (carry_base, carry_len) = (nlo, len - s);
            }
        }
        if drop_cache {
            fadvise(file, lo, len as u64, libc::POSIX_FADV_DONTNEED);
        }
        if job_tx
            .send(Job {
                chunk: *c,
                base: lo,
                data: Data::Buf(buf, len),
            })
            .is_err()
        {
            return;
        }
    }
}

fn reader_mmap(
    map: &Arc<Mmap>,
    chunks: &[Chunk],
    size: u64,
    cfg: &PassCfg,
    job_tx: &Sender<Job>,
    stop: &AtomicBool,
) {
    for c in chunks {
        if stop.load(Relaxed) {
            return;
        }
        let lo = c.from.saturating_sub(cfg.pre);
        let hi = (c.end + cfg.post).min(size);
        let data = Data::Map(map.clone(), lo as usize, hi as usize);
        if job_tx
            .send(Job {
                chunk: *c,
                base: lo,
                data,
            })
            .is_err()
        {
            return;
        }
    }
}

/// Scan `todo` (sub-ranges of the source) with the pipeline. `on_result` is
/// called on the calling thread for every finished chunk, `on_tick` at least
/// every 200 ms. Chunks still queued when `stop` is set are dropped unscanned.
#[allow(clippy::too_many_arguments)]
pub fn run_pass(
    scanner: &Scanner,
    file: &File,
    direct: Option<&File>,
    size: u64,
    rescued: &IntervalSet,
    todo: &IntervalSet,
    cfg: &PassCfg,
    stop: &AtomicBool,
    stats: &Stats,
    mut on_result: impl FnMut(ChunkResult),
    mut on_tick: impl FnMut(),
) -> io::Result<()> {
    let chunks = plan_chunks(todo, cfg.chunk, scanner.pats.max_anchor_len);
    if chunks.is_empty() {
        return Ok(());
    }
    let map = if cfg.io == IoMode::Mmap {
        Some(Arc::new(Mmap::new(file, size)?))
    } else {
        None
    };
    let nbuf = cfg.jobs + 2;
    let cap =
        (cfg.chunk + cfg.pre + cfg.post + scanner.pats.max_anchor_len as u64 + 2 * ALIGN) as usize;
    let (free_tx, free_rx) = unbounded::<AlignedBuf>();
    let (job_tx, job_rx) = bounded::<Job>(nbuf);
    let (res_tx, res_rx) = unbounded::<ChunkResult>();
    let src = Source {
        file,
        size,
        rescued,
    };

    thread::scope(|s| {
        let reader_file = direct.unwrap_or(file);
        let chunks = &chunks;
        s.spawn(move || match &map {
            Some(m) => reader_mmap(m, chunks, size, cfg, &job_tx, stop),
            None => reader_buffered(
                reader_file,
                chunks,
                size,
                cfg,
                (nbuf, cap),
                &free_rx,
                &job_tx,
                stop,
                stats,
            ),
        });
        for _ in 0..cfg.jobs {
            let (job_rx, free_tx, res_tx, src) =
                (job_rx.clone(), free_tx.clone(), res_tx.clone(), &src);
            s.spawn(move || {
                if cfg.idle_io {
                    set_idle_io();
                }
                let mut w = scanner.worker();
                for job in job_rx {
                    if !stop.load(Relaxed) {
                        let c = job.chunk;
                        scanner.scan(&mut w, src, job.bytes(), job.base, c.from, c.end);
                        let r = ChunkResult {
                            start: c.start,
                            end: c.end,
                            hits: std::mem::take(&mut w.hits),
                            pending: std::mem::take(&mut w.pending),
                        };
                        let _ = res_tx.send(r);
                    }
                    if let Data::Buf(b, _) = job.data {
                        let _ = free_tx.send(b);
                    }
                }
            });
        }
        drop((job_rx, res_tx));
        loop {
            match res_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(r) => on_result(r),
                Err(RecvTimeoutError::Timeout) => on_tick(),
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    });
    Ok(())
}

/// Open the source with O_DIRECT, checking that the filesystem accepts it.
pub fn open_direct(path: &std::path::Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(path)?;
    let mut probe = AlignedBuf::new(ALIGN as usize);
    f.read_at(probe.as_mut_slice(), 0)?;
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_plan() {
        let todo = IntervalSet::from_unsorted(vec![(0, 250), (1000, 1100)]);
        let c = plan_chunks(&todo, 100, 21);
        let v: Vec<_> = c.iter().map(|c| (c.start, c.end, c.from)).collect();
        assert_eq!(
            v,
            vec![
                (0, 100, 0),
                (100, 200, 100),
                (200, 250, 200),
                (1000, 1100, 980)
            ]
        );
    }

    #[test]
    fn robust_read_short_at_eof() {
        let dir = std::env::temp_dir().join(format!("wscan-rr-{}", std::process::id()));
        std::fs::write(&dir, vec![7u8; 10_000]).unwrap();
        let f = File::open(&dir).unwrap();
        let mut b = vec![0u8; 20_000];
        let bad = AtomicU64::new(0);
        assert_eq!(read_robust(&f, &mut b, 4096, &bad), 10_000 - 4096);
        assert_eq!(bad.load(Relaxed), 0);
        std::fs::remove_file(dir).unwrap();
    }
}
