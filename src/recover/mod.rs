//! Rebuild usable wallet files from what the scan found (OUTDIR/recovered/).
//!
//! - JSON wallets (Ethereum keystores, MetaMask vaults, Electrum, blockchain.info):
//!   the complete object around the hit, validated.
//! - Bitcoin Core wallets: database pages (Berkeley DB or SQLite) around the
//!   hits are parsed one by one, so split-up files are handled too. Records
//!   are grouped per wallet and written as a Bitcoin Core dump file
//!   (`bitcoin-wallet createfromdump`); contiguous files are also carved whole.
//! - Unencrypted private keys, verified with secp256k1, exported as WIF.

pub mod bdb;
pub mod json;
pub mod keys;
pub mod sqlite;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
    fs::{self, File},
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde_json::Value;

use crate::{intervals::IntervalSet, patterns::Patterns, reader::read_at_full, report, scan::Hit};
use keys::{Key, hex, sha256, sha256d};

/// Bytes around Bitcoin Core hits searched for database pages.
pub const MARGIN: u64 = 4 << 20;
/// Read granularity when sweeping regions; pages start on 512-byte sectors.
const WINDOW: u64 = 16 << 20;
const SECTOR: u64 = 512;
/// Largest wallet file carved whole.
const MAX_CARVE: u64 = 1 << 30;

struct Row {
    kind: &'static str,
    offset: u64,
    file: String,
    notes: String,
}

fn read(src: &File, size: u64, off: u64, len: u64) -> Vec<u8> {
    let len = len.min(size.saturating_sub(off)) as usize;
    let mut b = vec![0u8; len];
    let n = read_at_full(src, &mut b, off).unwrap_or(0);
    b.truncate(n);
    b
}

/// Record type of a Bitcoin Core wallet key: compact-size length + lowercase name.
pub fn rec_type(key: &[u8]) -> Option<&str> {
    let n = *key.first()? as usize;
    let t = key.get(1..1 + n)?;
    if n == 0 || n > 40 || !t.iter().all(|c| c.is_ascii_lowercase() || *c == b'_') {
        return None;
    }
    std::str::from_utf8(t).ok()
}

/// Bitcoin compact size at `b[o]`: (value, offset after it).
fn compact_size(b: &[u8], o: usize) -> Option<(usize, usize)> {
    match *b.get(o)? {
        n @ 0..=0xfc => Some((n as usize, o + 1)),
        0xfd => Some((
            u16::from_le_bytes(b.get(o + 1..o + 3)?.try_into().ok()?) as usize,
            o + 3,
        )),
        0xfe => Some((
            u32::from_le_bytes(b.get(o + 1..o + 5)?.try_into().ok()?) as usize,
            o + 5,
        )),
        _ => None,
    }
}

fn vec_at(b: &[u8], o: usize) -> Option<&[u8]> {
    let (n, o) = compact_size(b, o)?;
    b.get(o..o + n)
}

/// Private key of a `key` / `walletdescriptorkey` record, checked against
/// the public key in the record key.
fn plain_key(k: &[u8], v: &[u8]) -> Option<Key> {
    let t = rec_type(k)?;
    let pub_at = 1 + t.len() + if t == "walletdescriptorkey" { 32 } else { 0 };
    let pubkey = vec_at(k, pub_at)?;
    let key = keys::parse_der(vec_at(v, 0)?)?;
    (key.pubkey == pubkey).then_some(key)
}

const KEY_TYPES: &[&str] = &[
    "key",
    "wkey",
    "ckey",
    "mkey",
    "hdchain",
    "walletdescriptor",
    "walletdescriptorkey",
    "walletdescriptorckey",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fmt {
    Bdb,
    Sqlite,
}

/// One recovered Bitcoin Core wallet.
struct Wallet {
    fmt: Fmt,
    base: u64,
    ps: u64,
    file_len: Option<u64>,
    records: BTreeMap<Vec<u8>, Vec<u8>>,
    notes: Vec<String>,
}

// ---- Berkeley DB --------------------------------------------------------------

/// Log sequence number: orders versions of the same page.
type Lsn = (u32, u32);
/// Records of one leaf page.
type Leaf = (Lsn, Vec<(Vec<u8>, bdb::Val)>);

#[derive(Default)]
struct BdbGroup {
    last_pgno: Option<u32>,
    pages: BTreeSet<u32>,
    leaves: Vec<Leaf>,
    overflow: HashMap<u32, (u32, Vec<u8>)>,
    fragments: usize,
}

fn bdb_wallets(src: &File, size: u64, pages: Vec<(u64, bdb::Page)>) -> Vec<Wallet> {
    // Pages of one contiguous file share `disk offset - pgno * page size`.
    let mut groups: BTreeMap<(u64, u32), BdbGroup> = BTreeMap::new();
    for (off, p) in pages {
        let Some(base) = off.checked_sub(p.pgno as u64 * p.ps as u64) else {
            continue;
        };
        let g = groups.entry((base, p.ps)).or_default();
        g.pages.insert(p.pgno);
        match p.kind {
            bdb::Kind::Meta { last_pgno } if p.pgno == 0 => g.last_pgno = Some(last_pgno),
            bdb::Kind::Meta { .. } => {}
            bdb::Kind::Leaf(recs) => {
                let recs: Vec<_> = recs
                    .into_iter()
                    .filter(|(k, _)| rec_type(k).is_some())
                    .collect();
                if !recs.is_empty() {
                    g.leaves.push((p.lsn, recs));
                }
            }
            bdb::Kind::Overflow { next, data } => {
                g.overflow.insert(p.pgno, (next, data));
            }
        }
    }
    // A fragment of a split file has no meta page at its implied base: attach
    // it to the nearest wallet file it fits in (same page size, page numbers
    // in range and not already present).
    let frags: Vec<_> = groups
        .iter()
        .filter(|(_, g)| g.last_pgno.is_none())
        .map(|(k, _)| *k)
        .collect();
    for fk in frags {
        let f = &groups[&fk];
        let Some(&maxp) = f.pages.last() else {
            continue;
        };
        let target = groups
            .iter()
            .filter(|((_, ps), g)| {
                *ps == fk.1
                    && g.last_pgno.is_some_and(|l| l >= maxp)
                    && g.pages.is_disjoint(&f.pages)
            })
            .min_by_key(|((b, _), _)| b.abs_diff(fk.0))
            .map(|(k, _)| *k);
        if let Some(tk) = target {
            let f = groups.remove(&fk).unwrap();
            let t = groups.get_mut(&tk).unwrap();
            t.pages.extend(f.pages);
            t.leaves.extend(f.leaves);
            t.overflow.extend(f.overflow);
            t.fragments += 1;
        }
    }

    let mut out = Vec::new();
    for ((base, ps), g) in groups {
        if g.leaves.is_empty() {
            continue;
        }
        let ps64 = ps as u64;
        let overflow_page = |pgno: u32| -> Option<(u32, Vec<u8>)> {
            if let Some(p) = g.overflow.get(&pgno) {
                return Some(p.clone());
            }
            // Not seen during the sweep: try where a contiguous file would have it.
            let b = read(src, size, base + pgno as u64 * ps64, ps64);
            match bdb::parse(&b, Some(ps)) {
                Some(bdb::Page {
                    pgno: n,
                    kind: bdb::Kind::Overflow { next, data },
                    ..
                }) if n == pgno => Some((next, data)),
                _ => None,
            }
        };
        let mut best: BTreeMap<Vec<u8>, (Lsn, Option<Vec<u8>>)> = BTreeMap::new();
        for (lsn, recs) in &g.leaves {
            for (k, v) in recs {
                if best.get(k).is_some_and(|(l, _)| l >= lsn) {
                    continue;
                }
                let val = match v {
                    bdb::Val::Inline(b) => Some(b.clone()),
                    bdb::Val::Overflow { pgno, len } => {
                        let (mut data, mut p) = (Vec::new(), *pgno);
                        while data.len() < *len as usize && p != 0 {
                            let Some((next, d)) = overflow_page(p) else {
                                break;
                            };
                            data.extend_from_slice(&d);
                            p = next;
                        }
                        (data.len() == *len as usize).then_some(data)
                    }
                };
                best.insert(k.clone(), (*lsn, val));
            }
        }
        let mut notes = Vec::new();
        let missing = best.values().filter(|(_, v)| v.is_none()).count();
        if missing > 0 {
            notes.push(format!(
                "{missing} large record(s) lost (overflow pages not found)"
            ));
        }
        if g.fragments > 0 {
            notes.push(format!(
                "file was split: {} extra fragment(s) merged",
                g.fragments
            ));
        }
        if g.last_pgno.is_none() {
            notes.push("no file header found: may be only part of a wallet".into());
        }
        let records = best
            .into_iter()
            .filter_map(|(k, (_, v))| v.map(|v| (k, v)))
            .collect();
        let file_len = g.last_pgno.map(|l| (l as u64 + 1) * ps64);
        out.push(Wallet {
            fmt: Fmt::Bdb,
            base,
            ps: ps64,
            file_len,
            records,
            notes,
        });
    }
    out
}

// ---- SQLite -------------------------------------------------------------------

struct SqlRow {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    /// Payload start, first overflow page and total payload size when spilled.
    spill: Option<(Vec<u8>, u32, usize)>,
}

#[derive(Default)]
struct SqlGroup {
    header: Option<(u64, sqlite::Header)>,
    first: Option<u64>,
    rows: Vec<SqlRow>,
    fragments: usize,
}

fn descriptor_ids<'a>(rows: impl Iterator<Item = &'a SqlRow>, defining: bool) -> BTreeSet<Vec<u8>> {
    rows.filter_map(|r| {
        let t = rec_type(&r.key)?;
        let ok = if defining {
            t == "walletdescriptor"
        } else {
            t.starts_with("walletdescriptor")
        };
        r.key
            .get(1 + t.len()..1 + t.len() + 32)
            .filter(|_| ok)
            .map(|id| id.to_vec())
    })
    .collect()
}

/// True when every child pointer of the database's table b-tree interior
/// pages lands on a b-tree page: the file is stored in one piece.
fn sqlite_contiguous(src: &File, size: u64, base: u64, h: sqlite::Header) -> bool {
    let (ps, n) = (h.ps as usize, h.pages as usize);
    if n as u64 * ps as u64 > MAX_CARVE {
        return false;
    }
    let data = read(src, size, base, n as u64 * ps as u64);
    if data.len() < n * ps {
        return false;
    }
    let kind = |pg: u32| -> Option<u8> {
        let i = (pg as usize).checked_sub(1).filter(|&i| i < n)?;
        Some(data[i * ps + if i == 0 { 100 } else { 0 }])
    };
    (1..=n as u32).all(|pg| {
        let off = (pg as usize - 1) * ps;
        let hdr = off + if pg == 1 { 100 } else { 0 };
        if data[hdr] != 0x05 {
            return true;
        }
        let cells = u16::from_be_bytes([data[hdr + 3], data[hdr + 4]]) as usize;
        let mut children = vec![sqlite::u32be(&data, hdr + 8)];
        for c in 0..cells {
            let ptr = u16::from_be_bytes([data[hdr + 12 + 2 * c], data[hdr + 13 + 2 * c]]) as usize;
            if ptr + 4 > ps {
                return false;
            }
            children.push(sqlite::u32be(&data, off + ptr));
        }
        children
            .into_iter()
            .all(|c| matches!(kind(c), Some(0x05 | 0x0D)))
    })
}

fn sqlite_wallets(
    src: &File,
    size: u64,
    headers: &[(u64, sqlite::Header)],
    leaves: Vec<(u64, usize, Vec<sqlite::Cell>)>,
) -> Vec<Wallet> {
    // Group 0..headers.len(): pages inside a database's extent; beyond: per sweep region.
    let mut groups: BTreeMap<usize, SqlGroup> = BTreeMap::new();
    for (off, region, cells) in leaves {
        let owner = headers.iter().position(|(h, hd)| {
            off >= *h && off < h + hd.pages as u64 * hd.ps as u64 && (off - h) % hd.ps as u64 == 0
        });
        let gk = owner.unwrap_or(headers.len() + region);
        let g = groups.entry(gk).or_default();
        g.first = Some(g.first.map_or(off, |f| f.min(off)));
        if let Some(i) = owner {
            g.header = Some(headers[i]);
        }
        for c in cells {
            let row = if c.overflow.is_none() {
                sqlite::two_blobs(&c.local).map(|(key, value)| SqlRow {
                    key,
                    value: Some(value),
                    spill: None,
                })
            } else {
                sqlite::first_blob(&c.local).map(|key| SqlRow {
                    key,
                    value: None,
                    spill: Some((c.local.clone(), c.overflow.unwrap(), c.total)),
                })
            };
            if let Some(r) = row.filter(|r| rec_type(&r.key).is_some()) {
                g.rows.push(r);
            }
        }
    }
    // Headerless fragments join the database defining the descriptors they reference.
    let frags: Vec<usize> = groups
        .iter()
        .filter(|(_, g)| g.header.is_none())
        .map(|(k, _)| *k)
        .collect();
    for fk in frags {
        let refs = descriptor_ids(groups[&fk].rows.iter(), false);
        let target = groups
            .iter()
            .filter(|(_, g)| g.header.is_some())
            .find(|(_, g)| !descriptor_ids(g.rows.iter(), true).is_disjoint(&refs))
            .map(|(k, _)| *k);
        if let Some(tk) = target {
            let f = groups.remove(&fk).unwrap();
            let t = groups.get_mut(&tk).unwrap();
            t.rows.extend(f.rows);
            t.fragments += 1;
        }
    }

    let mut out = Vec::new();
    for (_, g) in groups {
        // Overflow pages carry no page number, so chains are only followed
        // when the file is verifiably in one piece.
        let contiguous = g.fragments == 0
            && g.header
                .is_some_and(|(b, h)| sqlite_contiguous(src, size, b, h));
        let (mut records, mut lost, mut conflicts) = (BTreeMap::new(), 0, 0);
        for r in g.rows {
            let value = match (r.value, r.spill, g.header) {
                (Some(v), _, _) => Some(v),
                (None, Some((mut payload, mut p, total)), Some((base, h))) if contiguous => {
                    let usable = (h.ps - h.reserved) as u64;
                    while payload.len() < total && p != 0 {
                        let page = read(src, size, base + (p as u64 - 1) * h.ps as u64, usable);
                        if page.len() < 4 {
                            break;
                        }
                        let take = (total - payload.len()).min(page.len() - 4);
                        payload.extend_from_slice(&page[4..4 + take]);
                        p = sqlite::u32be(&page, 0);
                        if p > h.pages {
                            break;
                        }
                    }
                    sqlite::two_blobs(&payload).map(|(_, v)| v)
                }
                _ => None,
            };
            let Some(v) = value else {
                lost += 1;
                continue;
            };
            match records.get(&r.key) {
                Some(old) if *old != v => conflicts += 1,
                Some(_) => {}
                None => {
                    records.insert(r.key, v);
                }
            }
        }
        let mut notes = Vec::new();
        if lost > 0 {
            notes.push(format!(
                "{lost} large record(s) lost (overflow pages not found)"
            ));
        }
        if g.header.is_some() && !contiguous && g.fragments == 0 {
            notes.push("file is split on disk".into());
        }
        if conflicts > 0 {
            notes.push(format!(
                "{conflicts} record(s) found with two different values; kept the first"
            ));
        }
        if g.fragments > 0 {
            notes.push(format!(
                "file was split: {} extra fragment(s) merged",
                g.fragments
            ));
        }
        let (base, ps, file_len) = match g.header {
            Some((b, h)) => {
                match sqlite::core_network(h.app_id) {
                    Some("mainnet") => {}
                    Some(net) => notes.push(format!("{net} wallet")),
                    None => notes.push("SQLite application_id is not a Bitcoin network".into()),
                }
                (b, h.ps as u64, Some(h.pages as u64 * h.ps as u64))
            }
            None => {
                notes.push("no file header found: may be only part of a wallet".into());
                (g.first.unwrap_or(0), 4096, None)
            }
        };
        if !records.is_empty() {
            out.push(Wallet {
                fmt: Fmt::Sqlite,
                base,
                ps,
                file_len,
                records,
                notes,
            });
        }
    }
    out
}

// ---- sweep ------------------------------------------------------------------------

/// Parse every sector-aligned database page in the regions around Bitcoin Core hits.
fn bitcoin_core_wallets(
    src: &File,
    size: u64,
    pats: &Patterns,
    hits: &[Hit],
    gap: u64,
) -> Vec<Wallet> {
    let btc: Vec<Hit> = hits
        .iter()
        .copied()
        .filter(|h| pats.list[h.pat as usize].name.starts_with("btc_"))
        .collect();
    let regions = IntervalSet::from_unsorted(
        report::clusters(pats, &btc, gap)
            .iter()
            .map(|c| {
                (
                    c.start.saturating_sub(MARGIN) / SECTOR * SECTOR,
                    (c.end + MARGIN).min(size),
                )
            })
            .collect(),
    );
    let (mut bpages, mut sheaders, mut sleaves) = (Vec::new(), Vec::new(), Vec::new());
    for (ri, &(rs, re)) in regions.as_slice().iter().enumerate() {
        let mut pos = rs;
        while pos < re {
            let lim = WINDOW.min(re - pos);
            let buf = read(src, size, pos, lim + 65536);
            let mut o = 0usize;
            while (o as u64) < lim && o + 512 <= buf.len() {
                let b = &buf[o..buf.len().min(o + 65536)];
                let off = pos + o as u64;
                if matches!(b[25], bdb::P_LBTREE | bdb::P_OVERFLOW | bdb::P_BTREEMETA)
                    && let Some(p) = bdb::parse(b, None)
                {
                    bpages.push((off, p));
                }
                if b[0] == b'S'
                    && let Some(h) = sqlite::parse_header(b)
                {
                    sheaders.push((off, h));
                }
                if b[0] == 0x0D || b.starts_with(sqlite::MAGIC) {
                    // Page size of the database this page belongs to, if known.
                    let db = sheaders
                        .iter()
                        .rev()
                        .find(|(h, hd): &&(u64, sqlite::Header)| {
                            off >= *h && off < h + hd.pages as u64 * hd.ps as u64
                        });
                    let (ps, usable) = db.map_or((4096, 4096), |(_, h)| {
                        (h.ps as usize, (h.ps - h.reserved) as usize)
                    });
                    let hdr = if b.starts_with(sqlite::MAGIC) { 100 } else { 0 };
                    if b.len() >= ps
                        && let Some(cells) = sqlite::parse_leaf(b, hdr, ps, usable)
                    {
                        sleaves.push((off, ri, cells));
                    }
                }
                o += SECTOR as usize;
            }
            pos += lim;
        }
    }
    let mut w = bdb_wallets(src, size, bpages);
    w.extend(sqlite_wallets(src, size, &sheaders, sleaves));
    w.retain(|w| {
        w.records
            .keys()
            .any(|k| rec_type(k).is_some_and(|t| KEY_TYPES.contains(&t)))
    });
    w
}

/// Bitcoin Core dump file (`bitcoin-wallet dump` format): header lines,
/// `hexkey,hexvalue` records, then the double-SHA256 of all preceding lines.
pub fn dump_text(fmt: &str, records: &BTreeMap<Vec<u8>, Vec<u8>>) -> String {
    let mut s = format!("BITCOIN_CORE_WALLET_DUMP,1\nformat,{fmt}\n");
    for (k, v) in records {
        let _ = writeln!(s, "{},{}", hex(k), hex(v));
    }
    let sum = hex(&sha256d(s.as_bytes()));
    let _ = writeln!(s, "checksum,{sum}");
    s
}

// ---- main entry ---------------------------------------------------------------

/// Something recovered, to show the user right away.
pub struct Finding {
    pub kind: &'static str,
    pub offset: u64,
    pub file: String,
    pub summary: String,
    /// Addresses to check balances of (most relevant first).
    pub addresses: Vec<String>,
    pub more_addresses: usize,
}

struct AddrRow {
    address: String,
    kind: &'static str,
    note: String,
    file: String,
}

/// Addresses-looking strings in a JSON wallet (Electrum, blockchain.info).
fn json_addresses(v: &Value) -> Vec<String> {
    fn looks(s: &str) -> bool {
        (26..=90).contains(&s.len())
            && s.bytes().all(|c| c.is_ascii_alphanumeric())
            && ["1", "3", "bc1", "m", "n", "2", "tb1"]
                .iter()
                .any(|p| s.starts_with(p))
    }
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) if looks(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(o) => o.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Some(a) = v.get("addresses") {
        walk(a, &mut out);
    }
    if let Some(h) = v.get("addr_history").and_then(Value::as_object) {
        out.extend(h.keys().filter(|k| looks(k)).cloned());
    }
    if let Some(ks) = v.get("keys").and_then(Value::as_array) {
        out.extend(
            ks.iter()
                .filter_map(|k| k.get("addr")?.as_str())
                .filter(|s| looks(s))
                .map(str::to_owned),
        );
    }
    let mut seen = HashSet::new();
    out.retain(|a| seen.insert(a.clone()));
    out
}

/// The recovered/ directory, filled incrementally: `add` processes hits (a
/// cluster as soon as its surroundings are scanned, or everything at the
/// end) and keeps the index files on disk up to date.
pub struct Recovery {
    dir: PathBuf,
    rows: Vec<Row>,
    seen: HashMap<[u8; 32], String>,
    json_done: Vec<(u64, u64)>,
    xprv: BTreeMap<String, Vec<u64>>,
    keys: BTreeMap<[u8; 32], (Key, String)>,
    wallet_sums: HashMap<[u8; 32], String>,
    addresses: Vec<AddrRow>,
    addr_seen: HashSet<String>,
    findings: Vec<Finding>,
    pub found: usize,
}

const DUP_DATA: &str = "another copy of the same data";
const DUP_WALLET: &str = "another copy of the same wallet";

impl Recovery {
    /// Start an empty OUTDIR/recovered.
    pub fn new(out: &Path) -> Result<Recovery> {
        let dir = out.join("recovered");
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        fs::create_dir_all(&dir)?;
        Ok(Recovery {
            dir,
            rows: Vec::new(),
            seen: HashMap::new(),
            json_done: Vec::new(),
            xprv: BTreeMap::new(),
            keys: BTreeMap::new(),
            wallet_sums: HashMap::new(),
            addresses: Vec::new(),
            addr_seen: HashSet::new(),
            findings: Vec::new(),
            found: 0,
        })
    }

    pub fn take_findings(&mut self) -> Vec<Finding> {
        std::mem::take(&mut self.findings)
    }

    fn finding(
        &mut self,
        kind: &'static str,
        offset: u64,
        file: String,
        summary: String,
        addrs: Vec<String>,
    ) {
        const SHOW: usize = 4;
        let more = addrs.len().saturating_sub(SHOW);
        self.found += 1;
        self.findings.push(Finding {
            kind,
            offset,
            file,
            summary,
            addresses: addrs.into_iter().take(SHOW).collect(),
            more_addresses: more,
        });
    }

    fn address(&mut self, address: String, kind: &'static str, note: String, file: &str) {
        if self.addr_seen.insert(address.clone()) {
            self.addresses.push(AddrRow {
                address,
                kind,
                note,
                file: file.to_owned(),
            });
        }
    }

    /// Write `data` to `sub/name` unless identical content was already
    /// saved. Returns the new file's path relative to recovered/.
    fn save(
        &mut self,
        kind: &'static str,
        sub: &str,
        name: String,
        data: &[u8],
        offset: u64,
        notes: String,
    ) -> Result<Option<String>> {
        let h = sha256(data);
        if let Some(prev) = self.seen.get(&h) {
            self.rows.push(Row {
                kind,
                offset,
                file: prev.clone(),
                notes: DUP_DATA.into(),
            });
            return Ok(None);
        }
        fs::create_dir_all(self.dir.join(sub))?;
        let rel = format!("{sub}/{name}");
        fs::write(self.dir.join(&rel), data)?;
        self.seen.insert(h, rel.clone());
        self.rows.push(Row {
            kind,
            offset,
            file: rel.clone(),
            notes,
        });
        Ok(Some(rel))
    }

    /// Recover everything `hits` point at.
    pub fn add(
        &mut self,
        src: &File,
        size: u64,
        pats: &Patterns,
        hits: &[Hit],
        gap: u64,
    ) -> Result<()> {
        self.add_json(src, size, pats, hits)?;
        for w in bitcoin_core_wallets(src, size, pats, hits, gap) {
            self.add_wallet(src, size, w)?;
        }
        // Loose DER private keys (deleted files, old wallet copies, logs).
        let mut new = Vec::new();
        for h in hits
            .iter()
            .filter(|h| pats.list[h.pat as usize].name == "btc_privkey_der")
        {
            if let Some(k) = keys::parse_der(&read(src, size, h.off, keys::DER_UNCOMPRESSED as u64))
                && !self.keys.contains_key(&k.secret)
            {
                self.keys.insert(
                    k.secret,
                    (k.clone(), format!("raw key at offset {}", h.off)),
                );
                new.push((h.off, k));
            }
        }
        if let Some(&(off, _)) = new.first() {
            let mut addrs = Vec::new();
            for (o, k) in &new {
                for a in keys::addresses(&k.pubkey) {
                    self.address(
                        a.clone(),
                        "loose private key",
                        format!("offset {o}"),
                        "keys/private_keys.tsv",
                    );
                    addrs.push(a);
                }
            }
            self.finding(
                "unencrypted bitcoin private key(s)",
                off,
                "keys/private_keys.tsv".into(),
                format!(
                    "{} verified key(s), not part of a recoverable wallet file",
                    new.len()
                ),
                addrs,
            );
        }
        self.write_index()
    }

    fn add_json(&mut self, src: &File, size: u64, pats: &Patterns, hits: &[Hit]) -> Result<()> {
        for h in hits {
            let off = h.off;
            let m = || read(src, size, h.off, h.len);
            match pats.list[h.pat as usize].name {
                "eth_keystore" => {
                    let d = m();
                    match serde_json::from_slice::<Value>(&d) {
                        Ok(v) => {
                            let addr = v
                                .get("address")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let ok = !addr.is_empty()
                                && addr.len() <= 64
                                && addr.bytes().all(|c| c.is_ascii_alphanumeric());
                            let id = if ok { addr.clone() } else { "unknown".into() };
                            let name = format!("UTC--wscan-off{off:012}--{id}.json");
                            if let Some(f) = self.save("ethereum keystore", "ethereum", name, &d, off,
                                "open with any Ethereum wallet (MetaMask import, geth, MyEtherWallet) and the password".into())?
                            {
                                let addrs = if ok { vec![format!("0x{}", addr.trim_start_matches("0x"))] } else { vec![] };
                                for a in &addrs {
                                    self.address(a.clone(), "ethereum keystore", String::new(), &f);
                                }
                                self.finding("ethereum keystore", off, f, "password-protected key file".into(), addrs);
                            }
                        }
                        Err(_) => {
                            self.save(
                                "ethereum keystore",
                                "ethereum",
                                format!("keystore_off{off:012}.txt"),
                                &d,
                                off,
                                "does not parse as JSON: damaged, fix by hand".into(),
                            )?;
                        }
                    }
                }
                "metamask_vault" => {
                    let raw = m();
                    let d = if memchr::memmem::find(&raw, b"\\\"").is_some() {
                        json::unescape(&raw).unwrap_or(raw)
                    } else {
                        raw
                    };
                    let ok = serde_json::from_slice::<Value>(&d)
                        .is_ok_and(|v| json::has_keys(&v, &["data", "iv", "salt"]));
                    let (name, note) = if ok {
                        (
                            format!("vault_off{off:012}.json"),
                            "decrypt with the MetaMask vault decryptor and the MetaMask password",
                        )
                    } else {
                        (
                            format!("vault_off{off:012}.txt"),
                            "does not parse as JSON: damaged, fix by hand",
                        )
                    };
                    if let Some(f) =
                        self.save("metamask vault", "metamask", name, &d, off, note.into())?
                        && ok
                    {
                        self.finding(
                            "metamask vault",
                            off,
                            f,
                            "encrypted vault (addresses known only after decryption)".into(),
                            vec![],
                        );
                    }
                }
                "electrum_encrypted" => {
                    if let Some(f) = self.save(
                        "electrum wallet (encrypted file)",
                        "electrum",
                        format!("encrypted_off{off:012}.wallet"),
                        &m(),
                        off,
                        "open with Electrum (File > Open) and the wallet password".into(),
                    )? {
                        self.finding(
                            "electrum wallet (encrypted file)",
                            off,
                            f,
                            "whole file encrypted: addresses known after opening it".into(),
                            vec![],
                        );
                    }
                }
                t @ ("electrum_seedver" | "electrum_type" | "blockchain_info") => {
                    if self.json_done.iter().any(|&(s, e)| off >= s && off < e) {
                        continue;
                    }
                    let electrum = t != "blockchain_info";
                    let (key, kind, sub) = if electrum {
                        ("seed_version", "electrum wallet", "electrum")
                    } else {
                        ("guid", "blockchain.info wallet", "blockchain_info")
                    };
                    let ws = off.saturating_sub(4 << 20);
                    let buf = read(src, size, ws, (off - ws) + (16 << 20));
                    match json::enclosing_object(&buf, (off - ws) as usize, 16 << 20, |v| json::has_keys(v, &[key])) {
                        Some((s, e, v)) => {
                            let start = ws + s as u64;
                            self.json_done.push((start, ws + e as u64));
                            let note = if v.get("use_encryption").and_then(Value::as_bool) == Some(true) {
                                "complete wallet file; keys are encrypted with the wallet password"
                            } else if electrum {
                                "complete wallet file; open with Electrum"
                            } else {
                                "complete wallet file"
                            };
                            if let Some(f) = self.save(kind, sub, format!("wallet_off{start:012}.json"), &buf[s..e], start, note.into())? {
                                let addrs = json_addresses(&v);
                                for a in &addrs {
                                    self.address(a.clone(), kind, String::new(), &f);
                                }
                                self.finding(kind, start, f, note.into(), addrs);
                            }
                        }
                        None => self.rows.push(Row { kind, offset: off, file: String::new(),
                            notes: "only a fragment (file split or damaged): see the cluster_*.bin carve".into() }),
                    }
                }
                "bip32_xprv" => {
                    let s = String::from_utf8_lossy(&m()).into_owned();
                    let valid = keys::base58check_decode(&s).is_some_and(|p| {
                        p.len() == 78
                            && [
                                [4, 0x88, 0xad, 0xe4],
                                [4, 0x9d, 0x78, 0x78],
                                [4, 0xb2, 0x43, 0x0c],
                                [4, 0x35, 0x83, 0x94],
                            ]
                            .contains(&[p[0], p[1], p[2], p[3]])
                            && p[45] == 0
                    });
                    if valid {
                        let first = !self.xprv.contains_key(&s);
                        self.xprv.entry(s.clone()).or_default().push(off);
                        if first {
                            self.finding(
                                "bip32 extended private key",
                                off,
                                "keys/bip32_xprv.txt".into(),
                                format!(
                                    "{}... (valid checksum): master key of an HD wallet",
                                    &s[..12]
                                ),
                                vec![],
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn add_wallet(&mut self, src: &File, size: u64, mut w: Wallet) -> Result<()> {
        let types =
            |w: &Wallet, t: &str| w.records.keys().filter(|k| rec_type(k) == Some(t)).count();
        let fmt = if w.fmt == Fmt::Bdb { "bdb" } else { "sqlite" };
        let sum = sha256(dump_text(fmt, &w.records).as_bytes());
        if let Some(prev) = self.wallet_sums.get(&sum) {
            self.rows.push(Row {
                kind: "bitcoin core wallet",
                offset: w.base,
                file: prev.clone(),
                notes: DUP_WALLET.into(),
            });
            return Ok(());
        }
        let mut stem = format!("bitcoin/wallet_{fmt}_off{:012}", w.base);
        while self
            .wallet_sums
            .values()
            .any(|f| f == &format!("{stem}.dump"))
        {
            stem.push('b');
        }
        let dump = format!("{stem}.dump");
        // Unencrypted keys, verified against their public keys.
        let mut plain = Vec::new();
        for (k, v) in &w.records {
            if let Some(key) = plain_key(k, v) {
                self.keys.entry(key.secret).or_insert((key, dump.clone()));
                plain.push(k.clone());
            }
        }
        let encrypted = types(&w, "mkey") > 0;
        let crypted = types(&w, "ckey") + types(&w, "walletdescriptorckey");
        if encrypted && !plain.is_empty() {
            // Stale pre-encryption copies; Core refuses wallets mixing both.
            for k in &plain {
                w.records.remove(k);
            }
            w.notes.push(format!(
                "{} unencrypted key(s) from before encryption left out of the dump (see keys/)",
                plain.len()
            ));
        }
        if crypted > 0 && !encrypted {
            w.notes.push(
                "encrypted keys but no master key (mkey) record found: cannot be decrypted".into(),
            );
        }
        if types(&w, "walletdescriptor") > 0 && types(&w, "flags") == 0 {
            w.notes.push("descriptor wallet without its flags record: add `-format=sqlite` and expect to repair".into());
        }
        fs::create_dir_all(self.dir.join("bitcoin"))?;
        fs::write(self.dir.join(&dump), dump_text(fmt, &w.records))?;
        self.wallet_sums.insert(sum, dump.clone());

        // Whole file, when it is stored in one piece at its header.
        if let Some(len) = w.file_len.filter(|&l| l <= MAX_CARVE && w.base + l <= size) {
            let data = read(src, size, w.base, len);
            let ext = if w.fmt == Fmt::Bdb { "dat" } else { "sqlite" };
            let whole = if w.fmt == Fmt::Bdb {
                // Every page of a BDB file, free ones included, carries its number.
                let pages = (len / w.ps) as usize;
                (0..pages).all(|i| {
                    u32::from_le_bytes(
                        data[i * w.ps as usize + 8..i * w.ps as usize + 12]
                            .try_into()
                            .unwrap(),
                    ) == i as u32
                })
            } else {
                !w.notes
                    .iter()
                    .any(|n| n.contains("split") || n.contains("lost"))
            };
            if whole {
                fs::write(self.dir.join(format!("{stem}.{ext}")), &data)?;
                w.notes
                    .push(format!("whole file also saved as {stem}.{ext}"));
            } else {
                w.notes
                    .push("file is split on disk: not carved whole, use the .dump".into());
            }
        }

        // Addresses: the address book (addresses handed out), then the ones
        // derived from the key records, and the public descriptors.
        let mut shown = Vec::new();
        for (k, v) in &w.records {
            let t = rec_type(k).unwrap_or("");
            let at = 1 + t.len();
            match t {
                "name" => {
                    if let Some(a) = vec_at(k, at).and_then(|a| std::str::from_utf8(a).ok()) {
                        let label = vec_at(v, 0)
                            .map(|l| String::from_utf8_lossy(l).into_owned())
                            .unwrap_or_default();
                        let note = if label.is_empty() {
                            "address book".to_owned()
                        } else {
                            format!("address book, label {label:?}")
                        };
                        self.address(a.to_owned(), "bitcoin core wallet", note, &dump);
                        shown.push(a.to_owned());
                    }
                }
                "key" | "ckey" => {
                    if let Some(p) = vec_at(k, at) {
                        for a in keys::addresses(p) {
                            self.address(
                                a,
                                "bitcoin core wallet",
                                format!("from a {t} record"),
                                &dump,
                            );
                        }
                    }
                }
                "walletdescriptor" => {
                    if let Some(d) = vec_at(v, 0).and_then(|d| std::str::from_utf8(d).ok()) {
                        self.address(
                            d.to_owned(),
                            "bitcoin core descriptor",
                            "public descriptor: import as watch-only to list its addresses".into(),
                            &dump,
                        );
                    }
                }
                _ => {}
            }
        }
        let nkeys = plain.len() + crypted;
        if shown.is_empty() {
            for (k, _) in w
                .records
                .iter()
                .filter(|(k, _)| matches!(rec_type(k), Some("key" | "ckey")))
                .take(4)
            {
                if let Some(p) = vec_at(k, 1 + rec_type(k).unwrap().len()) {
                    shown.extend(keys::addresses(p).into_iter().take(1));
                }
            }
        }

        let kind = if w.fmt == Fmt::Bdb {
            "bitcoin core wallet (legacy, Berkeley DB)"
        } else {
            "bitcoin core wallet (descriptor, SQLite)"
        };
        let headline = format!(
            "{} {}, {nkeys} key(s){}{}",
            if encrypted {
                "ENCRYPTED"
            } else {
                "UNENCRYPTED"
            },
            if types(&w, "hdchain") + types(&w, "walletdescriptor") > 0 {
                "HD"
            } else {
                "non-HD"
            },
            if types(&w, "walletdescriptor") > 0 {
                format!(", {} descriptors", types(&w, "walletdescriptor"))
            } else {
                String::new()
            },
            if types(&w, "name") > 0 {
                format!(", {} address book entries", types(&w, "name"))
            } else {
                String::new()
            },
        );
        let mut summary = format!(
            "{} records: {headline}, {} plain key(s), {crypted} encrypted key(s)",
            w.records.len(),
            plain.len()
        );
        for n in &w.notes {
            summary.push_str("; ");
            summary.push_str(n);
        }
        let mut live = headline;
        for n in w.notes.iter().filter(|n| !n.starts_with("whole file")) {
            live.push_str("; ");
            live.push_str(n);
        }
        self.rows.push(Row {
            kind,
            offset: w.base,
            file: dump.clone(),
            notes: summary,
        });
        let extra = if shown.is_empty() {
            0
        } else {
            types(&w, "name").max(shown.len()) - shown.len()
        };
        self.finding(kind, w.base, dump, live, shown);
        if let Some(f) = self.findings.last_mut() {
            f.more_addresses += extra;
        }
        Ok(())
    }

    /// (Re)write recovered.tsv, addresses.tsv, keys/ and README.txt.
    pub fn write_index(&self) -> Result<()> {
        let dir = &self.dir;
        if !self.keys.is_empty() || !self.xprv.is_empty() {
            fs::create_dir_all(dir.join("keys"))?;
        }
        let mut rows: Vec<String> = Vec::new();
        if !self.keys.is_empty() {
            let mut t =
                String::from("wif\taddress_p2pkh\taddress_p2wpkh\tpubkey\tsecret_hex\tsource\n");
            for (k, src) in self.keys.values() {
                let _ = writeln!(
                    t,
                    "{}\t{}\t{}\t{}\t{}\t{src}",
                    k.wif(),
                    k.p2pkh(),
                    k.p2wpkh().unwrap_or_default(),
                    hex(&k.pubkey),
                    hex(&k.secret)
                );
            }
            fs::write(dir.join("keys/private_keys.tsv"), t)?;
            rows.push(format!("bitcoin private keys\t0\tkeys/private_keys.tsv\t{} verified unencrypted key(s) (WIF, importable anywhere)", self.keys.len()));
        }
        if !self.xprv.is_empty() {
            let mut t = String::new();
            for (x, offs) in &self.xprv {
                let offs: Vec<String> = offs.iter().map(u64::to_string).collect();
                let _ = writeln!(t, "{x}\t# offsets {}", offs.join(","));
            }
            fs::write(dir.join("keys/bip32_xprv.txt"), t)?;
            rows.push(format!(
                "bip32 extended private keys\t0\tkeys/bip32_xprv.txt\t{} with a valid checksum",
                self.xprv.len()
            ));
        }
        let mut t = String::from("address\tkind\tnote\tfile\n");
        for a in &self.addresses {
            let _ = writeln!(t, "{}\t{}\t{}\t{}", a.address, a.kind, a.note, a.file);
        }
        fs::write(dir.join("addresses.tsv"), t)?;
        let mut tsv = String::from("kind\toffset\tfile\tnotes\n");
        for r in &self.rows {
            let _ = writeln!(tsv, "{}\t{}\t{}\t{}", r.kind, r.offset, r.file, r.notes);
        }
        for r in rows {
            let _ = writeln!(tsv, "{r}");
        }
        fs::write(dir.join("recovered.tsv"), tsv)?;
        fs::write(dir.join("README.txt"), README)?;
        Ok(())
    }

    pub fn print_summary(&self) {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for r in self
            .rows
            .iter()
            .filter(|r| !r.file.is_empty() && r.notes != DUP_DATA && r.notes != DUP_WALLET)
        {
            *counts.entry(r.kind).or_default() += 1;
        }
        println!("[+] Recovered into {}:", self.dir.display());
        if counts.is_empty() && self.keys.is_empty() && self.xprv.is_empty() {
            println!("    nothing usable");
        }
        for r in self
            .rows
            .iter()
            .filter(|r| r.kind.starts_with("bitcoin core") && r.notes != DUP_WALLET)
        {
            println!("    {}: {}", r.file, r.notes);
        }
        for (k, n) in counts
            .iter()
            .filter(|(k, _)| !k.starts_with("bitcoin core"))
        {
            println!("    {n} x {k}");
        }
        if !self.keys.is_empty() {
            println!(
                "    {} verified unencrypted private key(s): keys/private_keys.tsv",
                self.keys.len()
            );
        }
        if !self.xprv.is_empty() {
            println!(
                "    {} extended private key(s): keys/bip32_xprv.txt",
                self.xprv.len()
            );
        }
        if !self.addresses.is_empty() {
            println!(
                "    {} address(es) / descriptor(s) to check: addresses.tsv",
                self.addresses.len()
            );
        }
    }
}

/// Full recovery from all hits (end of a scan).
pub fn run(
    out: &Path,
    src: &File,
    size: u64,
    pats: &Patterns,
    hits: &[Hit],
    gap: u64,
) -> Result<()> {
    let mut r = Recovery::new(out)?;
    r.add(src, size, pats, hits, gap)?;
    r.print_summary();
    Ok(())
}

const README: &str = "\
Recovered wallets (written by wscan; see recovered.tsv for every item and its source offset)

bitcoin/wallet_<format>_off<offset>.dump
    Bitcoin Core wallet rebuilt from its database pages, in Bitcoin Core's
    dump format. Recreate the wallet with:
        bitcoin-wallet -wallet=recovered1 -dumpfile=wallet_....dump createfromdump
    then load it in Bitcoin Core (`loadwallet recovered1`) and rescan.
    Encrypted wallets keep their encryption: unlock with the original passphrase.
    Legacy (bdb) dumps need Bitcoin Core 0.21 to 28.x, which can still create
    Berkeley DB wallets; with Bitcoin Core 29+ load it there and run
    `migratewallet` to turn it into a descriptor wallet.
bitcoin/wallet_....dat / .sqlite
    The wallet file cut out whole, when its header was found. Exact copy if
    the file was stored in one piece on disk (see the notes in recovered.tsv);
    the .dump is the reliable output when the file was split.
keys/private_keys.tsv
    Unencrypted private keys found anywhere, each checked against its public
    key. WIF keys import into Bitcoin Core (importprivkey / importdescriptors
    with pkh(WIF)), Electrum, Sparrow...
keys/bip32_xprv.txt
    Extended private keys with a valid checksum.
ethereum/, metamask/, electrum/, blockchain_info/
    Complete wallet files / vaults, validated as JSON.
addresses.tsv
    Addresses to check balances of: Bitcoin Core address books (addresses
    the wallet handed out), addresses of every key record (also for
    encrypted wallets: public keys are not encrypted), public descriptors
    (import as watch-only), Ethereum / Electrum / blockchain.info addresses.
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_types() {
        assert_eq!(rec_type(b"\x04ckey\x21\x02"), Some("ckey"));
        assert_eq!(
            rec_type(b"\x13walletdescriptorkey"),
            Some("walletdescriptorkey")
        );
        assert_eq!(rec_type(b"main"), None);
        assert_eq!(rec_type(b"\x05ab"), None);
    }

    #[test]
    fn dump_checksum_covers_all_lines() {
        let recs: BTreeMap<Vec<u8>, Vec<u8>> = [(b"\x07version".to_vec(), vec![1, 2])].into();
        let d = dump_text("bdb", &recs);
        let (body, last) = d.trim_end().rsplit_once('\n').unwrap();
        assert_eq!(
            body,
            "BITCOIN_CORE_WALLET_DUMP,1\nformat,bdb\n0776657273696f6e,0102"
        );
        assert_eq!(
            last,
            format!("checksum,{}", hex(&sha256d(format!("{body}\n").as_bytes())))
        );
    }
}
