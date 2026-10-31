//! Berkeley DB (4.x/5.x btree, little-endian) page parser, as used by
//! Bitcoin Core legacy wallet.dat files.
//!
//! Every page starts with a 26-byte header:
//!   0 lsn (file u32, offset u32) | 8 pgno | 12 prev | 16 next |
//!   20 entries u16 | 22 hf_offset u16 | 24 level u8 | 25 type u8
//! Leaf pages (type 5) hold an index of `entries` u16 offsets followed by
//! items: B_KEYDATA `len u16, type u8 (1), data` or B_OVERFLOW
//! `u16, type u8 (3), u8, pgno u32, tlen u32`. Keys and values alternate.
//! Overflow pages (type 7) carry `hf_offset` bytes of data at offset 26.

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

pub const P_LBTREE: u8 = 5;
pub const P_OVERFLOW: u8 = 7;
pub const P_BTREEMETA: u8 = 9;
const B_KEYDATA: u8 = 1;
const B_OVERFLOW: u8 = 3;
const B_DELETE: u8 = 0x80;
pub const MAGIC: u32 = 0x053162;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Val {
    Inline(Vec<u8>),
    Overflow { pgno: u32, len: u32 },
}

#[derive(Clone, Debug)]
pub enum Kind {
    Meta { last_pgno: u32 },
    Leaf(Vec<(Vec<u8>, Val)>),
    Overflow { next: u32, data: Vec<u8> },
}

#[derive(Clone, Debug)]
pub struct Page {
    pub pgno: u32,
    pub lsn: (u32, u32),
    pub ps: u32,
    pub kind: Kind,
}

fn valid_ps(ps: u32) -> bool {
    ps.is_power_of_two() && (512..=65536).contains(&ps)
}

/// Parse the page starting at `b[0]`. `b` should hold up to 64 KiB (less at
/// the end of the data). `ps_hint` is the page size when known.
pub fn parse(b: &[u8], ps_hint: Option<u32>) -> Option<Page> {
    if b.len() < 64 {
        return None;
    }
    let pgno = u32le(b, 8);
    let lsn = (u32le(b, 0), u32le(b, 4));
    match b[25] {
        P_BTREEMETA => {
            let (magic, version, ps) = (u32le(b, 12), u32le(b, 16), u32le(b, 20));
            if magic != MAGIC || !(7..=10).contains(&version) || !valid_ps(ps) || b[24] != 0 {
                return None;
            }
            Some(Page {
                pgno,
                lsn,
                ps,
                kind: Kind::Meta {
                    last_pgno: u32le(b, 32),
                },
            })
        }
        P_LBTREE => parse_leaf(b, pgno, lsn, ps_hint),
        P_OVERFLOW => {
            let ps = ps_hint.unwrap_or(4096) as usize;
            let len = u16le(b, 22) as usize;
            if b[24] != 0 || u16le(b, 20) == 0 || len == 0 || 26 + len > ps.min(b.len()) {
                return None;
            }
            Some(Page {
                pgno,
                lsn,
                ps: ps as u32,
                kind: Kind::Overflow {
                    next: u32le(b, 16),
                    data: b[26..26 + len].to_vec(),
                },
            })
        }
        _ => None,
    }
}

fn parse_leaf(b: &[u8], pgno: u32, lsn: (u32, u32), ps_hint: Option<u32>) -> Option<Page> {
    let entries = u16le(b, 20) as usize;
    let hf = u16le(b, 22) as usize;
    let idx_end = 26 + 2 * entries;
    if b[24] != 1 || entries == 0 || !entries.is_multiple_of(2) || hf < idx_end || idx_end > b.len()
    {
        return None;
    }
    // Item extents; items live in [hf, page size).
    let mut items = Vec::with_capacity(entries);
    let mut max_end = 0;
    for i in 0..entries {
        let o = u16le(b, 26 + 2 * i) as usize;
        if o < hf || o + 3 > b.len() {
            return None;
        }
        let t = b[o + 2] & !B_DELETE;
        let end = match t {
            B_KEYDATA => o + 3 + u16le(b, o) as usize,
            B_OVERFLOW => o + 12,
            _ => return None,
        };
        if end > b.len() {
            return None;
        }
        max_end = max_end.max(end);
        items.push((o, end, b[o + 2]));
    }
    // Items are packed against the end of the page (4-byte aligned).
    let ps = match ps_hint {
        Some(p) if max_end <= p as usize => p,
        _ => {
            let p = (max_end as u32).next_power_of_two();
            if !valid_ps(p) || p as usize - max_end > 7 {
                return None;
            }
            p
        }
    };
    let mut recs = Vec::with_capacity(entries / 2);
    for pair in items.chunks(2) {
        let ((ko, kend, kt), (vo, vend, vt)) = (pair[0], pair[1]);
        if kt != B_KEYDATA || (kt | vt) & B_DELETE != 0 {
            continue;
        }
        let key = b[ko + 3..kend].to_vec();
        let val = if vt == B_KEYDATA {
            Val::Inline(b[vo + 3..vend].to_vec())
        } else {
            Val::Overflow {
                pgno: u32le(b, vo + 4),
                len: u32le(b, vo + 8),
            }
        };
        recs.push((key, val));
    }
    Some(Page {
        pgno,
        lsn,
        ps,
        kind: Kind::Leaf(recs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy_plain.wallet"
        ))
        .unwrap()
    }

    #[test]
    fn parses_fixture_pages() {
        let f = fixture();
        let meta = parse(&f, None).unwrap();
        assert_eq!(meta.pgno, 0);
        assert_eq!(meta.ps, 4096);
        let Kind::Meta { last_pgno } = meta.kind else {
            panic!()
        };
        assert_eq!((last_pgno as usize + 1) * 4096, f.len());
        let (mut leaves, mut overflow, mut recs) = (0, 0, 0);
        for p in f.chunks(4096) {
            match parse(p, None).map(|p| p.kind) {
                Some(Kind::Leaf(r)) => {
                    leaves += 1;
                    recs += r.len();
                }
                Some(Kind::Overflow { .. }) => overflow += 1,
                _ => {}
            }
        }
        assert!(leaves > 3 && overflow > 3);
        // All records of the subdatabase, plus "main" in the outer database.
        let expect = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/legacy_plain.records"
        ))
        .unwrap()
        .lines()
        .count();
        assert_eq!(recs, expect + 1);
    }

    #[test]
    fn rejects_garbage() {
        let mut f = fixture();
        assert!(parse(&[0u8; 4096], None).is_none());
        // A leaf whose index points outside the page.
        let leaf = f.chunks(4096).position(|p| p[25] == P_LBTREE).unwrap() * 4096;
        f[leaf + 26] = 0xff;
        f[leaf + 27] = 0xff;
        assert!(parse(&f[leaf..leaf + 4096], None).is_none());
    }
}
