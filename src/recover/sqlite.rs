//! SQLite page parser for Bitcoin Core descriptor wallets: table
//! `main(key BLOB PRIMARY KEY, value BLOB)`. Only table-leaf pages (type
//! 0x0D) are needed: each cell is one row.

fn u16be(b: &[u8], o: usize) -> usize {
    u16::from_be_bytes([b[o], b[o + 1]]) as usize
}

pub fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}

pub const MAGIC: &[u8] = b"SQLite format 3\0";
/// Bitcoin Core sets `PRAGMA application_id` to the network's message start.
pub fn core_network(app_id: u32) -> Option<&'static str> {
    Some(match app_id {
        0xf9be_b4d9 => "mainnet",
        0x0b11_0907 => "testnet3",
        0x1c16_3f28 => "testnet4",
        0x0a03_cf40 => "signet",
        0xfabf_b5da => "regtest",
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub ps: u32,
    pub reserved: u32,
    pub pages: u32,
    pub app_id: u32,
}

pub fn parse_header(b: &[u8]) -> Option<Header> {
    if b.len() < 100 || !b.starts_with(MAGIC) {
        return None;
    }
    let ps = match u16be(b, 16) {
        1 => 65536,
        p => p as u32,
    };
    if !ps.is_power_of_two() || ps < 512 {
        return None;
    }
    Some(Header {
        ps,
        reserved: b[20] as u32,
        pages: u32be(b, 28),
        app_id: u32be(b, 68),
    })
}

/// SQLite varint: big-endian, 7 bits per byte, 9th byte uses all 8 bits.
fn varint(b: &[u8], mut o: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for i in 0..9 {
        let x = *b.get(o)?;
        o += 1;
        if i == 8 {
            return Some(((v << 8) | x as u64, o));
        }
        v = (v << 7) | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            return Some((v, o));
        }
    }
    None
}

/// One row of a table-leaf page: the payload bytes stored on the page and,
/// when the row is larger, the first overflow page.
#[derive(Clone, Debug)]
pub struct Cell {
    pub total: usize,
    pub local: Vec<u8>,
    pub overflow: Option<u32>,
}

/// Parse a table-leaf page. `b` starts at the page; `hdr` is 100 for page 1.
pub fn parse_leaf(b: &[u8], hdr: usize, ps: usize, usable: usize) -> Option<Vec<Cell>> {
    if b.len() < ps || b[hdr] != 0x0D {
        return None;
    }
    let n = u16be(b, hdr + 3);
    let content = match u16be(b, hdr + 5) {
        0 => 65536,
        c => c,
    };
    let ptrs = hdr + 8;
    if n == 0 || ptrs + 2 * n > content || content > ps || b[hdr + 7] > 60 {
        return None;
    }
    let mut cells = Vec::with_capacity(n);
    for i in 0..n {
        let c = u16be(b, ptrs + 2 * i);
        if c < content || c >= ps {
            return None;
        }
        let (total, o) = varint(&b[..ps], c)?;
        let (_rowid, o) = varint(&b[..ps], o)?;
        let total = total as usize;
        let max_local = usable - 35;
        let local = if total <= max_local {
            total
        } else {
            let m = (usable - 12) * 32 / 255 - 23;
            let k = m + (total - m) % (usable - 4);
            if k <= max_local { k } else { m }
        };
        let end = o + local;
        if end + if local < total { 4 } else { 0 } > ps {
            return None;
        }
        let overflow = (local < total).then(|| u32be(b, end));
        cells.push(Cell {
            total,
            local: b[o..end].to_vec(),
            overflow,
        });
    }
    Some(cells)
}

/// Split a record of exactly two BLOB columns (the `main` table's key and
/// value) whose bytes are `payload`.
pub fn two_blobs(payload: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (hs, mut o) = varint(payload, 0)?;
    let hs = hs as usize;
    let mut lens = Vec::new();
    while o < hs {
        let (t, n) = varint(payload, o)?;
        o = n;
        if t < 12 || t % 2 != 0 {
            return None;
        }
        lens.push(((t - 12) / 2) as usize);
    }
    if lens.len() != 2 || o != hs || hs + lens[0] + lens[1] != payload.len() {
        return None;
    }
    let k = payload[hs..hs + lens[0]].to_vec();
    Some((k, payload[hs + lens[0]..].to_vec()))
}

/// Key blob of a record from the start of its payload (enough when the
/// value spills into overflow pages).
pub fn first_blob(payload: &[u8]) -> Option<Vec<u8>> {
    let (hs, o) = varint(payload, 0)?;
    let (t, _) = varint(payload, o)?;
    if t < 12 || t % 2 != 0 {
        return None;
    }
    let (hs, len) = (hs as usize, ((t - 12) / 2) as usize);
    payload.get(hs..hs + len).map(|k| k.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture_rows() {
        let f = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/desc_plain.wallet"
        ))
        .unwrap();
        let h = parse_header(&f).unwrap();
        assert_eq!(h.ps, 4096);
        assert_eq!(core_network(h.app_id), Some("mainnet"));
        assert_eq!(h.pages as usize * 4096, f.len());
        let usable = (h.ps - h.reserved) as usize;
        let (mut rows, mut spilled) = (0, 0);
        for (i, p) in f.chunks(4096).enumerate() {
            let Some(cells) = parse_leaf(p, if i == 0 { 100 } else { 0 }, 4096, usable) else {
                continue;
            };
            for c in cells {
                if c.overflow.is_some() {
                    spilled += 1;
                    assert!(first_blob(&c.local).unwrap()[1..3] == *b"tx");
                } else if i > 0 {
                    two_blobs(&c.local).unwrap();
                }
                rows += 1;
            }
        }
        let expect = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/desc_plain.records"
        ))
        .unwrap()
        .lines()
        .count();
        // Table rows plus the sqlite_schema rows on page 1 (table + its autoindex).
        assert_eq!(rows, expect + 2);
        assert!(spilled > 0);
    }

    #[test]
    fn varints() {
        assert_eq!(varint(&[0x7f], 0), Some((127, 1)));
        assert_eq!(varint(&[0x81, 0x00], 0), Some((128, 2)));
        assert_eq!(varint(&[0xff; 9], 0), Some((u64::MAX, 9)));
    }
}
