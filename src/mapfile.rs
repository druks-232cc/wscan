//! ddrescue mapfile parser.
//!
//! Format: comment lines (`#`), one status line `current_pos status [pass]`,
//! then contiguous block lines `pos size status`. Block status `+` means
//! rescued. ddrescue rewrites the file in place, so a read may catch it half
//! written: such reads fail to parse and are retried.

use std::{path::Path, thread, time::Duration};

use anyhow::{Context, Result, bail};

use crate::intervals::IntervalSet;

#[derive(Clone, Debug)]
pub struct Mapfile {
    pub rescued: IntervalSet,
    /// End of the last block: the size of the source device.
    pub extent: u64,
    /// ddrescue's current status character ('+' once finished).
    pub status: char,
    pub pass: Option<u32>,
}

impl Mapfile {
    pub fn finished(&self) -> bool {
        self.status == '+'
    }

    pub fn phase(&self) -> &'static str {
        match self.status {
            '?' => "copying",
            '*' => "trimming",
            '/' => "scraping",
            '-' => "retrying",
            'F' => "filling",
            'G' => "generating",
            '+' => "finished",
            _ => "unknown",
        }
    }
}

fn num(s: &str) -> Result<u64> {
    let r = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else {
        s.parse()
    };
    r.with_context(|| format!("bad number {s:?}"))
}

pub fn parse(text: &str) -> Result<Mapfile> {
    let mut rows = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().collect::<Vec<_>>());
    let head = rows.next().context("empty mapfile")?;
    if head.len() < 2 {
        bail!("bad status line");
    }
    let status = head[1].chars().next().context("bad status")?;
    let pass = head.get(2).and_then(|p| p.parse().ok());
    let (mut pos, mut blocks) = (0u64, Vec::new());
    for r in rows {
        if r.len() < 3 {
            bail!("truncated block line");
        }
        let (p, n) = (num(r[0])?, num(r[1])?);
        if p != pos {
            bail!("gap in mapfile at {p:#x}");
        }
        pos = p + n;
        if r[2] == "+" {
            blocks.push((p, p + n));
        }
    }
    if pos == 0 {
        bail!("no blocks");
    }
    Ok(Mapfile {
        rescued: IntervalSet::from_unsorted(blocks),
        extent: pos,
        status,
        pass,
    })
}

/// Read and parse, retrying while ddrescue is rewriting the file.
pub fn read(path: &Path) -> Result<Mapfile> {
    let mut last = None;
    for _ in 0..20 {
        match std::fs::read_to_string(path)
            .map_err(anyhow::Error::from)
            .and_then(|t| parse(&t))
        {
            Ok(m) => return Ok(m),
            Err(e) => last = Some(e),
        }
        thread::sleep(Duration::from_millis(500));
    }
    Err(last.unwrap()).with_context(|| format!("cannot parse mapfile {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = "# Mapfile. Created by GNU ddrescue version 1.27\n\
# Command line: ddrescue /dev/sdb img map\n\
# current_pos  current_status  current_pass\n\
0x00120000     ?               1\n\
#      pos        size  status\n\
0x00000000  0x00100000  +\n\
0x00100000  0x00010000  *\n\
0x00110000  0x00010000  +\n\
0x00120000  0x00EE0000  ?\n";

    #[test]
    fn parses_rescued_blocks() {
        let m = parse(MAP).unwrap();
        assert_eq!(m.rescued.as_slice(), &[(0, 0x100000), (0x110000, 0x120000)]);
        assert_eq!(m.extent, 0x1000000);
        assert_eq!(m.status, '?');
        assert_eq!(m.pass, Some(1));
        assert!(!m.finished());
    }

    #[test]
    fn rejects_partial_writes() {
        // Cut in the middle of a block line, and with a missing block.
        assert!(parse(&MAP[..MAP.len() - 6]).is_err());
        assert!(parse(&MAP.replace("0x00100000  0x00010000  *\n", "")).is_err());
        assert!(parse("# only comments\n").is_err());
    }

    #[test]
    fn finished_old_format() {
        let m = parse("0x0 +\n0x0 0x200 +\n").unwrap();
        assert!(m.finished());
        assert_eq!(m.pass, None);
        assert_eq!(m.rescued.total(), 0x200);
    }
}
