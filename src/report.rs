//! Final report: whole-match files, clusters of nearby hits, scores, carved
//! cluster files and report.tsv.

use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File},
    io::Write,
    path::Path,
};

use anyhow::Result;

use crate::{
    patterns::{Patterns, score},
    reader::read_at_full,
    scan::Hit,
};

pub struct ReportCfg {
    pub before: u64,
    pub after: u64,
    pub gap: u64,
    pub maxcarve: u64,
}

pub struct Cluster<'a> {
    pub start: u64,
    pub end: u64,
    pub counts: BTreeMap<&'a str, u32>,
    pub score: u32,
}

/// Keep the longest hit per (pattern, offset), sorted by offset.
pub fn dedup(hits: &[Hit]) -> Vec<Hit> {
    let mut best: HashMap<(u16, u64), u64> = HashMap::with_capacity(hits.len());
    for h in hits {
        let l = best.entry((h.pat, h.off)).or_insert(0);
        *l = (*l).max(h.len);
    }
    let mut v: Vec<Hit> = best
        .into_iter()
        .map(|((pat, off), len)| Hit { off, len, pat })
        .collect();
    v.sort_unstable();
    v
}

/// Group sorted hits that are at most `gap` bytes apart.
pub fn clusters<'a>(pats: &'a Patterns, hits: &[Hit], gap: u64) -> Vec<Cluster<'a>> {
    let mut out: Vec<Cluster> = Vec::new();
    for h in hits {
        let name = pats.list[h.pat as usize].name;
        match out.last_mut() {
            Some(c) if h.off.saturating_sub(c.end) <= gap => {
                c.end = c.end.max(h.off + h.len);
                *c.counts.entry(name).or_insert(0) += 1;
            }
            _ => out.push(Cluster {
                start: h.off,
                end: h.off + h.len,
                counts: [(name, 1)].into(),
                score: 0,
            }),
        }
    }
    for c in &mut out {
        c.score = score(&c.counts);
    }
    out
}

pub fn write(
    out: &Path,
    src: &File,
    size: u64,
    pats: &Patterns,
    all_hits: &[Hit],
    cfg: &ReportCfg,
) -> Result<()> {
    let hits = dedup(all_hits);
    for e in fs::read_dir(out)? {
        let name = e?.file_name();
        let n = name.to_string_lossy();
        if (n.starts_with("cluster_") && n.ends_with(".bin"))
            || (n.starts_with("match_") && n.ends_with(".txt"))
        {
            fs::remove_file(out.join(&name))?;
        }
    }
    let mut buf = Vec::new();
    fn read<'b>(src: &File, buf: &'b mut Vec<u8>, off: u64, len: u64) -> Result<&'b [u8]> {
        buf.resize(len as usize, 0);
        let n = read_at_full(src, buf, off)?;
        Ok(&buf[..n])
    }

    // Save every JSON-like / key match whole: often directly usable.
    let mut nwhole = 0;
    for h in hits.iter().filter(|h| pats.list[h.pat as usize].whole) {
        let p = out.join(format!(
            "match_{}_{:012}.txt",
            pats.list[h.pat as usize].name, h.off
        ));
        fs::write(p, read(src, &mut buf, h.off, h.len)?)?;
        nwhole += 1;
    }

    let mut cl = clusters(pats, &hits, cfg.gap);
    cl.sort_by_key(|c| (std::cmp::Reverse(c.score), c.start));
    let rp = out.join("report.tsv");
    let mut r = std::io::BufWriter::new(File::create(&rp)?);
    writeln!(
        r,
        "score\tcluster\tfirst_hit_offset\tcarve_start\tcarve_size\thits\tfile"
    )?;
    for (i, c) in cl.iter().enumerate() {
        let i = i + 1;
        let st = c.start.saturating_sub(cfg.before);
        let sz = (c.end + cfg.after - st)
            .min(cfg.maxcarve)
            .min(size.saturating_sub(st));
        let fname = out.join(format!(
            "cluster_{i:04}_score{:03}_off{:012}.bin",
            c.score, c.start
        ));
        let data = read(src, &mut buf, st, sz)?;
        fs::write(&fname, data)?;
        let summary: Vec<String> = c.counts.iter().map(|(k, v)| format!("{k}={v}")).collect();
        writeln!(
            r,
            "{}\t{i}\t{}\t{st}\t{}\t{}\t{}",
            c.score,
            c.start,
            data.len(),
            summary.join(","),
            fname.display()
        )?;
    }
    r.flush()?;
    drop(r);

    println!(
        "[+] {} hits, {} clusters, {nwhole} whole matches saved",
        hits.len(),
        cl.len()
    );
    println!("[+] Report (best first): {}", rp.display());
    let text = fs::read_to_string(&rp)?;
    let rows: Vec<Vec<&str>> = text
        .lines()
        .take(26)
        .map(|l| l.split('\t').collect())
        .collect();
    let w: Vec<usize> = (0..rows[0].len())
        .map(|k| {
            rows.iter()
                .map(|r| r.get(k).map_or(0, |v| v.len()))
                .max()
                .unwrap()
        })
        .collect();
    for row in &rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(k, v)| format!("{v:<w$}", w = w[k]))
            .collect();
        println!("{}", line.join("  ").trim_end());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clustering_and_dedup() {
        let pats = Patterns::new();
        let mkey = pats.index("btc_mkey").unwrap() as u16;
        let ckey = pats.index("btc_ckey").unwrap() as u16;
        let hits = vec![
            Hit {
                off: 100,
                len: 6,
                pat: mkey,
            },
            Hit {
                off: 100,
                len: 7,
                pat: mkey,
            },
            Hit {
                off: 2000,
                len: 7,
                pat: ckey,
            },
            Hit {
                off: 10_000_000,
                len: 7,
                pat: ckey,
            },
        ];
        let d = dedup(&hits);
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].len, 7);
        let c = clusters(&pats, &d, 1 << 20);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].score, 55);
        assert_eq!(c[1].score, 5);
    }
}
