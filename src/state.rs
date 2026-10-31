//! Resumable progress: `state.json` (scanned ranges + pending anchors) and
//! the append-only `hits.jsonl`.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    intervals::IntervalSet,
    patterns::Patterns,
    scan::{Hit, Pending},
};

#[derive(Serialize, Deserialize)]
struct StateFile {
    src: String,
    #[serde(default)]
    patterns: Option<String>,
    scanned: Vec<(u64, u64)>,
    pending: Vec<(String, u64)>,
}

pub struct State {
    dir: PathBuf,
    src: String,
    fingerprint: String,
    pub scanned: IntervalSet,
    pub pending: BTreeSet<Pending>,
    /// All hits so far, including previous runs.
    pub hits: Vec<Hit>,
    log: BufWriter<File>,
}

impl State {
    /// Load (or start) the state in `dir` for source `src`.
    pub fn open(dir: &Path, src: &str, pats: &Patterns, fresh: bool) -> Result<State> {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        let (state_f, hits_f) = (dir.join("state.json"), dir.join("hits.jsonl"));
        if fresh {
            for f in [&state_f, &hits_f] {
                if f.exists() {
                    fs::remove_file(f)?;
                }
            }
        }
        let mut st = State {
            dir: dir.to_owned(),
            src: src.to_owned(),
            fingerprint: pats.fingerprint.clone(),
            scanned: IntervalSet::new(),
            pending: BTreeSet::new(),
            hits: Vec::new(),
            log: BufWriter::new(OpenOptions::new().create(true).append(true).open(&hits_f)?),
        };
        if state_f.exists() {
            let sf: StateFile = serde_json::from_slice(&fs::read(&state_f)?)
                .with_context(|| format!("corrupt {}", state_f.display()))?;
            if sf.src != src {
                bail!(
                    "{} holds results for {}; use another -o or --fresh",
                    dir.display(),
                    sf.src
                );
            }
            if sf.patterns.as_deref() != Some(pats.fingerprint.as_str()) {
                bail!(
                    "{} was scanned with a different pattern set; \
                     use another -o or --fresh",
                    dir.display()
                );
            }
            st.scanned = IntervalSet::from_unsorted(sf.scanned);
            for (name, off) in sf.pending {
                if let Some(i) = pats.index(&name) {
                    st.pending.insert(Pending { pat: i as u16, off });
                }
            }
        }
        if hits_f.exists() {
            // A line cut by a crash is skipped; its chunk is not marked scanned anyway.
            for line in BufReader::new(File::open(&hits_f)?).lines() {
                let Ok((off, len, name)) = serde_json::from_str::<(u64, u64, String)>(&line?)
                else {
                    continue;
                };
                if let Some(i) = pats.index(&name) {
                    st.hits.push(Hit {
                        off,
                        len,
                        pat: i as u16,
                    });
                }
            }
        }
        Ok(st)
    }

    pub fn add_hits(&mut self, pats: &Patterns, hits: &[Hit]) -> Result<()> {
        for h in hits {
            writeln!(
                self.log,
                "[{}, {}, \"{}\"]",
                h.off, h.len, pats.list[h.pat as usize].name
            )?;
        }
        self.hits.extend_from_slice(hits);
        Ok(())
    }

    /// Durably write hits, then state (atomic rename).
    pub fn save(&mut self, pats: &Patterns) -> Result<()> {
        self.log.flush()?;
        self.log.get_ref().sync_data()?;
        let sf = StateFile {
            src: self.src.clone(),
            patterns: Some(self.fingerprint.clone()),
            scanned: self.scanned.as_slice().to_vec(),
            pending: self
                .pending
                .iter()
                .map(|p| (pats.list[p.pat as usize].name.to_owned(), p.off))
                .collect(),
        };
        let (path, tmp) = (self.dir.join("state.json"), self.dir.join("state.json.tmp"));
        let mut f = File::create(&tmp)?;
        serde_json::to_writer(&mut f, &sf)?;
        f.sync_all()?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_src_check() {
        let dir = std::env::temp_dir().join(format!("wscan-state-{}", std::process::id()));
        let pats = Patterns::new();
        {
            let mut st = State::open(&dir, "/img", &pats, true).unwrap();
            st.scanned.insert(0, 100);
            st.pending.insert(Pending { pat: 2, off: 50 });
            st.add_hits(
                &pats,
                &[Hit {
                    off: 5,
                    len: 7,
                    pat: 1,
                }],
            )
            .unwrap();
            st.save(&pats).unwrap();
        }
        let st = State::open(&dir, "/img", &pats, false).unwrap();
        assert_eq!(st.scanned.as_slice(), &[(0, 100)]);
        assert_eq!(st.pending.len(), 1);
        assert_eq!(
            st.hits,
            vec![Hit {
                off: 5,
                len: 7,
                pat: 1
            }]
        );
        assert!(State::open(&dir, "/other", &pats, false).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
