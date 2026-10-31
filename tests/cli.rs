//! End-to-end tests of the wscan binary.

use std::{
    collections::BTreeSet,
    fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use wscan::patterns::samples;

fn tmpdir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn sample(name: &str) -> (Vec<u8>, usize) {
    let (_, d, r) = samples::all().into_iter().find(|s| s.0 == name).unwrap();
    (d, r)
}

fn put(img: &Path, off: u64, data: &[u8]) {
    let mut f = fs::OpenOptions::new().write(true).open(img).unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(data).unwrap();
}

fn hits(out: &Path) -> BTreeSet<(u64, String)> {
    fs::read_to_string(out.join("hits.jsonl"))
        .unwrap()
        .lines()
        .map(|l| {
            let (o, _, n): (u64, u64, String) = serde_json::from_str(l).unwrap();
            (o, n)
        })
        .collect()
}

#[test]
fn full_scan_finds_all_samples_across_chunk_boundaries() {
    let d = tmpdir("full");
    let img = d.join("img");
    fs::write(&img, vec![b'.'; 20 << 20]).unwrap();
    let mut expect = BTreeSet::new();
    for (k, (name, data, rel)) in samples::all().into_iter().enumerate() {
        // Right across a 1 MiB chunk boundary.
        let off = ((k as u64 + 1) << 20) - 7;
        put(&img, off, &data);
        expect.insert((off + rel as u64, name.to_string()));
    }
    let out = d.join("out");
    let st = Command::new(env!("CARGO_BIN_EXE_wscan"))
        .args([
            img.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--chunk",
            "1M",
            "-j",
            "3",
        ])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    assert_eq!(hits(&out), expect);
    assert!(out.join("report.tsv").exists());
    let eth = fs::read_dir(&out).unwrap().filter_map(|e| e.ok()).any(|e| {
        e.file_name()
            .to_string_lossy()
            .starts_with("match_eth_keystore_")
    });
    assert!(eth);

    // Re-running resumes: nothing left to scan, same hits.
    let st = Command::new(env!("CARGO_BIN_EXE_wscan"))
        .args([img.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    assert_eq!(hits(&out), expect);
}

fn write_map(path: &Path, rescued_to: u64, size: u64, finished: bool) {
    let st = if finished { '+' } else { '?' };
    let mut s =
        format!("# Mapfile. Created by test\n0x{rescued_to:08X}     {st}               1\n");
    s += &format!("0x00000000  0x{rescued_to:08X}  +\n");
    if rescued_to < size {
        s += &format!("0x{rescued_to:08X}  0x{:08X}  ?\n", size - rescued_to);
    }
    // ddrescue rewrites in place; write via rename so the test is deterministic.
    fs::write(path.with_extension("tmp"), s).unwrap();
    fs::rename(path.with_extension("tmp"), path).unwrap();
}

#[test]
fn follow_mode_picks_up_newly_rescued_areas() {
    let d = tmpdir("follow");
    let (img, map, out) = (d.join("img"), d.join("img.map"), d.join("out"));
    let size = 8u64 << 20;
    let cut = 3u64 << 20;
    fs::write(&img, vec![0u8; size as usize]).unwrap();

    // A: anchor straddles the rescued boundary (only its first bytes rescued).
    // B: inside the rescued area, but its window reaches past the boundary.
    // C: entirely in the later area.
    let (a, ar) = sample("btc_ckey");
    let (b, br) = sample("eth_keystore");
    let (c, cr) = sample("bip32_xprv");
    let (aoff, boff, coff) = (cut - 3, cut - 1000, 6u64 << 20);
    put(&img, aoff, &a[..3]);
    put(&img, boff, &b[..200]);
    write_map(&map, cut, size, false);

    let mut child = Command::new(env!("CARGO_BIN_EXE_wscan"))
        .args([
            img.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "-m",
            map.to_str().unwrap(),
            "--poll",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_secs(2));
    assert!(
        child.try_wait().unwrap().is_none(),
        "exited before ddrescue finished"
    );

    // "ddrescue" rescues the rest and finishes.
    put(&img, aoff, &a);
    put(&img, boff, &b);
    put(&img, coff, &c);
    write_map(&map, size, size, true);

    let t = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if t.elapsed() > Duration::from_secs(30) {
            child.kill().unwrap();
            panic!("wscan did not exit after ddrescue finished");
        }
        thread::sleep(Duration::from_millis(100));
    };
    assert!(status.success());
    let h = hits(&out);
    for (off, name) in [
        (aoff + ar as u64, "btc_ckey"),
        (boff + br as u64, "eth_keystore"),
        (coff + cr as u64, "bip32_xprv"),
    ] {
        assert!(
            h.contains(&(off, name.to_string())),
            "missing {name} in {h:?}"
        );
    }
    let state = fs::read_to_string(out.join("state.json")).unwrap();
    assert!(
        state.contains(&format!("\"scanned\":[[0,{size}]]")),
        "{state}"
    );
    assert!(state.contains("\"pending\":[]"), "{state}");
}
