//! End-to-end wallet recovery: fixture wallets (tests/fixtures, made by
//! mkwallets.py) are planted in a disk image, whole or split into
//! out-of-order fragments, and must come back record for record.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use wscan::recover::keys::{hex, sha256d};

const MIB: usize = 1 << 20;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn records(name: &str) -> BTreeMap<String, String> {
    fs::read_to_string(fixture(&format!("{name}.records")))
        .unwrap()
        .lines()
        .map(|l| {
            let (k, v) = l.split_once(',').unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect()
}

/// Parse a dump file, checking its header and checksum.
fn read_dump(p: &Path) -> (String, BTreeMap<String, String>) {
    let text = fs::read_to_string(p).unwrap();
    let (body, last) = text.trim_end().rsplit_once('\n').unwrap();
    let sum = hex(&sha256d(format!("{body}\n").as_bytes()));
    assert_eq!(last, format!("checksum,{sum}"), "{}", p.display());
    let mut lines = body.lines();
    assert_eq!(lines.next(), Some("BITCOIN_CORE_WALLET_DUMP,1"));
    let fmt = lines
        .next()
        .unwrap()
        .strip_prefix("format,")
        .unwrap()
        .to_owned();
    let recs = lines
        .map(|l| l.split_once(',').unwrap())
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    (fmt, recs)
}

struct Rng(u64);

impl Rng {
    fn fill(&mut self, b: &mut [u8]) {
        for c in b.chunks_mut(8) {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            c.copy_from_slice(&self.0.to_le_bytes()[..c.len()]);
        }
    }
}

/// What `build_image` planted, for the assertions.
struct Planted {
    img: PathBuf,
    legacy_enc: Vec<u8>,
    desc_enc: Vec<u8>,
    electrum: &'static [u8],
    bci: &'static [u8],
    xprv: String,
}

/// A 72 MiB disk image with the fixture wallets, whole and split, plus a
/// lone key and JSON wallets.
fn build_image(dir: &Path) -> Planted {
    let mut img = vec![0u8; 72 * MIB];
    // Background: random data in some places, text in others, zeros elsewhere.
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for m in (0..72).step_by(3) {
        rng.fill(&mut img[m * MIB..(m + 1) * MIB]);
    }
    let put = |img: &mut Vec<u8>, off: usize, data: &[u8]| {
        img[off..off + data.len()].copy_from_slice(data)
    };
    let ps = 4096;

    // 1. Encrypted legacy wallet, contiguous, sector- but not page-aligned.
    let legacy_enc = fs::read(fixture("legacy_enc.wallet")).unwrap();
    put(&mut img, 5 * MIB + 3 * 512, &legacy_enc);

    // 2. Unencrypted legacy wallet split in two, second half stored first.
    let legacy_plain = fs::read(fixture("legacy_plain.wallet")).unwrap();
    let cut = legacy_plain.len() / ps / 2 * ps;
    put(&mut img, 20 * MIB, &legacy_plain[..cut]);
    put(&mut img, 19 * MIB + 512, &legacy_plain[cut..]);

    // 3. Encrypted descriptor wallet, contiguous.
    let desc_enc = fs::read(fixture("desc_enc.wallet")).unwrap();
    put(&mut img, 40 * MIB, &desc_enc);

    // 4. Unencrypted descriptor wallet split in two.
    let desc_plain = fs::read(fixture("desc_plain.wallet")).unwrap();
    let cut2 = desc_plain.len() / ps / 2 * ps;
    put(&mut img, 48 * MIB, &desc_plain[..cut2]);
    put(&mut img, 50 * MIB + 1024, &desc_plain[cut2..]);

    // 5. A lone private key, e.g. from a deleted file: secret 1 (generator point).
    let one_der = fs::read_to_string(fixture("secret1.der.hex")).unwrap();
    let one_der: Vec<u8> = (0..one_der.trim().len() / 2)
        .map(|i| u8::from_str_radix(&one_der[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    put(&mut img, 60 * MIB + 777, &one_der);

    // 6. An Electrum JSON wallet.
    let electrum = br#"{
    "addr_history": {"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": [["4a5e1e", 1]]},
    "keystore": {"type": "bip32", "xpub": "xpub661MyMwAqRbcF", "seed": "{not a brace}"},
    "seed_version": 18,
    "use_encryption": false,
    "wallet_type": "standard"
}"#;
    put(&mut img, 66 * MIB + 99, electrum);

    // 7. JSON-type wallets and an extended key.
    let sample = |n: &str| {
        wscan::patterns::samples::all()
            .into_iter()
            .find(|s| s.0 == n)
            .unwrap()
            .1
    };
    put(&mut img, 67 * MIB + 5, &sample("eth_keystore"));
    let b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789+/".repeat(4);
    let vault = format!(
        r#"leveldb{{"vault":"{{\"data\":\"{b64}\",\"iv\":\"aGVsbG8gd29ybGQgaXY=\",\"salt\":\"c2FsdHNhbHRzYWx0c2FsdA==\"}}"}}"#
    );
    put(&mut img, 67 * MIB + 10_000, vault.as_bytes());
    let mut payload = vec![0x04, 0x88, 0xad, 0xe4];
    payload.extend([0u8; 41]);
    payload.extend([0x5au8; 33]);
    payload[45] = 0;
    let xprv = wscan::recover::keys::base58check(&payload);
    let mut bad = xprv.clone().into_bytes();
    bad[50] = if bad[50] == b'z' { b'y' } else { b'z' };
    put(
        &mut img,
        67 * MIB + 20_000,
        format!(" {xprv} {} ", String::from_utf8(bad).unwrap()).as_bytes(),
    );
    let bci = br#"{"guid":"8c4ab1f2-1234-4abc-9def-0123456789ab","sharedKey":"x","double_encryption":false,"keys":[{"addr":"1x","priv":"y"}]}"#;
    put(&mut img, 67 * MIB + 30_000, bci);
    put(&mut img, 67 * MIB + 40_000, &sample("electrum_encrypted"));

    let img_path = dir.join("disk.img");
    fs::write(&img_path, &img).unwrap();
    Planted {
        img: img_path,
        legacy_enc,
        desc_enc,
        electrum,
        bci,
        xprv,
    }
}

fn tmp(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn recovers_wallets_whole_and_fragmented() {
    let dir = tmp("recover");
    let Planted {
        img: img_path,
        legacy_enc,
        desc_enc,
        electrum,
        bci,
        xprv,
    } = build_image(&dir);
    let out = dir.join("out");
    let st = Command::new(env!("CARGO_BIN_EXE_wscan"))
        .args([img_path.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());

    let rec = out.join("recovered");
    let dumps: Vec<PathBuf> = fs::read_dir(rec.join("bitcoin"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "dump"))
        .collect();
    let parsed: Vec<(PathBuf, String, BTreeMap<String, String>)> = dumps
        .iter()
        .map(|p| {
            let (f, r) = read_dump(p);
            (p.clone(), f, r)
        })
        .collect();
    assert_eq!(parsed.len(), 4, "{:?}", dumps);

    let find = |name: &str| {
        let want = records(name);
        let probe = want
            .keys()
            .find(|k| {
                k.starts_with("04636b6579")
                    || k.starts_with("036b6579")
                    || k.starts_with("13")
                    || k.starts_with("14")
            })
            .unwrap()
            .clone();
        parsed
            .iter()
            .find(|(_, _, r)| r.contains_key(&probe))
            .unwrap_or_else(|| panic!("{name} not recovered"))
    };

    // Contiguous and split legacy wallets: every record back, byte for byte.
    for (name, fmt) in [
        ("legacy_enc", "bdb"),
        ("legacy_plain", "bdb"),
        ("desc_enc", "sqlite"),
    ] {
        let (p, f, got) = find(name);
        assert_eq!(f, fmt, "{name}");
        let want = records(name);
        let missing: Vec<_> = want.keys().filter(|k| !got.contains_key(*k)).collect();
        assert!(
            missing.is_empty(),
            "{name}: {} missing, e.g. {:?}",
            missing.len(),
            missing.first()
        );
        assert_eq!(*got, want, "{name}: {}", p.display());
    }
    let carved = |ext: &str| -> Vec<Vec<u8>> {
        fs::read_dir(rec.join("bitcoin"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == ext))
            .map(|p| fs::read(p).unwrap())
            .collect()
    };
    // Contiguous files are carved whole; split ones are not.
    assert_eq!(carved("dat"), vec![legacy_enc.clone()]);
    assert_eq!(carved("sqlite"), vec![desc_enc.clone()]);

    // Split SQLite wallet: overflow chains of the second half cannot be
    // followed, so large `tx` records may be lost; everything else is back and
    // nothing is wrong.
    let (_, f, got) = find("desc_plain");
    assert_eq!(f, "sqlite");
    let want = records("desc_plain");
    for (k, v) in got {
        assert_eq!(want.get(k), Some(v), "wrong record {k}");
    }
    for k in want.keys().filter(|k| !k.starts_with("027478")) {
        assert!(got.contains_key(k), "desc_plain lost non-tx record {k}");
    }

    // Unencrypted keys: all of them, verified, plus the lone key.
    let tsv = fs::read_to_string(rec.join("keys/private_keys.tsv")).unwrap();
    let secrets: BTreeSet<&str> = tsv
        .lines()
        .skip(1)
        .map(|l| l.split('\t').nth(4).unwrap())
        .collect();
    let mut want_keys: BTreeSet<String> = ["legacy_plain", "desc_plain"]
        .iter()
        .flat_map(|n| {
            fs::read_to_string(fixture(&format!("{n}.keys")))
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    want_keys.insert(format!("{:064x}", 1));
    for k in &want_keys {
        assert!(secrets.contains(k.as_str()), "key {k} not exported");
    }
    assert_eq!(secrets.len(), want_keys.len());
    let line1 = tsv
        .lines()
        .find(|l| l.contains(&format!("{:064x}", 1)))
        .unwrap();
    assert!(line1.starts_with("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn\t1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH\tbc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), "{line1}");

    // Electrum: the complete JSON file, and the encrypted file.
    let files = |sub: &str| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<_> = fs::read_dir(rec.join(sub))
            .unwrap()
            .map(|e| e.unwrap().path())
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    fs::read(&p).unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    };
    let el = files("electrum");
    assert_eq!(el.len(), 2);
    assert!(
        el.iter()
            .any(|(n, d)| n.starts_with("wallet_") && d == electrum)
    );
    assert!(
        el.iter()
            .any(|(n, d)| n.starts_with("encrypted_") && d.starts_with(b"QklFMQ"))
    );

    let eth = files("ethereum");
    assert_eq!(eth.len(), 1);
    assert!(
        eth[0]
            .0
            .ends_with("--008aeeda4d805471df9b2a5b0f38a0c3bcba786b.json")
    );
    serde_json::from_slice::<serde_json::Value>(&eth[0].1).unwrap();

    let mm = files("metamask");
    assert_eq!(mm.len(), 1);
    let v: serde_json::Value = serde_json::from_slice(&mm[0].1).unwrap();
    assert_eq!(v["salt"], "c2FsdHNhbHRzYWx0c2FsdA==");

    assert_eq!(files("blockchain_info")[0].1, bci);
    let x = fs::read_to_string(rec.join("keys/bip32_xprv.txt")).unwrap();
    assert_eq!(x.lines().count(), 1, "{x}");
    assert!(x.starts_with(&xprv));
}

/// Wallets are recovered while the scan runs; an interrupt keeps them, and
/// the resumed scan re-announces them and finishes the job.
#[test]
fn live_recovery_survives_interrupt_and_resume() {
    let dir = tmp("recover_live");
    let p = build_image(&dir);
    let out = dir.join("out");
    let err1 = dir.join("run1.err");
    let mut child = Command::new(env!("CARGO_BIN_EXE_wscan"))
        .args([
            p.img.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--chunk",
            "1M",
            "--max-rate",
            "12",
        ])
        .stdout(Stdio::null())
        .stderr(fs::File::create(&err1).unwrap())
        .spawn()
        .unwrap();
    // Wait until both legacy wallets (at 5 and 20 MiB) were found live.
    let t = std::time::Instant::now();
    while fs::read_to_string(&err1)
        .unwrap()
        .matches("FOUND BITCOIN CORE WALLET (LEGACY")
        .count()
        < 2
    {
        assert!(
            t.elapsed().as_secs() < 30,
            "no live finding: {}",
            fs::read_to_string(&err1).unwrap()
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "scan ended before the interrupt"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let bitcoin = out.join("recovered/bitcoin");
    assert!(bitcoin.join("wallet_bdb_off000005244416.dump").exists());
    assert_eq!(
        fs::read(bitcoin.join("wallet_bdb_off000005244416.dat")).unwrap(),
        p.legacy_enc
    );

    unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    let st = child.wait().unwrap();
    assert_eq!(st.code(), Some(130));
    assert!(bitcoin.join("wallet_bdb_off000020971520.dump").exists());
    let state = fs::read_to_string(out.join("state.json")).unwrap();
    assert!(
        !state.contains(&format!("[[0,{}]]", 72 * MIB)),
        "interrupted scan must not be complete"
    );

    let o = Command::new(env!("CARGO_BIN_EXE_wscan"))
        .args([p.img.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(
        err.matches("[=] found earlier: BITCOIN CORE WALLET (LEGACY")
            .count(),
        2,
        "{err}"
    );
    assert!(
        err.contains("FOUND BITCOIN CORE WALLET (DESCRIPTOR"),
        "{err}"
    );
    let dumps = fs::read_dir(&bitcoin)
        .unwrap()
        .filter(|e| e.as_ref().unwrap().path().extension().unwrap() == "dump")
        .count();
    assert_eq!(dumps, 4);
    let addrs = fs::read_to_string(out.join("recovered/addresses.tsv")).unwrap();
    assert!(addrs.contains("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH\tloose private key"));
    assert!(addrs.contains("0x008aeeda4d805471df9b2a5b0f38a0c3bcba786b"));
    assert!(addrs.contains("\tbitcoin core descriptor\t"));
}
