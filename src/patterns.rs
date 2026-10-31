//! Wallet signatures. Every pattern has fixed "anchor" literals that any match
//! must contain; anchors are found with one SIMD pass over the data and the
//! full regex only runs on a small window around each anchor (the ripgrep
//! "inner literal" strategy).

use std::collections::BTreeMap;

use regex_automata::{meta, util::syntax};

/// JSON filler: no braces, no NUL byte.
const J: &str = r"[^{}\x00]";
/// Base64 alphabet.
const B64: &str = r"[A-Za-z0-9+/=]";
/// Double quote, optionally JSON-escaped.
const Q: &str = r#"\\?""#;

pub struct Pattern {
    pub name: &'static str,
    pub anchors: Vec<&'static [u8]>,
    pub source: String,
    pub re: meta::Regex,
    /// Bytes read before the anchor. Patterns with `before <= 1` must match
    /// starting exactly at their anchor (anchored search).
    pub before: u64,
    /// Bytes read after the anchor; `None` means `--maxmatch`.
    pub after: Option<u64>,
    /// Save the whole match to its own file in the report.
    pub whole: bool,
}

impl Pattern {
    pub fn anchored(&self) -> bool {
        self.before <= 1
    }
}

pub struct Patterns {
    pub list: Vec<Pattern>,
    /// (pattern index, anchor literal), in prefilter order.
    pub anchors: Vec<(usize, &'static [u8])>,
    pub max_anchor_len: usize,
    /// Changes whenever the pattern set changes; stored in state.json.
    pub fingerprint: String,
}

/// name, anchor literals, regex, bytes before / after the anchor, save whole match.
type Def = (
    &'static str,
    Vec<&'static [u8]>,
    String,
    u64,
    Option<u64>,
    bool,
);

fn defs() -> Vec<Def> {
    let nest = format!(r"(?:{J}|\{{{J}*\}})");
    // Two levels deep: modern MetaMask vaults put "keyMetadata":{..{..}..}
    // between "iv" and "salt" (a brace-free filler misses them).
    let nest2 = format!(r"(?:{J}|\{{{nest}*\}})");
    vec![
        // Bitcoin Core (Berkeley DB wallet.dat): record keys + expected binary layout
        (
            "btc_mkey",
            vec![b"\x04mkey\x01\x00"],
            r"\x04mkey\x01\x00".into(),
            0,
            Some(16),
            false,
        ),
        (
            "btc_ckey",
            vec![b"\x04ckey"],
            r"\x04ckey[\x21\x41][\x02\x03\x04]".into(),
            0,
            Some(16),
            false,
        ),
        (
            "btc_key",
            vec![b"\x03key"],
            r"\x03key[\x21\x41][\x02\x03\x04]".into(),
            0,
            Some(16),
            false,
        ),
        (
            "btc_defaultkey",
            vec![b"defaultkey"],
            r"defaultkey[\x21\x41][\x02\x03\x04]".into(),
            0,
            Some(16),
            false,
        ),
        (
            "btc_hdchain",
            vec![b"\x07hdchain"],
            r"\x07hdchain".into(),
            0,
            Some(16),
            false,
        ),
        // Bitcoin Core descriptor wallets (SQLite, v0.21+): record key, 32-byte
        // descriptor id, then the serialized pubkey.
        (
            "btc_desc_key",
            vec![b"\x13walletdescriptorkey"],
            r"\x13walletdescriptorkey(?s:.){32}[\x21\x41][\x02\x03\x04]".into(),
            0,
            Some(64),
            false,
        ),
        (
            "btc_desc_ckey",
            vec![b"\x14walletdescriptorckey"],
            r"\x14walletdescriptorckey(?s:.){32}[\x21\x41][\x02\x03\x04]".into(),
            0,
            Some(64),
            false,
        ),
        (
            "btc_desc",
            vec![b"\x10walletdescriptor"],
            r"\x10walletdescriptor".into(),
            0,
            Some(32),
            false,
        ),
        // Unencrypted private key in Bitcoin Core's DER format (inside `key`
        // records, but also in deleted files and stale pages).
        (
            "btc_privkey_der",
            vec![
                b"\x30\x81\xd3\x02\x01\x01\x04\x20",
                b"\x30\x82\x01\x13\x02\x01\x01\x04\x20",
            ],
            r"(?:\x30\x81\xd3|\x30\x82\x01\x13)\x02\x01\x01\x04\x20(?s:.){32}\xa0".into(),
            0,
            Some(300),
            false,
        ),
        // Ethereum keystore v3: whole JSON object with a crypto block and 64-hex ciphertext
        (
            "eth_keystore",
            vec![br#""ciphertext""#],
            format!(
                r#"\{{{J}{{0,400}}"[cC]rypto"\s*:\s*\{{{nest}*?"ciphertext"\s*:\s*"[0-9a-fA-F]{{64}}"{nest}*?\}}{J}{{0,400}}\}}"#
            ),
            16384,
            Some(16384),
            true,
        ),
        // MetaMask vault (plain or JSON-escaped inside LevelDB)
        (
            "metamask_vault",
            vec![br#""salt"#],
            format!(
                r"\{{{Q}data{Q}\s*:\s*{Q}{B64}{{100,}}{Q}\s*,\s*{Q}iv{Q}\s*:\s*{Q}{B64}{{16,}}{Q}{nest2}{{0,300}}{Q}salt{Q}\s*:\s*{Q}{B64}{{16,}}{Q}{nest2}{{0,300}}\}}"
            ),
            1 << 20,
            Some(4096),
            true,
        ),
        // Electrum: plain JSON wallet, and encrypted file (base64 of "BIE1")
        (
            "electrum_seedver",
            vec![br#""seed_version""#],
            r#""seed_version"\s*:\s*[0-9]{1,2}\s*[,}]"#.into(),
            0,
            Some(64),
            false,
        ),
        (
            "electrum_type",
            vec![br#""wallet_type""#],
            r#""wallet_type"\s*:\s*"(?:standard|imported|2fa|[0-9]+of[0-9]+)""#.into(),
            0,
            Some(64),
            false,
        ),
        (
            "electrum_encrypted",
            vec![b"QklFMQ"],
            r"QklFMQ[A-Za-z0-9+/]{200,}={0,2}".into(),
            0,
            None,
            true,
        ),
        // BIP32 extended private keys (full length only)
        (
            "bip32_xprv",
            vec![b"xprv", b"yprv", b"zprv", b"tprv"],
            r"\b[xyzt]prv[1-9A-HJ-NP-Za-km-z]{107,108}\b".into(),
            1,
            Some(120),
            true,
        ),
        // Blockchain.info legacy wallet
        (
            "blockchain_info",
            vec![br#"{"guid""#],
            r#"\{"guid"\s*:\s*"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}""#
                .into(),
            0,
            Some(64),
            true,
        ),
    ]
}

/// Byte-oriented regex: no Unicode, `.`/classes match any byte.
pub fn compile(source: &str) -> meta::Regex {
    meta::Regex::builder()
        .syntax(syntax::Config::new().unicode(false).utf8(false))
        .configure(meta::Config::new().utf8_empty(false))
        .build(source)
        .unwrap_or_else(|e| panic!("bad pattern {source:?}: {e}"))
}

impl Patterns {
    pub fn new() -> Patterns {
        let mut list = Vec::new();
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a
        for (name, anchors, source, before, after, whole) in defs() {
            let fp = format!("{name}\0{source}\0{before}\0{after:?}\0");
            for b in fp.bytes() {
                h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
            }
            let re = compile(&source);
            list.push(Pattern {
                name,
                anchors,
                source,
                re,
                before,
                after,
                whole,
            });
        }
        let anchors: Vec<_> = list
            .iter()
            .enumerate()
            .flat_map(|(i, p)| p.anchors.iter().map(move |a| (i, *a)))
            .collect();
        let max_anchor_len = anchors.iter().map(|(_, a)| a.len()).max().unwrap_or(1);
        Patterns {
            list,
            anchors,
            max_anchor_len,
            fingerprint: format!("{h:016x}"),
        }
    }

    pub fn index(&self, name: &str) -> Option<usize> {
        self.list.iter().position(|p| p.name == name)
    }
}

impl Default for Patterns {
    fn default() -> Self {
        Self::new()
    }
}

/// Real wallets produce several related records close together.
pub fn score(n: &BTreeMap<&str, u32>) -> u32 {
    let g = |k: &str| n.get(k).copied().unwrap_or(0);
    let once = |k: &str, w: u32| if g(k) > 0 { w } else { 0 };
    let mut s = once("btc_mkey", 50);
    s += 5 * g("btc_ckey") + 5 * g("btc_key");
    s += once("btc_defaultkey", 10) + once("btc_hdchain", 10);
    s += 5 * g("btc_desc_ckey") + 5 * g("btc_desc_key") + once("btc_desc", 10);
    s += 20 * g("btc_privkey_der");
    s += 60 * g("eth_keystore") + 60 * g("metamask_vault");
    if g("electrum_seedver") > 0 && g("electrum_type") > 0 {
        s += 30;
    }
    s += 40 * g("electrum_encrypted") + 40 * g("bip32_xprv");
    s += 20 * g("blockchain_info");
    s
}

#[doc(hidden)]
pub mod samples {
    //! Positive samples for every pattern, shared by tests, benches and examples.

    pub fn hex64() -> String {
        "0123456789abcdef".repeat(4)
    }

    /// (pattern name, sample bytes, offset of the expected match inside the sample)
    pub fn all() -> Vec<(&'static str, Vec<u8>, usize)> {
        let b58: String = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".repeat(2);
        let b64: String = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789+/".repeat(5);
        vec![
            ("btc_mkey", b"\x04mkey\x01\x00\x00\x00\x30".to_vec(), 0),
            ("btc_ckey", b"\x04ckey\x21\x02abcdefgh".to_vec(), 0),
            ("btc_key", b"\x03key\x41\x04abcdefgh".to_vec(), 0),
            ("btc_defaultkey", b"defaultkey\x21\x03xx".to_vec(), 0),
            ("btc_hdchain", b"\x07hdchain\x00\x01".to_vec(), 0),
            ("btc_desc_key", [&b"\x13walletdescriptorkey"[..], &[0x55; 32], b"\x21\x02rest"].concat(), 0),
            ("btc_desc_ckey", [&b"\x14walletdescriptorckey"[..], &[0xaa; 32], b"\x21\x03rest"].concat(), 0),
            ("btc_desc", b"\x10walletdescriptor\x01\x02".to_vec(), 0),
            (
                "btc_privkey_der",
                [&b"\x30\x81\xd3\x02\x01\x01\x04\x20"[..], &[0x11; 32], b"\xa0\x81\x85"].concat(),
                0,
            ),
            ("eth_keystore", format!(
                r#"xx{{"address":"008aeeda4d805471df9b2a5b0f38a0c3bcba786b","crypto":{{"cipher":"aes-128-ctr","ciphertext":"{h}","cipherparams":{{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"}},"kdf":"scrypt","kdfparams":{{"dklen":32,"n":262144,"p":8,"r":1,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"}},"mac":"{h}"}},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}}yy"#,
                h = hex64()).into_bytes(), 2),
            ("metamask_vault", format!(
                r#"zz{{"data":"{b64}","iv":"aGVsbG8gd29ybGQgaXY=","keyMetadata":{{"algorithm":"PBKDF2","params":{{"iterations":600000}}}},"salt":"c2FsdHNhbHRzYWx0c2FsdA=="}}"#
            ).into_bytes(), 2),
            ("electrum_seedver", br#""seed_version": 17,"#.to_vec(), 0),
            ("electrum_type", br#""wallet_type": "standard""#.to_vec(), 0),
            ("electrum_encrypted", format!("QklFMQ{}==\n", &b64.replace('=', "")[..220]).into_bytes(), 0),
            ("bip32_xprv", format!(" xprv{} ", &b58[..107]).into_bytes(), 1),
            ("blockchain_info", br#"{"guid":"8c4ab1f2-1234-4abc-9def-0123456789ab","sharedKey":"x"}"#.to_vec(), 0),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sample_matches_its_pattern_only_at_its_offset() {
        let pats = Patterns::new();
        for (name, data, off) in samples::all() {
            let p = &pats.list[pats.index(name).unwrap()];
            let m =
                p.re.find(&data[..])
                    .unwrap_or_else(|| panic!("{name} did not match"));
            assert_eq!(m.start(), off, "{name}");
        }
    }

    #[test]
    fn every_pattern_has_a_sample() {
        let pats = Patterns::new();
        let names: Vec<_> = samples::all().iter().map(|s| s.0).collect();
        for p in &pats.list {
            assert!(names.contains(&p.name), "no sample for {}", p.name);
        }
    }

    #[test]
    fn negative_samples() {
        let pats = Patterns::new();
        let neg: &[(&str, &[u8])] = &[
            ("btc_ckey", b"\x04ckey\x20\x02"),
            ("btc_key", b"\x03key\x21\x05"),
            ("btc_desc_key", b"\x13walletdescriptorkey\x21\x02"),
            ("electrum_type", br#""wallet_type": "bogus""#),
            ("bip32_xprv", b"xprv0OIl"),
            ("blockchain_info", br#"{"guid":"not-a-guid"}"#),
        ];
        for (name, data) in neg {
            let p = &pats.list[pats.index(name).unwrap()];
            assert!(p.re.find(*data).is_none(), "{name} matched {data:?}");
        }
    }

    /// Anchored patterns: every literal prefix the regex can start with must
    /// begin with one of the pattern's anchors, otherwise a match could exist
    /// without its anchor and be missed by the prefilter.
    #[test]
    fn anchors_are_required_prefixes() {
        use regex_syntax::hir::literal::{ExtractKind, Extractor};
        let pats = Patterns::new();
        for p in pats.list.iter().filter(|p| p.anchored()) {
            let hir = regex_syntax::ParserBuilder::new()
                .unicode(false)
                .utf8(false)
                .build()
                .parse(&p.source)
                .unwrap();
            let seq = Extractor::new().kind(ExtractKind::Prefix).extract(&hir);
            let lits = seq
                .literals()
                .unwrap_or_else(|| panic!("{}: infinite prefix set", p.name));
            assert!(!lits.is_empty(), "{}", p.name);
            for lit in lits {
                let b = lit.as_bytes();
                assert!(
                    p.anchors.iter().any(|a| b.starts_with(a)),
                    "{}: prefix {:?} lacks an anchor",
                    p.name,
                    String::from_utf8_lossy(b)
                );
            }
        }
    }

    /// Windowed patterns: the anchor must occur in every sample match.
    #[test]
    fn windowed_anchor_inside_match() {
        let pats = Patterns::new();
        for (name, data, _) in samples::all() {
            let p = &pats.list[pats.index(name).unwrap()];
            let m = p.re.find(&data[..]).unwrap();
            let s = &data[m.range()];
            assert!(
                p.anchors
                    .iter()
                    .any(|a| memchr::memmem::find(s, a).is_some()),
                "{name}"
            );
        }
    }

    #[test]
    fn scores() {
        let n: BTreeMap<&str, u32> = [("btc_mkey", 1), ("btc_ckey", 4)].into();
        assert_eq!(score(&n), 70);
        let n: BTreeMap<&str, u32> = [("electrum_seedver", 1), ("electrum_type", 1)].into();
        assert_eq!(score(&n), 30);
    }
}
