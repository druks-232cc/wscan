//! JSON wallets: find the complete object around a hit and validate it.

use serde_json::Value;

/// End (exclusive) of the balanced JSON object starting at `b[start] == '{'`,
/// skipping braces inside strings.
fn object_end(b: &[u8], start: usize, max_len: usize) -> Option<usize> {
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    for (i, &c) in b.iter().enumerate().skip(start).take(max_len) {
        if in_str {
            match c {
                _ if esc => esc = false,
                b'\\' => esc = true,
                b'"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            0 => return None,
            _ => {}
        }
    }
    None
}

/// The innermost JSON object around `b[rel]` that parses and satisfies
/// `want`. Tries up to 64 opening braces going backwards.
pub fn enclosing_object(
    b: &[u8],
    rel: usize,
    max_len: usize,
    want: impl Fn(&Value) -> bool,
) -> Option<(usize, usize, Value)> {
    let mut tried = 0;
    let mut i = rel + 1;
    while i > 0 && tried < 64 {
        i -= 1;
        if b[i] != b'{' {
            continue;
        }
        tried += 1;
        let Some(end) = object_end(b, i, max_len) else {
            continue;
        };
        if end <= rel {
            continue;
        }
        if let Ok(v) = serde_json::from_slice::<Value>(&b[i..end])
            && want(&v)
        {
            return Some((i, end, v));
        }
    }
    None
}

/// Undo one level of JSON string escaping (vaults stored inside another
/// JSON string, e.g. MetaMask's LevelDB values).
pub fn unescape(b: &[u8]) -> Option<Vec<u8>> {
    let quoted = [b"\"", b, b"\""].concat();
    serde_json::from_slice::<String>(&quoted)
        .ok()
        .map(String::into_bytes)
}

pub fn has_keys(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| keys.iter().all(|k| o.contains_key(*k)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_outer_wallet_object() {
        let doc = br#"garbage { "x": 1 } {"addresses": {"receiving": ["a{"]}, "seed_version": 17, "wallet_type": "standard", "keystore": {"type": "bip32"}} trailing"#;
        let rel = memchr::memmem::find(doc, b"\"seed_version\"").unwrap();
        let (s, e, _) =
            enclosing_object(doc, rel, 1 << 20, |v| has_keys(v, &["seed_version"])).unwrap();
        assert!(doc[s..e].starts_with(b"{\"addresses\""));
        assert!(doc[s..e].ends_with(b"}}"));
    }

    #[test]
    fn rejects_truncated() {
        let doc = br#"{"seed_version": 17, "wallet_type": "standard", "keystore": {"#;
        assert!(enclosing_object(doc, 2, 1 << 20, |_| true).is_none());
    }

    #[test]
    fn unescapes_vault() {
        assert_eq!(
            unescape(br#"{\"data\":\"x\"}"#).unwrap(),
            br#"{"data":"x"}"#
        );
    }
}
