//! Private keys: Bitcoin Core's DER format, verification against the public
//! key with real secp256k1 arithmetic, WIF / address encoding.

use k256::{PublicKey, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn sha256d(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b))
}

pub fn hash160(b: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(b)).into()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58(b: &[u8]) -> String {
    let zeros = b.iter().take_while(|&&x| x == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &x in &b[zeros..] {
        let mut carry = x as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut s = "1".repeat(zeros);
    s.extend(digits.iter().rev().map(|&d| B58[d as usize] as char));
    s
}

pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let zeros = s.bytes().take_while(|&c| c == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for c in s.bytes().skip(zeros) {
        let mut carry = B58.iter().position(|&x| x == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

pub fn base58check(payload: &[u8]) -> String {
    let mut v = payload.to_vec();
    v.extend_from_slice(&sha256d(payload)[..4]);
    base58(&v)
}

/// Decode and verify a base58check string; returns the payload.
pub fn base58check_decode(s: &str) -> Option<Vec<u8>> {
    let v = base58_decode(s)?;
    if v.len() < 5 {
        return None;
    }
    let (p, c) = v.split_at(v.len() - 4);
    (sha256d(p)[..4] == *c).then(|| p.to_vec())
}

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Segwit v0 address (bech32, BIP173).
pub fn segwit_v0(hrp: &str, program: &[u8]) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut data = vec![0u8]; // witness version 0
    let (mut acc, mut bits) = (0u32, 0);
    for &b in program {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v.extend(&data);
    v.extend([0u8; 6]);
    let pm = bech32_polymod(&v) ^ 1;
    let mut s = format!("{hrp}1");
    for &d in &data {
        s.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

/// A private key whose public key was recomputed and checked.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub secret: [u8; 32],
    pub pubkey: Vec<u8>,
}

pub fn p2pkh(pubkey: &[u8]) -> String {
    let mut p = vec![0x00];
    p.extend_from_slice(&hash160(pubkey));
    base58check(&p)
}

/// Native segwit address (only defined for compressed keys).
pub fn p2wpkh(pubkey: &[u8]) -> Option<String> {
    (pubkey.len() == 33).then(|| segwit_v0("bc", &hash160(pubkey)))
}

/// Segwit wrapped in P2SH (Bitcoin Core's default "3..." addresses 0.16-0.20).
pub fn p2sh_p2wpkh(pubkey: &[u8]) -> Option<String> {
    (pubkey.len() == 33).then(|| {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&hash160(pubkey));
        let mut p = vec![0x05];
        p.extend_from_slice(&hash160(&script));
        base58check(&p)
    })
}

/// Every standard single-key address of a public key.
pub fn addresses(pubkey: &[u8]) -> Vec<String> {
    let mut v = vec![p2pkh(pubkey)];
    v.extend(p2sh_p2wpkh(pubkey));
    v.extend(p2wpkh(pubkey));
    v
}

impl Key {
    pub fn compressed(&self) -> bool {
        self.pubkey.len() == 33
    }

    /// Mainnet WIF.
    pub fn wif(&self) -> String {
        let mut p = vec![0x80];
        p.extend_from_slice(&self.secret);
        if self.compressed() {
            p.push(1);
        }
        base58check(&p)
    }

    pub fn p2pkh(&self) -> String {
        let mut p = vec![0x00];
        p.extend_from_slice(&hash160(&self.pubkey));
        base58check(&p)
    }

    /// Native segwit address (only defined for compressed keys).
    pub fn p2wpkh(&self) -> Option<String> {
        self.compressed()
            .then(|| segwit_v0("bc", &hash160(&self.pubkey)))
    }
}

/// Check that `secret` is the private key of SEC1 `pubkey`.
pub fn verify(secret: &[u8], pubkey: &[u8]) -> Option<Key> {
    let sk = SecretKey::from_slice(secret).ok()?;
    let pk = PublicKey::from_sec1_bytes(pubkey).ok()?;
    (sk.public_key() == pk).then(|| Key {
        secret: secret.try_into().unwrap(),
        pubkey: pubkey.to_vec(),
    })
}

/// Lengths of Bitcoin Core's DER private keys (compressed / uncompressed).
pub const DER_COMPRESSED: usize = 214;
pub const DER_UNCOMPRESSED: usize = 279;

/// Parse a Bitcoin Core DER private key (`ec_seckey_export_der`): the secret
/// follows `02 01 01 04 20`, the public key is the trailing BIT STRING.
/// The pair is verified with secp256k1.
pub fn parse_der(d: &[u8]) -> Option<Key> {
    let (head, tail, publen): (&[u8], &[u8], usize) =
        if d.len() >= DER_UNCOMPRESSED && d.starts_with(b"\x30\x82\x01\x13\x02\x01\x01\x04\x20") {
            (&d[..9], b"\xa1\x44\x03\x42\x00", 65)
        } else if d.len() >= DER_COMPRESSED && d.starts_with(b"\x30\x81\xd3\x02\x01\x01\x04\x20") {
            (&d[..8], b"\xa1\x24\x03\x22\x00", 33)
        } else {
            return None;
        };
    let total = if publen == 65 {
        DER_UNCOMPRESSED
    } else {
        DER_COMPRESSED
    };
    let secret = &d[head.len()..head.len() + 32];
    let pk = &d[total - publen..total];
    if &d[total - publen - tail.len()..total - publen] != tail {
        return None;
    }
    verify(secret, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    }

    #[test]
    fn key_one_vectors() {
        let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pubkey: Vec<u8> = (0..33)
            .map(|i| u8::from_str_radix(&g[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let k = verify(&one(), &pubkey).unwrap();
        assert_eq!(
            k.wif(),
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
        );
        assert_eq!(k.p2pkh(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(
            k.p2wpkh().unwrap(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        let mut wrong = pubkey.clone();
        wrong[0] = 3;
        assert!(verify(&one(), &wrong).is_none());
    }

    #[test]
    fn base58check_roundtrip() {
        let s = base58check(b"\x00hello");
        assert_eq!(base58check_decode(&s).unwrap(), b"\x00hello");
        let mut bad = s.into_bytes();
        let last = bad.len() - 1;
        bad[last] = if bad[last] == b'2' { b'3' } else { b'2' };
        assert!(base58check_decode(std::str::from_utf8(&bad).unwrap()).is_none());
    }
}
