#!/usr/bin/env python3
"""Generate Bitcoin Core-format test wallets (worthless, deterministic).

  python3 tests/fixtures/mkwallets.py tests/fixtures

For each wallet NAME it writes:
  NAME.wallet    the wallet file: Berkeley DB btree (legacy_*) or SQLite (desc_*)
  NAME.records   its records, "hexkey,hexvalue" per line, sorted: what a
                 `bitcoin-wallet dump` of it contains (minus header/checksum)
  NAME.keys      hex private keys stored unencrypted in it, sorted
and secret1.der.hex, a lone DER private key (secret 1).

Records use Bitcoin Core's serialization (wallet/walletdb.cpp); keys are real
secp256k1 keys in Core's DER format with the key-integrity hash. The BDB file
follows the BDB 4.8 on-disk layout Core uses: outer btree holding "main",
subdatabase btree with the records, overflow pages for large values.
"""
import hashlib
import random
import sqlite3
import struct
import sys
from pathlib import Path

# ---- secp256k1 -----------------------------------------------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (l * l - a[0] - b[0]) % P
    return x, (l * (a[0] - x) - a[1]) % P


def pubkey(secret, compressed=True):
    r, q, k = None, G, secret
    while k:
        if k & 1:
            r = add(r, q)
        q, k = add(q, q), k >> 1
    if compressed:
        return bytes([2 + (r[1] & 1)]) + r[0].to_bytes(32, "big")
    return b"\x04" + r[0].to_bytes(32, "big") + r[1].to_bytes(32, "big")


# ---- DER private key, as Bitcoin Core's ec_seckey_export_der ---------------
def der(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82]) + n.to_bytes(2, "big")
    return bytes([tag]) + ln + body


def der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")
    return der(0x02, b)


def privkey_der(secret, compressed=True):
    pub = pubkey(secret, compressed)
    gpt = pubkey(1, compressed)
    params = der(0x30, der_int(1)
                 + der(0x30, der(0x06, bytes.fromhex("2a8648ce3d0101")) + der_int(P))
                 + der(0x30, der(0x04, b"\x00") + der(0x04, b"\x07"))
                 + der(0x04, gpt) + der_int(N) + der_int(1))
    out = der(0x30, der_int(1) + der(0x04, secret.to_bytes(32, "big"))
              + der(0xA0, params) + der(0xA1, der(0x03, b"\x00" + pub)))
    assert len(out) == (214 if compressed else 279), len(out)
    return out


# ---- Bitcoin serialization --------------------------------------------------
def cs(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def vec(b):
    return cs(len(b)) + b


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def u32(v):
    return struct.pack("<I", v)


def i64(v):
    return struct.pack("<q", v)


def key_record(prefix, pub, secret, compressed):
    d = privkey_der(secret, compressed)
    return prefix + vec(pub), vec(d) + sha256d(pub + d)


def legacy_wallet(rng, encrypted):
    recs, keys = {}, []
    recs[vec(b"version")] = u32(169900)
    recs[vec(b"minversion")] = u32(159900)
    recs[vec(b"orderposnext")] = i64(7)
    recs[vec(b"bestblock")] = u32(169900) + vec(b"")
    recs[vec(b"bestblock_nomerkle")] = u32(169900) + vec(rng.randbytes(32))
    if encrypted:
        recs[vec(b"mkey") + u32(1)] = vec(rng.randbytes(48)) + vec(rng.randbytes(8)) + u32(0) + u32(181433) + vec(b"")
    pubs = []
    for i in range(48):
        secret = rng.randrange(1, N)
        compressed = i % 7 != 3          # a few old-style uncompressed keys
        pub = pubkey(secret, compressed)
        pubs.append(pub)
        if encrypted:
            recs[vec(b"ckey") + vec(pub)] = vec(rng.randbytes(48))
        else:
            k, v = key_record(vec(b"key"), pub, secret, compressed)
            recs[k] = v
            keys.append(secret)
        recs[vec(b"keymeta") + vec(pub)] = struct.pack("<iq", 12, 1700000000 + i) + vec(f"m/0'/0'/{i}'".encode()) + rng.randbytes(20) + rng.randbytes(8)
        if i < 20:
            recs[vec(b"pool") + i64(i)] = struct.pack("<iq", 169900, 1700000000) + vec(pub) + b"\x00\x00"
    recs[vec(b"hdchain")] = struct.pack("<iI", 2, 30) + hash160(pubs[0]) + u32(18)
    recs[vec(b"defaultkey")] = vec(pubs[1])
    for i in range(6):
        addr = f"1Label{i}{rng.randbytes(12).hex()}".encode()
        recs[vec(b"name") + vec(addr)] = vec(f"label {i}".encode())
        recs[vec(b"purpose") + vec(addr)] = vec(b"receive")
    for i in range(24):
        # Some transactions are larger than a page and land in overflow pages.
        size = rng.choice([180, 250, 400, 900, 2500, 9000])
        recs[vec(b"tx") + rng.randbytes(32)] = rng.randbytes(size)
    return recs, keys


def desc_wallet(rng, encrypted):
    recs, keys = {}, []
    recs[vec(b"version")] = u32(280100)
    recs[vec(b"minversion")] = u32(229900)
    recs[vec(b"flags")] = struct.pack("<Q", (1 << 34) | (1 << 2))   # DESCRIPTORS | KEY_ORIGIN_METADATA
    recs[vec(b"bestblock_nomerkle")] = u32(280100) + vec(rng.randbytes(32))
    recs[vec(b"orderposnext")] = i64(3)
    if encrypted:
        recs[vec(b"mkey") + u32(1)] = vec(rng.randbytes(48)) + vec(rng.randbytes(8)) + u32(0) + u32(201325) + vec(b"")
    for t, kind in enumerate(["pkh", "sh(wpkh", "wpkh", "tr"]):
        for internal in (0, 1):
            secret = rng.randrange(1, N)
            pub = pubkey(secret)
            desc = f"{kind}([{rng.randbytes(4).hex()}/84h/1h/0h]tpubD6NzVbkrYhZ4X{rng.randbytes(40).hex()}/{internal}/*){')' if '(' in kind[3:] else ''}#{rng.randbytes(4).hex()}"
            did = hashlib.sha256(desc.encode()).digest()
            recs[vec(b"walletdescriptor") + did] = vec(desc.encode()) + i64(1700000000) + struct.pack("<iii", 0, 1000, 5)
            if encrypted:
                recs[vec(b"walletdescriptorckey") + did + vec(pub)] = vec(rng.randbytes(48))
            else:
                k, v = key_record(vec(b"walletdescriptorkey") + did, pub, secret, True)
                recs[k] = v
                keys.append(secret)
            for i in range(6):
                recs[vec(b"walletdescriptorcache") + did + u32(i)] = vec(rng.randbytes(78))
            recs[vec(b"activeinternalspk" if internal else b"activeexternalspk") + bytes([t])] = did
    for i in range(16):
        size = rng.choice([200, 350, 800, 3000, 7000])
        recs[vec(b"tx") + rng.randbytes(32)] = rng.randbytes(size)
    return recs, keys


# ---- Berkeley DB btree writer ----------------------------------------------
PS = 4096
P_IBTREE, P_LBTREE, P_OVERFLOW, P_BTREEMETA = 3, 5, 7, 9
OVFL = 1000          # values longer than this go to overflow pages


class Bdb:
    def __init__(self, rng):
        self.pages, self.rng, self.lsn = {}, rng, 0

    def header(self, pgno, prev, nxt, entries, hf, level, ptype):
        self.lsn += 1
        return struct.pack("<IIIIIHHBB", 1, 1000 * self.lsn, pgno, prev, nxt, entries, hf, level, ptype)

    def meta(self, pgno, last, root, nkeys, flags):
        m = self.header(pgno, 0, 0, 0, 0, 0, 0)[:12]
        m += struct.pack("<III", 0x053162, 9, PS) + bytes([0, P_BTREEMETA, 0, 0])
        m += struct.pack("<IIIIII", 0, last, 0, nkeys, nkeys, flags) + self.rng.randbytes(20)
        m += struct.pack("<IIIII", 0, 2, 0, 0x20, root)
        return m.ljust(PS, b"\0")

    def page(self, pgno, items, level, ptype, prev=0, nxt=0):
        body, offs, end = [], [], PS
        for it in items:
            sz = (len(it) + 3) & ~3
            end -= sz
            offs.append(end)
            body.append((end, it))
        assert 26 + 2 * len(items) <= end, "page overflow"
        p = bytearray(PS)
        p[:26] = self.header(pgno, prev, nxt, len(items), end, level, ptype)
        p[26:26 + 2 * len(items)] = b"".join(struct.pack("<H", o) for o in offs)
        for o, it in body:
            p[o:o + len(it)] = it
        return bytes(p)

    def overflow(self, first, data):
        per = PS - 26
        chunks = [data[i:i + per] for i in range(0, len(data), per)]
        for i, c in enumerate(chunks):
            pg = first + i
            p = bytearray(PS)
            p[:26] = self.header(pg, pg - 1 if i else 0, pg + 1 if i + 1 < len(chunks) else 0, 1, len(c), 0, P_OVERFLOW)
            p[26:26 + len(c)] = c
            self.pages[pg] = bytes(p)
        return len(chunks)


def kd(b):
    return struct.pack("<HB", len(b), 1) + b


def write_bdb(path, recs, rng):
    db = Bdb(rng)
    # Page 0 outer meta, 1 outer leaf ("main" -> 2), 2 subdb meta, 3 subdb root.
    nxt = 4
    leaves, cur, used = [], [], 26
    big = {}
    for k in sorted(recs):
        v = recs[k]
        if len(v) > OVFL:
            big[k] = nxt
            nxt += db.overflow(nxt, v)
            item = struct.pack("<HBBII", 0, 3, 0, big[k], len(v))
        else:
            item = kd(v)
        need = 4 + ((len(kd(k)) + 3) & ~3) + ((len(item) + 3) & ~3)
        if used + need > PS:
            leaves.append(cur)
            cur, used = [], 26
        cur += [kd(k), item]
        used += need
    leaves.append(cur)
    first_leaf = nxt
    for i, items in enumerate(leaves):
        pg = first_leaf + i
        db.pages[pg] = db.page(pg, items, 1, P_LBTREE,
                               pg - 1 if i else 0, pg + 1 if i + 1 < len(leaves) else 0)
    last = first_leaf + len(leaves) - 1
    # Root internal page: first key empty, then each leaf's first key.
    internal = []
    for i, items in enumerate(leaves):
        key = b"" if i == 0 else items[0][3:]
        internal.append(struct.pack("<HBBII", len(key), 1, 0, first_leaf + i, len(items) // 2) + key)
    db.pages[3] = db.page(3, internal, 2, P_IBTREE)
    db.pages[2] = db.meta(2, 0, 3, len(recs), 0)
    db.pages[1] = db.page(1, [kd(b"main"), kd(struct.pack(">I", 2))], 1, P_LBTREE)
    db.pages[0] = db.meta(0, last, 1, 1, 0x20)
    Path(path).write_bytes(b"".join(db.pages[i] for i in range(last + 1)))


def write_sqlite(path, recs):
    Path(path).unlink(missing_ok=True)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size = 4096")
    # Core stores the network magic; mainnet f9beb4d9 (a signed int32 for SQLite).
    con.execute(f"PRAGMA application_id = {0xf9beb4d9 - (1 << 32)}")
    con.execute("PRAGMA user_version = 0")
    con.execute("CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)")
    # Insertion order as Core would write: arbitrary; shuffle deterministically.
    items = sorted(recs.items())
    random.Random(7).shuffle(items)
    con.executemany("INSERT INTO main VALUES (?, ?)", items)
    con.commit()
    got = dict(con.execute("SELECT key, value FROM main"))
    assert got == recs
    con.close()


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    for name, maker, enc in [("legacy_plain", legacy_wallet, False), ("legacy_enc", legacy_wallet, True),
                             ("desc_plain", desc_wallet, False), ("desc_enc", desc_wallet, True)]:
        rng = random.Random(name)
        recs, keys = maker(rng, enc)
        w = out / f"{name}.wallet"
        if name.startswith("legacy"):
            write_bdb(w, recs, rng)
        else:
            write_sqlite(w, recs)
        (out / f"{name}.records").write_text("".join(f"{k.hex()},{v.hex()}\n" for k, v in sorted(recs.items())))
        (out / f"{name}.keys").write_text("".join(f"{s:064x}\n" for s in sorted(keys)))
        print(f"{name}: {len(recs)} records, {len(keys)} plain keys, {w.stat().st_size} bytes")
    # A lone DER private key (secret 1) as left behind by a deleted file.
    (out / "secret1.der.hex").write_text(privkey_der(1).hex() + "\n")


if __name__ == "__main__":
    main()
