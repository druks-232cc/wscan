# wscan

**Find lost crypto wallets on a dying or reformatted disk, while it's still being rescued, at up to 18 GiB/s.**

`wscan` scans a disk image or block device byte by byte for crypto-wallet
structures, including deleted files, stale filesystem pages and fragments
scattered across the disk. It rebuilds the wallets it finds into files you
can restore, and lists their addresses so you can check balances before
doing anything else.

> [!WARNING]
> **This project is entirely vibecoded.** Every line of code, test and
> documentation was written by an AI assistant (Claude) from prompts; no
> human has reviewed the code line by line. It has an automated test suite,
> but it has **not** been audited, and restoring its Bitcoin Core dumps has
> not yet been checked against a real Bitcoin Core (see
> `tests/fixtures/validate_with_core.sh`). Always work on a **copy** of the
> disk, keep the original image, and treat recovered keys with care.

## Ultra fast

**wscan scans faster than your disk can be read.** On an ordinary desktop
CPU it scans **up to 18 GiB/s**, roughly **a 4 TB disk in under 4 minutes**
if the disk could keep up. No single SSD or hard disk delivers data that
fast, so the scan always runs at the disk's full read speed and finishes in
about the time it takes to read the disk once.

Headroom below compares each disk's read speed with wscan's measured end to
end speed (7.8 GiB/s on one core, 18 GiB/s with `mmap` on 8 cores):

| source | read speed | wscan headroom |
|---|---|---|
| hard disk | 0.1–0.25 GiB/s | **30–80×** faster, on a single core |
| SATA SSD | ~0.5 GiB/s | **~15×** faster, on a single core |
| NVMe SSD | 3–7 GiB/s | **1–2.5×** on a single core, **2.5–6×** with `mmap` |
| **wscan, in-memory image** | **18 GiB/s** | measured (see [Benchmarks](#benchmarks)) |

### How

- **One SIMD pass for every pattern.** All wallet signatures are found at
  once with the Teddy multi-pattern search used by ripgrep. The full regex
  only runs on a small window around each candidate.
- **Every byte is read exactly once,** sequentially in large 32 MiB chunks
  (`--chunk`). Scan workers (`-j`, default min(8, CPUs)) never touch the
  disk, so hard disks and RAIDZ see a single sequential stream instead of
  random seeks.
- **Empty space costs almost nothing.** All-zero blocks are skipped at
  64 GiB/s per core.
- **Choice of I/O path:** `--io read` (default), `mmap` (fastest on cached
  or in-memory images), or `direct` (O_DIRECT, bypasses the page cache and
  falls back to `read` where unsupported). On ZFS, `read` avoids double
  caching between the ARC and the page cache.
- **Bad sectors don't stop it.** Unreadable sectors on a raw device are
  zero-filled and reported, and the scan keeps going.

### Benchmarks

Measured on a consumer desktop CPU, release build. Your numbers will
vary with hardware.

**Scan loop, one core** (`cargo bench --bench scan`, 32 MiB in-memory buffers,
anchor search + regex check, no I/O):

| data | throughput |
|---|---|
| random bytes (encrypted / compressed data) | **14.6 GiB/s** |
| text-like bytes (JSON, logs, documents) | **12.4 GiB/s** |
| all-zero blocks (skipped) | **64.1 GiB/s** |
| all-zero blocks, zero-skip off | 16.4 GiB/s |

**End to end** (`wscan IMAGE --no-recover` on a 4 GiB synthetic image from
`examples/mkimage` held in tmpfs: mixed random, zero and text blocks with
wallets planted at known offsets, best of two runs):

| `--io` | `-j 1` | `-j 4` | `-j 8` (default) | `-j 12` |
|---|---|---|---|---|
| `read` (default) | 7.8 GiB/s | 7.6 GiB/s | 7.2 GiB/s | 7.2 GiB/s |
| `mmap` | 8.0 GiB/s | 16.6 GiB/s | **18.0 GiB/s** | 17.8 GiB/s |

With `--io read` the single reader thread (copying from the page cache) is
most likely the limit, so extra workers don't help. With `mmap` the workers
read the pages themselves and the scan reaches about 18 GiB/s.

## Why wscan

- **Read-only.** It never writes to the source image or device.
- **Works alongside ddrescue.** Point it at the ddrescue mapfile and it scans
  each area as soon as it is rescued. It doesn't wait for a rescue that can
  take days.
- **Recovers as it goes.** Each wallet is rebuilt and written to disk the
  moment its surroundings have been scanned, with its addresses printed live.
- **Stop and resume at any time.** Ctrl+C saves progress, and running the
  same command again continues where it stopped.
- **Puts fragmented wallets back together.** Bitcoin Core database pages are
  parsed one by one, so a `wallet.dat` split across the disk can still be
  rebuilt.
- **Ultra fast.** 12–15 GiB/s per core, up to 18 GiB/s end to end: always
  faster than the disk (see [Ultra fast](#ultra-fast)).
- **Single static binary** (~2.6 MB, no dependencies) you can drop onto a
  rescue live USB.

## What it finds

| Wallet | Recovered as |
|---|---|
| Bitcoin Core, legacy `wallet.dat` (Berkeley DB) | `bitcoin-wallet` dump (restorable), whole file if contiguous |
| Bitcoin Core descriptor wallets (SQLite) | `bitcoin-wallet` dump (restorable), whole file if contiguous |
| Ethereum keystores (UTC/JSON) | the complete keystore JSON |
| MetaMask vaults (incl. LevelDB-escaped) | the vault JSON, ready for the vault decryptor |
| Electrum (JSON and encrypted) | the wallet file |
| blockchain.info wallets | the wallet JSON |
| BIP32 `xprv` / `yprv` / `zprv` | checksum-validated keys |
| Loose unencrypted private keys (DER) | WIF + addresses, verified with secp256k1 |

## Quick start

```
cargo build --release
./target/release/wscan disk.img                 # results go to wallet_hits/
./target/release/wscan IMAGE [-o OUTDIR] [-m MAPFILE] [options]
```

Then look at `wallet_hits/recovered/recovered.tsv` (what was rebuilt) and
`wallet_hits/recovered/addresses.tsv` (what to check the balance of).

## While ddrescue is still running

```
ddrescue -d /dev/sdX disk.img disk.map          # terminal 1
./target/release/wscan disk.img -m disk.map     # terminal 2
```

With `-m`, wscan scans only the areas ddrescue has finished (`+`). It then
keeps watching the mapfile and scans newly rescued areas as they appear. It
exits once ddrescue reports it is finished. Wallet records that straddle a
not-yet-rescued area are re-checked when that area is rescued.

- `--once` scans what is rescued now and exits.
- `--report-every MIN` rewrites the report periodically while following.
- `--max-rate MIB_S` and `--idle-io` leave disk bandwidth to ddrescue when both
  run on the same pool.
- Ctrl+C (or SIGTERM / SIGHUP) saves progress and writes a report of what was
  found so far. Running the same command again resumes, after first listing
  the wallets earlier runs found (`[=] found earlier`). Press Ctrl+C twice to
  quit immediately. Progress is checkpointed every 10 s, so at most 10 s of
  scanning is redone.

## Output (`OUTDIR`, default `wallet_hits/`)

| file | content |
|---|---|
| `recovered/` | **rebuilt wallet files**, see below (`recovered/recovered.tsv` lists everything) |
| `report.tsv` | clusters, best score first |
| `cluster_NNNN_scoreSSS_off*.bin` | carved data around each cluster |
| `match_<type>_<offset>.txt` | whole keystore / vault / xprv / Electrum matches |
| `hits.jsonl`, `state.json` | resumable progress (`--fresh` starts over) |

## Wallet recovery (`recovered/`)

Wallets are recovered **while the scan runs**: once everything around a
cluster of hits has been scanned (the cluster gap plus the 4 MiB page-sweep
margin; in follow mode, once ddrescue has rescued it), the wallet is rebuilt
and its files are written to `recovered/` immediately. Each one is announced
with the addresses to check:

```
[+] FOUND BITCOIN CORE WALLET (LEGACY, BERKELEY DB) at offset 5244416 (0.00 GiB)
      ENCRYPTED HD, 48 key(s), 6 address book entries
      -> recovered/bitcoin/wallet_bdb_off000005244416.dump
      addresses: 1Abc..., 3Def..., bc1q... (+12 more in recovered/addresses.tsv)
```

At the end, a full pass rebuilds `recovered/` from all hits. Only this pass
can merge pieces of one wallet found far apart. `--no-recover` turns
recovery off. Re-running on a finished scan redoes just this step.

`recovered/addresses.tsv` lists everything worth checking the balance of:
- Bitcoin Core address books (the addresses a wallet handed out).
- Addresses of every key record. Encrypted wallets are included, because
  public keys are not encrypted.
- Public descriptors (import them watch-only).
- Ethereum, Electrum and blockchain.info addresses.
- Addresses of loose keys.

- **Bitcoin Core** (legacy `wallet.dat` / Berkeley DB, and descriptor
  wallets / SQLite). Database pages around every Bitcoin Core hit are parsed
  one by one, so a wallet file split into pieces on disk is put back
  together. Each wallet becomes `bitcoin/wallet_NN_<bdb|sqlite>_off*.dump`,
  in the format of `bitcoin-wallet dump`. To restore one:
  ```
  bitcoin-wallet -wallet=recovered -dumpfile=wallet_01_bdb_off....dump createfromdump
  ```
  Then load the wallet in Bitcoin Core and unlock it with the original
  passphrase if it was encrypted. Legacy (bdb) dumps need Bitcoin Core
  0.21–28.x to restore; after that, `migratewallet` works on newer
  versions. When a file sits in one piece, it is also carved whole
  (`.dat` / `.sqlite`), and only after its pages have been checked to be in
  place. The notes in `recovered.tsv` give each wallet's key counts and
  whether it is encrypted, and warn about anything missing (for example, a
  lost master key or large transaction records whose fragment wasn't found).
- **Unencrypted private keys**: from wallets and from loose DER keys (deleted
  files, stale pages). Each key is checked against its public key with
  secp256k1. They are written to `keys/private_keys.tsv` with their WIF and
  addresses.
- **Ethereum keystores, MetaMask vaults** (unescaped from LevelDB),
  **Electrum** (JSON and encrypted files) and **blockchain.info** wallets:
  the complete object, validated as JSON. **xprv/yprv/zprv** keys are kept
  only when their checksum is valid.

Limits: data on sectors ddrescue could not read is gone. A split SQLite
wallet keeps all its keys and descriptors, but large transaction records
whose continuation sits in a fragment that wasn't found are dropped rather
than guessed. A fragment far (> 4 MiB) from any key record is not searched.

## Static binary

```
cargo build --profile dist --target x86_64-unknown-linux-musl   # ~2.6 MB, no dependencies
```

## Development

```
cargo test                      # unit + end-to-end (incl. follow mode)
cargo bench --bench scan        # per-core scan throughput
cargo run --release --example mkimage -- test.img 4096   # synthetic image + test.img.expected
python3 tests/fixtures/mkwallets.py tests/fixtures      # regenerate the test wallets
tests/fixtures/validate_with_core.sh ~/bitcoin-28.1/bin # restore check with real Bitcoin Core
```

The test wallets in `tests/fixtures` are generated by `mkwallets.py` in
Bitcoin Core's formats: real SQLite files, BDB 4.8-layout btree files, real
secp256k1 keys. `validate_with_core.sh` closes the loop with a real Bitcoin
Core 28.x. It creates wallets, plants them in an image (some split into
fragments), runs wscan, restores every dump with `createfromdump`, and checks
that the keys are identical.

## License

MIT. See [LICENSE](LICENSE).
