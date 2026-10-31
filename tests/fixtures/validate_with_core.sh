#!/usr/bin/env bash
# Validate wscan's wallet recovery against a real Bitcoin Core (28.x: the
# last series that can still create legacy Berkeley DB wallets).
#
#   tests/fixtures/validate_with_core.sh /path/to/bitcoin-28.1/bin [path/to/wscan]
#
# 1. bitcoind (regtest, offline, throwaway datadir) creates four wallets:
#    legacy/descriptor x unencrypted/encrypted, with some history.
# 2. Their wallet.dat files are planted in a disk image, two of them split
#    into out-of-order fragments.
# 3. wscan scans the image; every recovered .dump is restored with
#    `bitcoin-wallet createfromdump`, loaded, unlocked if encrypted, and its
#    private keys compared with the original wallet's.
set -euo pipefail
BIN=${1:?usage: $0 <bitcoin-core-bin-dir> [wscan]}
WSCAN=${2:-$(cd "$(dirname "$0")/../.." && pwd)/target/release/wscan}
D=$(mktemp -d)
trap '"$BIN/bitcoin-cli" -regtest -datadir="$D/node" -rpcport=18999 stop >/dev/null 2>&1 || true; sleep 2; rm -rf "$D"' EXIT
mkdir -p "$D/node"
PASS=correct-horse-battery
cli() { "$BIN/bitcoin-cli" -regtest -datadir="$D/node" -rpcport=18999 "$@"; }
start() {
  "$BIN/bitcoind" -regtest -datadir="$D/node" -daemon -listen=0 -rpcport=18999 -keypool=20 \
    -deprecatedrpc=create_bdb -fallbackfee=0.0001 >/dev/null
  cli -rpcwait getblockchaininfo >/dev/null
}
stop() { cli stop >/dev/null; while cli getblockchaininfo >/dev/null 2>&1; do sleep 0.5; done; }

# Private keys of a loaded wallet, normalized: legacy -> WIFs, descriptor -> xprv/tprv strings.
keys() {
  local w=$1 enc=$2
  [ "$enc" = 1 ] && cli -rpcwallet="$w" walletpassphrase $PASS 60
  if [ "$(cli -rpcwallet="$w" getwalletinfo | grep -c '"descriptors": true')" = 1 ]; then
    cli -rpcwallet="$w" listdescriptors true | grep -oE '[tx]prv[1-9A-HJ-NP-Za-km-z]+' | sort -u
  else
    rm -f "$D/k.txt"
    cli -rpcwallet="$w" dumpwallet "$D/k.txt" >/dev/null
    grep -oE '^c[1-9A-HJ-NP-Za-km-z]{51} ' "$D/k.txt" | sort -u
  fi
}

echo "[*] creating wallets"
start
declare -A ENC=([legacy_plain]=0 [legacy_enc]=1 [desc_plain]=0 [desc_enc]=1)
for w in legacy_plain legacy_enc desc_plain desc_enc; do
  desc=true; [[ $w == legacy* ]] && desc=false
  pass=(); [ "${ENC[$w]}" = 1 ] && pass=(passphrase=$PASS)
  cli -named createwallet wallet_name=$w descriptors=$desc "${pass[@]}" >/dev/null
  for i in 1 2 3; do cli -rpcwallet=$w getnewaddress "label$i" >/dev/null; done
  cli generatetoaddress 2 "$(cli -rpcwallet=$w getnewaddress)" >/dev/null
  keys $w "${ENC[$w]}" > "$D/$w.orig.keys"
  echo "    $w: $(wc -l < "$D/$w.orig.keys") private keys"
done
for w in "${!ENC[@]}"; do cli unloadwallet $w >/dev/null; done
stop

echo "[*] building the disk image"
python3 -I - "$D" <<'EOF'
import os, random, sys
d = sys.argv[1]
rnd = random.Random(1)
img = bytearray(rnd.randbytes(96 << 20))
def wallet(n): return open(f"{d}/node/regtest/wallets/{n}/wallet.dat", "rb").read()
def put(off, b): img[off:off + len(b)] = b
put((5 << 20) + 1536, wallet("legacy_enc"))                 # whole, sector-aligned
w = wallet("legacy_plain"); cut = len(w) // 4096 // 2 * 4096 # split, second half first
put(20 << 20, w[:cut]); put((20 << 20) - cut - 512 * 7, w[cut:])
put(40 << 20, wallet("desc_enc"))                            # whole
w = wallet("desc_plain"); cut = len(w) // 4096 // 2 * 4096   # split
put(60 << 20, w[:cut]); put((62 << 20) + 1024, w[cut:])
open(f"{d}/disk.img", "wb").write(img)
EOF

echo "[*] scanning with wscan"
"$WSCAN" "$D/disk.img" -o "$D/out" | sed -n '/Recovered/,$p'

echo "[*] restoring every recovered dump with bitcoin-wallet createfromdump"
start
fail=0
for dump in "$D"/out/recovered/bitcoin/*.dump; do
  n=$(basename "$dump" .dump)
  if ! "$BIN/bitcoin-wallet" -regtest -datadir="$D/node" -wallet="r_$n" -dumpfile="$dump" createfromdump >"$D/$n.log" 2>&1; then
    echo "    FAIL $n: createfromdump: $(tail -1 "$D/$n.log")"; fail=1; continue
  fi
  cli loadwallet "r_$n" >/dev/null
  enc=0; cli -rpcwallet="r_$n" getwalletinfo | grep -q unlocked_until && enc=1
  keys "r_$n" $enc > "$D/$n.keys" || true
  match=""
  for w in "${!ENC[@]}"; do cmp -s "$D/$w.orig.keys" "$D/$n.keys" && match=$w; done
  if [ -n "$match" ]; then
    echo "    OK   $n == $match ($(wc -l < "$D/$n.keys") keys, encrypted=$enc)"
  else
    echo "    FAIL $n: keys differ from every original wallet"; fail=1
  fi
done
stop
[ $fail = 0 ] && echo "[+] all recovered wallets restored by Bitcoin Core with identical keys" || { echo "[!] failures above"; exit 1; }
