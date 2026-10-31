//! Synthetic disk image for tests and benchmarks: a mix of random, zero and
//! text-like 1 MiB blocks with wallet samples planted at known offsets
//! (including right across 32 MiB chunk boundaries).
//!
//!   cargo run --release --example mkimage -- IMAGE SIZE_MIB [SAMPLES]
//!
//! Writes the expected `offset name` list to IMAGE.expected.

use std::{
    fs::File,
    io::{BufWriter, Seek, SeekFrom, Write},
};

use wscan::patterns::samples;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, b: &mut [u8]) {
        for c in b.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: mkimage IMAGE SIZE_MIB [SAMPLES]");
        std::process::exit(2);
    }
    let size = args[2].parse::<u64>().expect("SIZE_MIB") << 20;
    let nsamples: usize = args.get(3).map_or(200, |s| s.parse().expect("SAMPLES"));
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);

    let mut f = BufWriter::with_capacity(8 << 20, File::create(&args[1])?);
    let text: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n\t{}[]:,\"'.-_/=+";
    let mut block = vec![0u8; 1 << 20];
    for i in 0..(size >> 20) {
        match i % 10 {
            0..=3 => rng.fill(&mut block),
            4..=6 => block.fill(0),
            _ => {
                rng.fill(&mut block);
                for b in block.iter_mut() {
                    *b = text[*b as usize % text.len()];
                }
            }
        }
        f.write_all(&block)?;
    }
    let mut f = f.into_inner()?;

    let all = samples::all();
    let mut expected = Vec::new();
    let chunk = 32u64 << 20;
    for k in 0..nsamples {
        let (name, data, rel) = &all[k % all.len()];
        let len = data.len() as u64;
        // Every third sample straddles a chunk boundary, the rest are spread out.
        let off = if k % 3 == 0 {
            let b = chunk * (1 + rng.next() % (size / chunk).max(1));
            b.saturating_sub(1 + rng.next() % len)
        } else {
            rng.next() % size
        };
        let off = off.min(size - len);
        // Keep samples from overlapping each other.
        if expected
            .iter()
            .any(|&(o, l, _)| off < o + l + 64 && o < off + len + 64)
        {
            continue;
        }
        f.seek(SeekFrom::Start(off))?;
        f.write_all(data)?;
        expected.push((off, len, (off + *rel as u64, *name)));
    }
    let mut e = BufWriter::new(File::create(format!("{}.expected", args[1]))?);
    expected.sort();
    for (_, _, (o, n)) in &expected {
        writeln!(e, "{o} {n}")?;
    }
    eprintln!("wrote {} MiB with {} samples", size >> 20, expected.len());
    Ok(())
}
