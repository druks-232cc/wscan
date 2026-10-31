//! Per-core throughput of the hot loop (prefilter + verification) on
//! in-memory buffers, independent of disk speed.

use std::fs::File;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use wscan::{
    intervals::IntervalSet,
    patterns::Patterns,
    scan::{Scanner, Source},
};

fn buffers() -> Vec<(&'static str, Vec<u8>)> {
    let n = 32 << 20;
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut random = vec![0u8; n];
    for b in random.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let text: &[u8] = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJ 0123456789 {}[]:,\"\n";
    let json = random
        .iter()
        .map(|&b| text[b as usize % text.len()])
        .collect();
    vec![("random", random), ("text", json), ("zero", vec![0u8; n])]
}

fn bench(c: &mut Criterion) {
    let devnull = File::open("/dev/null").unwrap();
    let mut g = c.benchmark_group("scan");
    for zero_skip in [true, false] {
        let sc = Scanner::new(Patterns::new(), 8 << 20, zero_skip);
        let mut w = sc.worker();
        for (name, data) in buffers() {
            let rescued = IntervalSet::from_unsorted(vec![(0, data.len() as u64)]);
            let src = Source {
                file: &devnull,
                size: data.len() as u64,
                rescued: &rescued,
            };
            g.throughput(Throughput::Bytes(data.len() as u64));
            g.bench_function(format!("{name}/zero_skip={zero_skip}"), |b| {
                b.iter(|| {
                    sc.scan(&mut w, &src, &data, 0, 0, data.len() as u64);
                    w.hits.clear();
                })
            });
        }
    }
    g.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench
}
criterion_main!(benches);
