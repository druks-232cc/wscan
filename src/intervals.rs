//! Sorted, merged sets of half-open byte ranges `[start, end)`.

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntervalSet {
    v: Vec<(u64, u64)>,
}

impl IntervalSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_unsorted(mut iv: Vec<(u64, u64)>) -> Self {
        iv.retain(|&(s, e)| s < e);
        iv.sort_unstable();
        let mut v: Vec<(u64, u64)> = Vec::with_capacity(iv.len());
        for (s, e) in iv {
            match v.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => v.push((s, e)),
            }
        }
        IntervalSet { v }
    }

    pub fn as_slice(&self) -> &[(u64, u64)] {
        &self.v
    }

    pub fn is_empty(&self) -> bool {
        self.v.is_empty()
    }

    pub fn total(&self) -> u64 {
        self.v.iter().map(|(s, e)| e - s).sum()
    }

    pub fn insert(&mut self, s: u64, e: u64) {
        if s >= e {
            return;
        }
        // First interval that ends at or after s, last that starts at or before e.
        let i = self.v.partition_point(|&(_, ie)| ie < s);
        let j = self.v.partition_point(|&(is, _)| is <= e);
        if i == j {
            self.v.insert(i, (s, e));
        } else {
            let ns = s.min(self.v[i].0);
            let ne = e.max(self.v[j - 1].1);
            self.v.splice(i..j, [(ns, ne)]);
        }
    }

    /// Parts of `self` not covered by `other`.
    pub fn subtract(&self, other: &IntervalSet) -> IntervalSet {
        let b = &other.v;
        let mut out = Vec::new();
        let mut j = 0;
        for &(mut s, e) in &self.v {
            while j < b.len() && b[j].1 <= s {
                j += 1;
            }
            let mut k = j;
            while k < b.len() && b[k].0 < e {
                if b[k].0 > s {
                    out.push((s, b[k].0));
                }
                s = s.max(b[k].1);
                k += 1;
            }
            if s < e {
                out.push((s, e));
            }
        }
        IntervalSet { v: out }
    }

    /// Clip every interval to `[0, limit)`.
    pub fn clamp(&self, limit: u64) -> IntervalSet {
        IntervalSet::from_unsorted(self.v.iter().map(|&(s, e)| (s, e.min(limit))).collect())
    }

    /// True if `[s, e)` lies entirely inside one interval.
    pub fn covers(&self, s: u64, e: u64) -> bool {
        let i = self.v.partition_point(|&(is, _)| is <= s);
        i > 0 && self.v[i - 1].1 >= e
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_and_insert() {
        let mut a = IntervalSet::from_unsorted(vec![(10, 20), (0, 5), (5, 7), (30, 40)]);
        assert_eq!(a.as_slice(), &[(0, 7), (10, 20), (30, 40)]);
        a.insert(18, 31);
        assert_eq!(a.as_slice(), &[(0, 7), (10, 40)]);
        a.insert(7, 10);
        assert_eq!(a.as_slice(), &[(0, 40)]);
        a.insert(50, 60);
        a.insert(45, 46);
        assert_eq!(a.as_slice(), &[(0, 40), (45, 46), (50, 60)]);
        assert_eq!(a.total(), 51);
    }

    #[test]
    fn subtract_and_covers() {
        let a = IntervalSet::from_unsorted(vec![(0, 100), (200, 300)]);
        let b = IntervalSet::from_unsorted(vec![(10, 20), (90, 210), (250, 260)]);
        assert_eq!(
            a.subtract(&b).as_slice(),
            &[(0, 10), (20, 90), (210, 250), (260, 300)]
        );
        assert!(a.covers(0, 100));
        assert!(!a.covers(50, 101));
        assert!(a.covers(200, 200));
        assert!(!a.covers(150, 160));
        assert_eq!(a.clamp(250).as_slice(), &[(0, 100), (200, 250)]);
    }
}
