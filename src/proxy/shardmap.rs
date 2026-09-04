//! A sharded concurrent hash map — the proxy's replacement for `dashmap`.
//!
//! The data path keeps six of these (sessions, per-client metrics, protocol
//! pins, SIP dialogs, DNS echo state, relay handles) and touches them on every
//! datagram, so the shape that matters is: a read that takes a shard lock and
//! nothing more, and an `entry` that makes "check, reserve, insert" one atomic
//! step. That is all `dashmap` was providing, and it is ~200 lines over
//! `parking_lot::RwLock` + `std::collections::HashMap`.
//!
//! Design notes:
//!
//! * **Shard count** is `available_parallelism * 4`, rounded to a power of two
//!   and clamped to `[16, 256]` — the same heuristic `dashmap` uses, so
//!   contention behaviour under load is unchanged.
//! * **`parking_lot` locks**, not `std`: no poisoning (a panic in one handler
//!   must not permanently disable the proxy's session table) and mapped guards,
//!   which let [`get`](ShardMap::get) hand out a `&V` without cloning the value
//!   or re-hashing the key on every deref. `parking_lot` is already compiled
//!   in — `tokio` depends on it — so this adds no crate.
//! * **Iteration** is expressed as [`for_each`](ShardMap::for_each) /
//!   [`find_map`](ShardMap::find_map) / [`map_collect`](ShardMap::map_collect)
//!   rather than a lending `Iterator`. Each locks one shard at a time, and the
//!   closure form makes the lock scope obvious at the call site — a plain
//!   iterator that hands out guards is exactly how cross-shard deadlocks get
//!   written by accident.
//!
//! Callers must not re-enter the same map from inside one of those closures
//! (or while holding a `Ref`/`RefMut`): the shard lock is not reentrant.

use std::borrow::Borrow;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};

use parking_lot::{
    MappedRwLockReadGuard, MappedRwLockWriteGuard, RwLock, RwLockReadGuard, RwLockWriteGuard,
};

/// Shared reference to a value, holding its shard's read lock.
pub type Ref<'a, V> = MappedRwLockReadGuard<'a, V>;
/// Exclusive reference to a value, holding its shard's write lock.
pub type RefMut<'a, V> = MappedRwLockWriteGuard<'a, V>;

fn shard_count() -> usize {
    let par = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (par * 4).next_power_of_two().clamp(16, 256)
}

/// A hash map split across independently locked shards.
pub struct ShardMap<K, V> {
    shards: Box<[RwLock<HashMap<K, V, RandomState>>]>,
    hasher: RandomState,
    mask: usize,
}

impl<K: Hash + Eq, V> Default for ShardMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Hash + Eq, V> ShardMap<K, V> {
    /// Create an empty map.
    pub fn new() -> Self {
        let n = shard_count();
        let hasher = RandomState::new();
        let shards = (0..n)
            .map(|_| RwLock::new(HashMap::with_hasher(hasher.clone())))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            hasher,
            mask: n - 1,
        }
    }

    /// Which shard owns `key`.
    ///
    /// The high bits of the hash pick the shard; `HashMap` consumes the low
    /// bits for its own bucket index, so taking from opposite ends keeps the
    /// two distributions independent.
    #[inline]
    fn shard_for<Q>(&self, key: &Q) -> &RwLock<HashMap<K, V, RandomState>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let h = self.hasher.hash_one(key);
        &self.shards[((h >> 32) as usize) & self.mask]
    }

    /// Read a value, holding its shard's read lock for the guard's lifetime.
    pub fn get<Q>(&self, key: &Q) -> Option<Ref<'_, V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let guard = self.shard_for(key).read();
        RwLockReadGuard::try_map(guard, |m| m.get(key)).ok()
    }

    /// Mutate a value in place, holding its shard's write lock.
    pub fn get_mut<Q>(&self, key: &Q) -> Option<RefMut<'_, V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let guard = self.shard_for(key).write();
        RwLockWriteGuard::try_map(guard, |m| m.get_mut(key)).ok()
    }

    /// Insert a value, returning the previous one if the key was present.
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.shard_for(&key).write().insert(key, value)
    }

    /// Remove a key, returning the `(key, value)` pair if it was present.
    pub fn remove<Q>(&self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard_for(key).write().remove_entry(key)
    }

    /// Remove a key only if the predicate accepts the current value. The check
    /// and the removal happen under one write lock, so nothing can slip in
    /// between them.
    pub fn remove_if<Q>(&self, key: &Q, predicate: impl FnOnce(&K, &V) -> bool) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut shard = self.shard_for(key).write();
        let (k, v) = shard.get_key_value(key)?;
        if !predicate(k, v) {
            return None;
        }
        shard.remove_entry(key)
    }

    /// Whether the map holds `key`.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.shard_for(key).read().contains_key(key)
    }

    /// Total number of entries across all shards.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().len()).sum()
    }

    /// Whether every shard is empty.
    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.read().is_empty())
    }

    /// Drop every entry.
    pub fn clear(&self) {
        for shard in self.shards.iter() {
            shard.write().clear();
        }
    }

    /// Keep only the entries the predicate accepts, one shard at a time.
    pub fn retain(&self, mut f: impl FnMut(&K, &mut V) -> bool) {
        for shard in self.shards.iter() {
            shard.write().retain(|k, v| f(k, v));
        }
    }

    /// Visit every entry under a shared lock.
    pub fn for_each(&self, mut f: impl FnMut(&K, &V)) {
        for shard in self.shards.iter() {
            for (k, v) in shard.read().iter() {
                f(k, v);
            }
        }
    }

    /// Return the first non-`None` result of `f`, stopping the walk there.
    pub fn find_map<R>(&self, mut f: impl FnMut(&K, &V) -> Option<R>) -> Option<R> {
        for shard in self.shards.iter() {
            let guard = shard.read();
            for (k, v) in guard.iter() {
                if let Some(r) = f(k, v) {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Map every entry into a `Vec`.
    pub fn map_collect<R>(&self, mut f: impl FnMut(&K, &V) -> R) -> Vec<R> {
        let mut out = Vec::with_capacity(self.len());
        self.for_each(|k, v| out.push(f(k, v)));
        out
    }

    /// Get the entry for `key`, holding its shard's write lock so a caller can
    /// check for vacancy and insert without another task racing in between.
    pub fn entry(&self, key: K) -> Entry<'_, K, V> {
        let shard = self.shard_for(&key).write();
        if shard.contains_key(&key) {
            Entry::Occupied(OccupiedEntry { shard, key })
        } else {
            Entry::Vacant(VacantEntry { shard, key })
        }
    }
}

/// A map entry, holding its shard's write lock.
pub enum Entry<'a, K, V> {
    /// The key is present.
    Occupied(OccupiedEntry<'a, K, V>),
    /// The key is absent.
    Vacant(VacantEntry<'a, K, V>),
}

/// An entry whose key is present in the map.
pub struct OccupiedEntry<'a, K, V> {
    shard: RwLockWriteGuard<'a, HashMap<K, V, RandomState>>,
    key: K,
}

impl<K: Hash + Eq, V> OccupiedEntry<'_, K, V> {
    /// The current value.
    pub fn get(&self) -> &V {
        // Constructed only after `contains_key`, under a write lock that has
        // not been released since.
        self.shard.get(&self.key).expect("occupied entry is present")
    }

    /// The current value, mutably.
    pub fn get_mut(&mut self) -> &mut V {
        self.shard
            .get_mut(&self.key)
            .expect("occupied entry is present")
    }
}

/// An entry whose key is absent from the map.
pub struct VacantEntry<'a, K, V> {
    shard: RwLockWriteGuard<'a, HashMap<K, V, RandomState>>,
    key: K,
}

impl<K: Hash + Eq, V> VacantEntry<'_, K, V> {
    /// Insert a value for this key.
    pub fn insert(mut self, value: V) {
        self.shard.insert(self.key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn addr(n: u16) -> SocketAddr {
        format!("127.0.0.1:{n}").parse().unwrap()
    }

    #[test]
    fn insert_get_remove_round_trip() {
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        assert!(m.is_empty());
        assert_eq!(m.insert(addr(1), 10), None);
        assert_eq!(m.insert(addr(1), 11), Some(10), "insert returns the old value");
        assert_eq!(*m.get(&addr(1)).unwrap(), 11);
        assert!(m.contains_key(&addr(1)));
        assert_eq!(m.len(), 1);
        assert_eq!(m.remove(&addr(1)), Some((addr(1), 11)));
        assert!(m.get(&addr(1)).is_none());
        assert!(m.is_empty());
    }

    #[test]
    fn get_mut_writes_through() {
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        m.insert(addr(2), 1);
        *m.get_mut(&addr(2)).unwrap() += 41;
        assert_eq!(*m.get(&addr(2)).unwrap(), 42);
        assert!(m.get_mut(&addr(999)).is_none());
    }

    #[test]
    fn remove_if_respects_the_predicate() {
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        m.insert(addr(3), 7);
        assert_eq!(m.remove_if(&addr(3), |_, v| *v == 8), None, "predicate rejected");
        assert!(m.contains_key(&addr(3)));
        assert_eq!(m.remove_if(&addr(3), |_, v| *v == 7), Some((addr(3), 7)));
        assert!(!m.contains_key(&addr(3)));
        assert_eq!(m.remove_if(&addr(3), |_, _| true), None, "absent key");
    }

    #[test]
    fn entry_distinguishes_occupied_from_vacant() {
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        match m.entry(addr(4)) {
            Entry::Vacant(v) => v.insert(100),
            Entry::Occupied(_) => panic!("fresh key must be vacant"),
        }
        match m.entry(addr(4)) {
            Entry::Occupied(mut o) => {
                assert_eq!(*o.get(), 100);
                *o.get_mut() = 101;
            }
            Entry::Vacant(_) => panic!("key was just inserted"),
        }
        assert_eq!(*m.get(&addr(4)).unwrap(), 101);
    }

    #[test]
    fn retain_drops_only_rejected_entries() {
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        for i in 0..100u16 {
            m.insert(addr(i + 1), i as u32);
        }
        assert_eq!(m.len(), 100);
        m.retain(|_, v| *v % 2 == 0);
        assert_eq!(m.len(), 50);
        assert!(m.contains_key(&addr(1)), "value 0 is even");
        assert!(!m.contains_key(&addr(2)), "value 1 is odd");
    }

    #[test]
    fn retain_can_mutate_and_observe_keys() {
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        m.insert(addr(10), 1);
        m.insert(addr(11), 2);
        let mut seen = Vec::new();
        m.retain(|k, v| {
            seen.push(*k);
            *v *= 10;
            true
        });
        seen.sort();
        assert_eq!(seen, vec![addr(10), addr(11)]);
        assert_eq!(*m.get(&addr(10)).unwrap(), 10);
    }

    #[test]
    fn walks_visit_every_entry_exactly_once() {
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        for i in 0..200u16 {
            m.insert(addr(i + 1), i as u32);
        }
        let count = AtomicUsize::new(0);
        m.for_each(|_, _| {
            count.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(count.load(Ordering::Relaxed), 200);

        let mut all = m.map_collect(|_, v| *v);
        all.sort_unstable();
        assert_eq!(all, (0..200u32).collect::<Vec<_>>());

        assert_eq!(m.find_map(|k, v| (*v == 42).then_some(*k)), Some(addr(43)));
        assert_eq!(m.find_map(|_, v| (*v == 9999).then_some(())), None);
    }

    #[test]
    fn clear_empties_every_shard() {
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        for i in 0..500u16 {
            m.insert(addr(i + 1), 0);
        }
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn keys_spread_across_shards() {
        // A hash that ignored the key would funnel everything into one shard
        // and silently serialise the whole data path.
        let m: ShardMap<SocketAddr, u32> = ShardMap::new();
        for i in 0..1000u16 {
            m.insert(addr(i + 1), 0);
        }
        let occupied = m.shards.iter().filter(|s| !s.read().is_empty()).count();
        assert!(occupied > 1, "every key landed in one shard");
        let biggest = m.shards.iter().map(|s| s.read().len()).max().unwrap();
        assert!(
            biggest < 500,
            "one shard holds {biggest} of 1000 keys — distribution is broken"
        );
    }

    #[test]
    fn concurrent_entry_creation_is_single_flight() {
        // The property the session table depends on: N threads racing on the
        // same key produce exactly one insert.
        let m: Arc<ShardMap<SocketAddr, usize>> = Arc::new(ShardMap::new());
        let inserts = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = Arc::clone(&m);
            let inserts = Arc::clone(&inserts);
            handles.push(std::thread::spawn(move || {
                for i in 0..200u16 {
                    match m.entry(addr(i + 1)) {
                        Entry::Vacant(v) => {
                            inserts.fetch_add(1, Ordering::Relaxed);
                            v.insert(i as usize);
                        }
                        Entry::Occupied(_) => {}
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.len(), 200);
        assert_eq!(
            inserts.load(Ordering::Relaxed),
            200,
            "a key was inserted more than once"
        );
    }

    #[test]
    fn concurrent_readers_and_writers_stay_consistent() {
        let m: Arc<ShardMap<SocketAddr, u64>> = Arc::new(ShardMap::new());
        for i in 0..64u16 {
            m.insert(addr(i + 1), 0);
        }
        let mut handles = Vec::new();
        for _ in 0..4 {
            let m = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    for i in 0..64u16 {
                        if let Some(mut v) = m.get_mut(&addr(i + 1)) {
                            *v += 1;
                        }
                    }
                }
            }));
        }
        for _ in 0..2 {
            let m = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = m.len();
                    m.for_each(|_, _| {});
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        for i in 0..64u16 {
            assert_eq!(*m.get(&addr(i + 1)).unwrap(), 4000);
        }
    }
}
