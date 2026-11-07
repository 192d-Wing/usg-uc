//! Fixed-capacity LRU map with O(1) get, insert and eviction.
//!
//! An intrusive doubly linked list over a slab (`Vec`) of nodes, indexed by
//! a keyed-hash map (std `RandomState`, attacker-chosen keys). Every entry
//! carries an expiry; an expired entry is removed when it is next read.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)

use std::collections::HashMap;
use std::sync::Arc;

const NIL: usize = usize::MAX;

struct Node<V> {
    /// Shared with the index map: one allocation per inserted key.
    key: Option<Arc<str>>,
    val: Option<V>,
    expires: u64,
    prev: usize,
    next: usize,
}

/// The map. Not synchronised; callers wrap it in a lock.
pub struct Lru<V> {
    cap: usize,
    map: HashMap<Arc<str>, usize>,
    nodes: Vec<Node<V>>,
    free: Vec<usize>,
    /// Most recently used.
    head: usize,
    /// Least recently used.
    tail: usize,
}

impl<V: Clone> Lru<V> {
    /// An empty map holding at most `cap` (>= 1) entries.
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            map: HashMap::new(),
            nodes: Vec::new(),
            free: Vec::new(),
            head: NIL,
            tail: NIL,
        }
    }

    /// Entries held.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Capacity.
    #[cfg(test)]
    pub const fn cap(&self) -> usize {
        self.cap
    }

    /// Drops every entry.
    pub fn clear(&mut self) {
        self.map.clear();
        self.nodes.clear();
        self.free.clear();
        self.head = NIL;
        self.tail = NIL;
    }

    fn unlink(&mut self, i: usize) {
        let (prev, next) = match self.nodes.get(i) {
            Some(n) => (n.prev, n.next),
            None => return,
        };
        match self.nodes.get_mut(prev) {
            Some(p) => p.next = next,
            None => self.head = next,
        }
        match self.nodes.get_mut(next) {
            Some(n) => n.prev = prev,
            None => self.tail = prev,
        }
    }

    fn push_front(&mut self, i: usize) {
        let old = self.head;
        if let Some(n) = self.nodes.get_mut(i) {
            n.prev = NIL;
            n.next = old;
        }
        match self.nodes.get_mut(old) {
            Some(h) => h.prev = i,
            None => self.tail = i,
        }
        self.head = i;
    }

    fn remove_index(&mut self, i: usize) {
        self.unlink(i);
        if let Some(n) = self.nodes.get_mut(i) {
            n.val = None;
            if let Some(key) = n.key.take() {
                self.map.remove(&key);
            }
            self.free.push(i);
        }
    }

    /// The value for `key` if present and `expires > now`; marks it most
    /// recently used. An expired entry is removed.
    pub fn get(&mut self, key: &str, now: u64) -> Option<V> {
        let i = *self.map.get(key)?;
        let live = self.nodes.get(i).is_some_and(|n| n.expires > now);
        if !live {
            self.remove_index(i);
            return None;
        }
        self.unlink(i);
        self.push_front(i);
        self.nodes.get(i).and_then(|n| n.val.clone())
    }

    /// Removes `key`.
    pub fn remove(&mut self, key: &str) {
        if let Some(&i) = self.map.get(key) {
            self.remove_index(i);
        }
    }

    /// Inserts or replaces `key`, evicting the least recently used entry
    /// when full.
    pub fn insert(&mut self, key: &str, val: V, expires: u64) {
        if let Some(&i) = self.map.get(key) {
            if let Some(n) = self.nodes.get_mut(i) {
                n.val = Some(val);
                n.expires = expires;
            }
            self.unlink(i);
            self.push_front(i);
            return;
        }
        if self.map.len() >= self.cap && self.tail != NIL {
            self.remove_index(self.tail);
        }
        let key: Arc<str> = Arc::from(key);
        let node = Node {
            key: Some(Arc::clone(&key)),
            val: Some(val),
            expires,
            prev: NIL,
            next: NIL,
        };
        let i = if let Some(i) = self.free.pop() {
            if let Some(slot) = self.nodes.get_mut(i) {
                *slot = node;
            }
            i
        } else {
            self.nodes.push(node);
            self.nodes.len() - 1
        };
        self.map.insert(key, i);
        self.push_front(i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_least_recently_used() {
        let mut l = Lru::new(2);
        l.insert("a", 1, 100);
        l.insert("b", 2, 100);
        assert_eq!(l.get("a", 0), Some(1)); // a is now MRU
        l.insert("c", 3, 100); // evicts b
        assert_eq!(l.get("b", 0), None);
        assert_eq!(l.get("a", 0), Some(1));
        assert_eq!(l.get("c", 0), Some(3));
        assert_eq!(l.len(), 2);
        l.insert("a", 9, 100); // replace keeps size
        assert_eq!(l.len(), 2);
        assert_eq!(l.get("a", 0), Some(9));
    }

    #[test]
    fn expiry_and_remove_and_slot_reuse() {
        let mut l = Lru::new(3);
        l.insert("a", 1, 10);
        assert_eq!(l.get("a", 10), None);
        assert_eq!(l.len(), 0);
        for round in 0..100u64 {
            l.insert(&format!("k{round}"), round, 1000);
        }
        assert_eq!(l.len(), 3);
        assert!(l.nodes.len() <= 4, "slots reused, not grown");
        l.remove("k99");
        assert_eq!(l.get("k99", 0), None);
        assert_eq!(l.get("k98", 0), Some(98));
        l.clear();
        assert_eq!(l.len(), 0);
        l.insert("z", 1, 5);
        assert_eq!(l.get("z", 0), Some(1));
    }
}
